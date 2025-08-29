#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "shadow_port.h"

/*
 * This ring buffer keeps track of incoming packets and their metadata.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/*
 * This hash map maps ports to either shadowed or not (0 = non/shadowed, 1 = shadowed).
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u16);
    __type(value, u8);
    __uint(max_entries, MAX_PORT);
} shadow_ports SEC(".maps");

/*
 * This hash map maps port to either honey potted or not (0 = non/honey potted, 1 = honey potted).
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u16);
    __type(value, u8);
    __uint(max_entries, MAX_PORT);
} honey_ports SEC(".maps");

/*
 * This hash map allows the user to know which port a honey pot was originally sent to.
 * This helps the user code figure out what response to send back to the sender.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct conn_state_t);
    __type(value, u16);
    __uint(max_entries, MAX_PORT);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} honey_lookup SEC(".maps");

/*
 * Helper function to calculate 16-bit checksum.
 *
 * Arguments:
 *     __u32 csum - Fold this check sum.
 * Returns:
 *     __u16 - The folded check sum.
 */
static __always_inline __u16 csum_fold(__u32 csum) {
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum = (csum & 0xFFFF) + (csum >> 16);
    return (__u16)~csum;
}

/*
 * Calculate IP header checksum.
 *
 * Arguments:
 *     struct iphdr *iph - The header to calculate.
 * Returns:
 *     __u16 - The checksum of the IP header.
 */
static __always_inline __u16 ip_checksum(struct iphdr *iph) {
    __u32 csum = 0;
    __u16 *data = (__u16 *)iph;
    int len = sizeof(struct iphdr) >> 1; // Convert to 16-bit words

    // Clear existing checksum
    iph->check = 0;

    // Sum all 16-bit words in header
    #pragma unroll
    for(int i = 0; i < 10; i++) { // IP header is 20 bytes = 10 x 16-bit words
        if(i < len)
            csum += *data++;
    }

    return csum_fold(csum);
}

/*
 * Calculate TCP checksum (includes pseudo header).
 * 
 * Arguments:
 *     struct iphdr *ip - The ip header.
 *     struct tcphdr *tcp - The tcp header.
 *     void *data_end - Always have to check against data_end.
 * Returns:
 *     __u16 - A checksum for a TCP packet.
 */
static __always_inline __u16 tcp_checksum(struct iphdr *iph, struct tcphdr *tcph, void *data_end) {
    __u32 csum = 0;
    __u16 tcp_len;
    
    // Calculate TCP segment length
    tcp_len = __builtin_bswap16(iph->tot_len) - (iph->ihl << 2);
    
    // Clear existing checksum
    tcph->check = 0;
    
    // Add pseudo header (source IP, dest IP, protocol, TCP length)
    csum += (iph->saddr & 0xffff) + (iph->saddr >> 16);
    csum += (iph->daddr & 0xffff) + (iph->daddr >> 16);
    csum += __builtin_bswap16(IPPROTO_TCP);
    csum += __builtin_bswap16(tcp_len);
    
    // Add TCP header and data
    __u16 *data = (__u16 *)tcph;
    
    // Bounds check
    if((void *)(data + 10) > data_end)
        return 0; // Invalid packet

    #pragma unroll
    for(int i = 0; i < 10; i++) {
        csum += *data++;
    }
    
    return csum_fold(csum);
}

/*
 * Send a TCP SYN ACK back to the incoming connection.
 * 
 * Arguments:
 *     struct xdp_md *ctx - The current context (data/data_end).
 *     struct ethhdr *eth - Ethernet header.
 *     struct iphdr *iph - IP header.
 *     struct tcphdr *tcph - TCP header.
 * Returns:
 *     int XDP_TX (success) or XDP_PASS (failure).
 */
static __always_inline int send_syn_ack(struct xdp_md *ctx, struct ethhdr *eth, struct iphdr *iph, struct tcphdr *tcph) {
    void *data_end = (void *)(long)ctx->data_end;

    // Verify packet boundaries
    if((void *)(tcph + 1) > data_end)
        return XDP_PASS;

    // Save original values
    __u32 orig_saddr = iph->addrs.saddr;
    __u32 orig_daddr = iph->addrs.daddr;
    __u16 orig_sport = tcph->source;
    __u16 orig_dport = tcph->dest;
    __u32 orig_seq = tcph->seq;

    // Swap MAC addresses
    __u8 tmp_mac[ETH_ALEN];
    __builtin_memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, tmp_mac, ETH_ALEN);

    // Swap IP addresses
    iph->addrs.saddr = orig_daddr;
    iph->addrs.daddr = orig_saddr;

    // Swap ports
    tcph->source = orig_dport;
    tcph->dest = orig_sport;

    // Set TCP flags for SYN-ACK
    tcph->syn = 1;
    tcph->ack = 1;
    tcph->rst = 0;
    tcph->fin = 0;
    tcph->psh = 0;
    tcph->urg = 0;

    // Set sequence and acknowledgement numbers
    tcph->seq = __builtin_bswap32(0x12345678); // Random ISN for honeypot
    tcph->ack_seq = __builtin_bswap32(__builtin_bswap32(orig_seq) + 1);

    // Set window size (adversize reasonable buffer)
    tcph->window = __builtin_bswap16(65535);

    // Clear urgent pointer
    tcph->urg_ptr = 0;

    // Update IP header
    iph->ttl = 64; // Reset TTL

    // Recalculate IP checksum
    iph->check = ip_checksum(iph);

    // Recalculate TCP checksum
    tcph->check = tcp_checksum(iph, tcph, data_end);

    return XDP_TX; // Send packet back out same interface
}

/*
 * Redirect a packet to the honey pot socket.
 *
 * Arguments:
 *     struct xdp_md *ctx - The current context (data/data_end).
 *     struct iphdr *iph - IP header.
 *     struct tcphdr *tcph - TCP header.
 */
static __always_inline void redirect_to_hp(struct xdp_md *ctx, struct iphdr *iph, struct tcphdr *tcph) {
    void *data_end = (void *)(long)ctx->data_end;

    // Verify packet boundaries
    if((void *)(tcph + 1) > data_end)
        return;

    /* Need to store the original connection response for user retrieval */
    struct conn_state_t conn = {};
    conn.src_ip = iph->addrs.saddr;
    conn.dst_ip = iph->addrs.daddr;
    conn.src_port = tcph->source;
    conn.dst_port = __builtin_bswap16(HONEY_PORT);
    
    bpf_map_update_elem(&honey_lookup, &conn, &tcph->dest, 0);

    // Send to dedicated honey pot port and recalate checksum
    tcph->dest = __builtin_bswap16(HONEY_PORT);

    // Update check sums
    iph->check = ip_checksum(iph);
    tcph->check = tcp_checksum(iph, tcph, data_end);
}

SEC("xdp")
int shadow_port(struct xdp_md *ctx) {
    struct event_t *e;
    u8 *is_shadowed;
    u8 *is_honey_pot;

    /* Grab the Ethernet header from the packet */
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Check that it's an IP packet
    if(eth->h_proto != __builtin_bswap16(ETH_P_IP))
        return XDP_PASS;

    /* Parse the header from this packet */
    struct iphdr *iph = (void *)(eth + 1);
    if((void *)(iph + 1) > data_end)
        return XDP_PASS;
    
    if(iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* Parse header from this packet */
    struct tcphdr *tcph = (void *)(iph + 1);
    if((void *)(tcph + 1) > data_end)
        return XDP_PASS;

    // Don't let outside connections connect to honey pot port directly
    //if(__builtin_bswap16(tcph->dest) == HONEY_PORT)
    //    return XDP_DROP;

    // Only log SYN packets (new connection attempts)
    if(!(tcph->syn && !tcph->ack))
        return XDP_PASS;

    e = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
    if(!e)
        return XDP_PASS;

    /* Log incoming TCP request */
    e->conn.src_ip = iph->addrs.saddr;
    e->conn.dst_ip = iph->addrs.daddr;
    e->conn.src_port = __builtin_bswap16(tcph->source);
    e->conn.dst_port = __builtin_bswap16(tcph->dest);
    e->timestamp = bpf_ktime_get_tai_ns();
    e->shadow_type = REGULAR;

    // Check if the port is shadowed
    u16 dst_port = __builtin_bswap16(tcph->dest);
    is_shadowed = bpf_map_lookup_elem(&shadow_ports, &dst_port);
    if(is_shadowed && *is_shadowed) {
        // Event is a shadowed port
        e->shadow_type = SHADOW;
        bpf_ringbuf_submit(e, 0);
        
        // Send SYN-ACK response
        return send_syn_ack(ctx, eth, iph, tcph);   
    }

    // Check if the port is honey potted
    is_honey_pot = bpf_map_lookup_elem(&honey_ports, &dst_port);
    if(is_honey_pot && *is_honey_pot) {
        // Event is a honey pot port
        e->shadow_type = HONEY;

        // Redirect to honey pot socket
        redirect_to_hp(ctx, iph, tcph);
    }

    bpf_ringbuf_submit(e, 0);

    // Default - Let the packet through
    return XDP_PASS;
}

/*
 * Parse a TCP packet.
 *
 * Arguments:
 *     struct __sk_buff *skb - The packet to parse.
 *     __u64 *off_eth - Store ethernet offset here.
 *     __u64 *off_ip - Store IP offset here.
 *     __u64 *off_tcp - Store TCP offset here.
 *     struct iphdr *iph - Store IP header here.
 *     struct tcph *tcph - Store TCP header here.
 * Returns:
 *     int - 0 on success, -1 on failure.
 */
static __always_inline int parse_tcp(struct __sk_buff *skb, __u64 *off_eth, __u64 *off_ip, __u64 *off_tcp, struct iphdr *iph, struct tcphdr *tcph) {
    __u32 eth_proto;
    __u32 ip_off = sizeof(struct ethhdr);
    __u32 tcp_off;
    int ret;

    /* Ensure ethernet header is available and read ethertype */
    ret = bpf_skb_load_bytes(skb, 12, &eth_proto, sizeof(__u16)); // offset 12 = h_proto (be16)
    if (ret < 0) return -1;
    eth_proto = __builtin_bswap16((__u16)eth_proto);
    if (eth_proto != ETH_P_IP) return -1;

    /* Load IPv4 header first (minimum 20 bytes) */
    ret = bpf_skb_load_bytes(skb, ip_off, iph, sizeof(struct iphdr));
    if (ret < 0) return -1;

    if (iph->protocol != IPPROTO_TCP) return -1;

    /* Calculate tcp header offset from iph->ihl (ihl in 32-bit words) */
    tcp_off = ip_off + (iph->ihl * 4);

    /* Load TCP header (minimum 20 bytes) */
    ret = bpf_skb_load_bytes(skb, tcp_off, tcph, sizeof(struct tcphdr));
    if (ret < 0) return -1;

    /* Populate out offsets for caller (if they need them) */
    *off_eth = 0;
    *off_ip  = ip_off;
    *off_tcp = tcp_off;
    return 0;
}

SEC("tc")
int fix_header(struct __sk_buff *skb) {
    __u64 off_eth, off_ip, off_tcp;
    struct iphdr iph;
    struct tcphdr tcph;
    if(parse_tcp(skb, &off_eth, &off_ip, &off_tcp, &iph, &tcph) < 0)
        return BPF_OK;

    // Need to know if this egress packet is part of the XDP honey pot flow.
    struct conn_state_t key = {
        .src_ip = iph.daddr,
        .dst_ip = iph.saddr,
        .src_port = tcph.dest,
        .dst_port = __builtin_bswap16(HONEY_PORT),
    };

    // Reverse lookup
    __u16 *orig_port = bpf_map_lookup_elem(&honey_lookup, &key);
    if(!orig_port)
        return BPF_OK;

    // Change outgoing port
    __u16 old = tcph.source;
    __u16 new = *orig_port;

    if(bpf_skb_store_bytes(skb, off_tcp + offsetof(struct tcphdr, source), &new, sizeof(new), 0) < 0)
        return BPF_OK;

    // Adjust TCP checksum
    if(bpf_l4_csum_replace(skb, off_tcp + offsetof(struct tcphdr, check), old, new, sizeof(new)) < 0)
        return BPF_OK;

    return BPF_OK;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";