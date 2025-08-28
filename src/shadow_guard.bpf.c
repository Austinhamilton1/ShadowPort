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

SEC("xdp")
int shadow_guard(struct xdp_md *ctx) {
    struct event_t *e;
    u8 *is_shadowed;

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
        
    /* Check the protocol: log ICMP, answer TCP with SYN defined */
    if(iph->protocol == IPPROTO_ICMP) {
        /* Parse header from this packet */
        struct icmphdr *icmph = (void *)(iph + 1);
        if((void *)(icmph + 1) > data_end)
            return XDP_PASS;

        // Network is being pinged
        if(icmph->type == ICMP_ECHO) {
            e = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
            if(!e)
                return XDP_PASS;

            /* Log incoming PING request */
            e->src_ip = iph->addrs.saddr;
            e->dst_ip = iph->addrs.daddr;
            e->src_port = 0;
            e->dst_port = 0;
            e->timestamp = bpf_ktime_get_tai_ns();

            bpf_ringbuf_submit(e, 0);
        }
    } else if(iph->protocol == IPPROTO_TCP) {
        /* Parse header from this packet */
        struct tcphdr *tcph = (void *)(iph + 1);
        if((void *)(tcph + 1) > data_end)
            return XDP_PASS;

        // Only log SYN packets (new connection attempts)
        if(!(tcph->syn && !tcph->ack))
            return XDP_PASS;

        e = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
        if(!e)
            return XDP_PASS;

        /* Log incoming TCP request */
        e->src_ip = iph->addrs.saddr;
        e->dst_ip = iph->addrs.daddr;
        e->src_port = __builtin_bswap16(tcph->source);
        e->dst_port = __builtin_bswap16(tcph->dest);
        e->timestamp = bpf_ktime_get_tai_ns();

        // Check if the port is shadowed
        u16 dst_port = __builtin_bswap16(tcph->dest);
        is_shadowed = bpf_map_lookup_elem(&shadow_ports, &dst_port);
        if(is_shadowed && *is_shadowed) {
            // Event is a shadowed port
            e->shadow_port = 1;
            bpf_ringbuf_submit(e, 0);
            
            // Send SYN-ACK response
            return send_syn_ack(ctx, eth, iph, tcph);   
        }

        bpf_ringbuf_submit(e, 0);
    }

    // Default - Let the packet through
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";