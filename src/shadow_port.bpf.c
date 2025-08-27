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
    __uint(max_entries, 1 << 16);
} shadowed_ports SEC(".maps");

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

SEC("xdp")
int shadow_port(struct xdp_md *ctx) {
    struct event_t *e;

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

        bpf_ringbuf_submit(e, 0);

        // Check if the port is shadowed
        u8 is_shadowed = bpf_map_lookup_elem(&shadowed_ports, &e->dst_port);
        if(is_shadowed) {
            
        }
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";