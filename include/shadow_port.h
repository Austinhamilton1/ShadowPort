#ifndef SHADOW_PORT_H
#define SHADOW_PORT_H

#define ETH_P_IP 0x0800
#define ICMP_ECHO 8

struct event_t {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u64 timestamp;    // TAI time
};

#endif