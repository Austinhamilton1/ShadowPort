#ifndef SHADOW_PORT_H
#define SHADOW_PORT_H

#define ETH_P_IP    0x0800
#define ICMP_ECHO   8
#define ETH_ALEN    6

#define MAX_PORT    1 << 16

struct event_t {
    __u32 src_ip;       // Source IP
    __u32 dst_ip;       // Dest IP
    __u16 src_port;     // Source Port
    __u16 dst_port;     // Dest Port
    __u8 shadow_port;   // Is shadow?
    __u64 timestamp;    // TAI time
};

#endif