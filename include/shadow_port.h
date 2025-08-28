#ifndef SHADOW_PORT_H
#define SHADOW_PORT_H

#define ETH_P_IP    0x0800
#define ICMP_ECHO   8
#define ETH_ALEN    6

#define MAX_PORT    1 << 16
#define HONEY_PORT  2222
#define MAX_EVENTS  1024

typedef enum {
    REGULAR,
    SHADOW,
    HONEY,
} type;

struct conn_state_t {
    __u32 src_ip;       // Source IP
    __u32 dst_ip;       // Dest IP
    __u16 src_port;     // Source Port
    __u16 dst_port;     // Dest Port
};

struct event_t {
    struct conn_state_t conn;   // Connection info
    type shadow_type;           // Is shadow? Is honey? Is nothing?
    __u64 timestamp;            // TAI time
};

#endif