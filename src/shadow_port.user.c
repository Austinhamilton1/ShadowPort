#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "shadow_port.h"

static volatile bool running = true;

/*
 * On a termination signal, indicate that we want to stop running.
 */
static void sig_handler(int sig) {
    running = false;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if(level >= LIBBPF_DEBUG)
        return 0;

    return vfprintf(stderr, format, args);
}

/*
 * Convert unsigned integer representation of ip address to string.
 * 
 * Arguments:
 *     char *buf - Write result here.
 *     unsigned int ip_int - Convert this ip address.
 */
void utoip(char *buf, unsigned int ip_int) {
    unsigned char octet1 = (ip_int >> 24) & 0xFF;
    unsigned char octet2 = (ip_int >> 16) & 0xFF;
    unsigned char octet3 = (ip_int >> 8) & 0xFF;
    unsigned char octet4 = ip_int & 0xFF;

    sprintf(buf, "%d.%d.%d.%d", octet1, octet2, octet3, octet4);
}

/* 
 * Runs when event is triggered by the ring buffer.
 */
int handle_event(void *ctx, void *data, unsigned long size) {
    // Get the data from the ring buffer.
    struct event_t *e = data;

    /* Read the src and dst IP addresses for the event */
    char src_ip[16];
    char dst_ip[16];
    utoip(src_ip, ntohl(e->src_ip));
    utoip(dst_ip, ntohl(e->dst_ip));

    // No port signifies the type of incoming packet is ICMP
    if(e->src_port == 0) {
        printf("%lld - Incoming ping from %s to %s\n", e->timestamp, dst_ip, src_ip);
    } else {
        printf("%lld - Incoming TCP connection from %s:%d to %s:%d\n", e->timestamp, src_ip, e->src_port, dst_ip, e->dst_port);
    }

    return 0;
}

int main(int argc, char **argv) {
    struct bpf_object *obj;         // BPF object
    struct bpf_program *prog;       // BPF program
    struct bpf_map *events_map;     // Map for ring buffer
    struct ring_buffer *rb = NULL;  // Ring buffer
    static int ifindex = 0;         // Interface index
    int prog_fd;                    // fd of the program
    int events_fd;                  // fd of the ring buffer
    int err;                        // Error code

    if(argc != 3) {
        fprintf(stderr, "Usage: %s <interface> <xdp_program.o>\n", argv[0]);
        return 1;
    }

    // Shut down gracefully
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Get the file descriptor of the interface provided */
    const char *ifname = argv[1];
    ifindex = if_nametoindex(ifname);
    if(ifindex == 0) {
        fprintf(stderr, "Error: Interface %s not found\n", ifname);
        return 1;
    }
    /* Load BPF object file */
    const char *filename = argv[2];
    obj = bpf_object__open_file(filename, NULL);
    if(libbpf_get_error(obj)) {
        fprintf(stderr, "Error: Failed to open BPF object file %s\n", filename);
        return 1;
    }

    /* Load BPF program into kernel */
    err = bpf_object__load(obj);
    if(err) {
        fprintf(stderr, "Error: Failed to load BPF object: %s\n", strerror(-err));
        goto cleanup;
    }

    // Set the print function
    libbpf_set_print(libbpf_print_fn);

    /* Find the XDP program by name */
    prog = bpf_object__find_program_by_name(obj, "shadow_port");
    if(!prog) {
        fprintf(stderr, "Error: XDP program 'shadow_port' not found in objet file\n");
        err = -1;
        goto cleanup;
    }

    /* Get the program fd */
    prog_fd = bpf_program__fd(prog);
    if(prog_fd < 0) {
        fprintf(stderr, "Error: Failed to get program fd\n");
        err = prog_fd;
        goto cleanup;
    }

    /* Attach XDP program to interface */
    err = bpf_xdp_attach(ifindex, prog_fd, 0, NULL);
    if(err) {
        fprintf(stderr, "Error: Failed to attach XDP program to %s: %s\n", ifname, strerror(-err));
        goto cleanup;
    }

    printf("Successfully attached ShadowPort to %s (ifindex: %d)\n", ifname, ifindex);
    
    /* Find the events ring buffer map */
    events_map = bpf_object__find_map_by_name(obj, "events");
    if(!events_map) {
        fprintf(stderr, "Error: Could not find 'events' map in BPF object\n");
        err = -1;
        goto cleanup;
    }

    /* Get the ring buffer fd */
    events_fd = bpf_map__fd(events_map);
    if(events_fd < 0) {
        fprintf(stderr, "Error: Failed to get 'events' map fd\n");
        err = events_fd;
        goto cleanup;
    }

    /* Create ring buffer */
    rb = ring_buffer__new(events_fd, handle_event, NULL, NULL);
    if(!rb) {
        fprintf(stderr, "Error: Failed to create ring buffer\n");
        err = -1;
        goto cleanup;
    }

    printf("Events buffer created successfully\n");
    printf("ShadowPort is now monitoring for connection attempts...\n");
    printf("Press Ctrl-C to detach and exit...\n");

    while(running) {
        err = ring_buffer__poll(rb, 100);
        if(err == -EINTR) {
            err = 0;
            break;
        }
        if(err < 0) {
            fprintf(stderr, "Error polling ring buffer: %s\n", strerror(-err));
            break;
        }
    }

    printf("Exiting main loop, starting cleanup...\n");

cleanup:
    // Clean up ring buffer
    if(rb) {
        ring_buffer__free(rb);
        printf("Ring buffer cleaned up\n");
    }

    // Detach program from interface
    if(ifindex > 0) {
        int detach_err = bpf_xdp_detach(ifindex, 0, NULL);
        if(detach_err) {
            fprintf(stderr, "Warning: Failed to detach XDP program: %s\n", strerror(-detach_err));
        } else {
            printf("XDP program detached from %s\n", ifname);
        }
    }

    // Clean up BPF object
    if(obj) {
        bpf_object__close(obj);
        printf("BPF object cleaned up\n");
    }

    printf("ShadowPort shutdown complete\n");    
    return err ? 1 : 0;
}