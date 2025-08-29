#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <fcntl.h>
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
    utoip(src_ip, ntohl(e->conn.src_ip));
    utoip(dst_ip, ntohl(e->conn.dst_ip));

    if(e->shadow_type == SHADOW) {
        printf("%lld - Received SHADOW TCP connection from %s:%d to %s:%d\n", e->timestamp, src_ip, e->conn.src_port, dst_ip, e->conn.dst_port);
    } else if(e->shadow_type == HONEY) {
        printf("%lld - Received HONEY POT TCP connection from %s:%d to %s:%d\n", e->timestamp, src_ip, e->conn.src_port, dst_ip, e->conn.dst_port);
    }

    return 0;
}

int main(int argc, char **argv) {
    struct bpf_object *obj;                 // BPF object
    struct bpf_program *shadow_prog;        // shadow_port BPF program
    struct bpf_program *header_prog;        // fix_hader BPF program

    struct bpf_map *events_map;             // Map for ring buffer
    struct ring_buffer *rb = NULL;          // Ring buffer
    struct bpf_map *shadow_map;             // Shadow Ports hash map
    struct bpf_map *honey_map;              // Honey Pot Ports hash map
    struct bpf_map *honey_lookup;           // Service resolution hash map

    struct bpf_tc_hook hook;                // TC hook point
    struct bpf_tc_opts opts;                // TC hook options

    int ifindex = 0;                        // Interface index
    int shadow_prog_fd;                     // fd of the shadow_port program
    int header_prog_fd;                     // fd of the fix_header program.
    int events_fd;                          // fd of the ring buffer

    int honey_sock;                         // Honey pot socket
    int epfd;                               // Handles incoming connections
    int opt = 1;                            // Socket options

    int err;                                // Error code

    int shadow_ports[MAX_PORT];             // Ports to shadow
    int honey_ports[MAX_PORT];              // Ports to honey pot

    struct epoll_event events[MAX_EVENTS];  // Events for honey pot
    
    // Initialize shadow_ports
    for(int i = 0; i < MAX_PORT; i++) {
        shadow_ports[i] = -1;
    }

    // Initialize honey_ports
    for(int i = 0; i < MAX_PORT; i++) {
        honey_ports[i] = -1;
    }

    if(argc < 3 && argc != 5 && argc != 7) {
        fprintf(stderr, "Usage: %s <interface> <xdp_program.o> [:--shadow <port1,port2,...>] [:--honey <port1,port2,...>]\n", argv[0]);
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
    shadow_prog = bpf_object__find_program_by_name(obj, "shadow_port");
    if(!shadow_prog) {
        fprintf(stderr, "Error: XDP program 'shadow_port' not found in objet file\n");
        err = -1;
        goto cleanup;
    }

    /* Get the program fd */
    shadow_prog_fd = bpf_program__fd(shadow_prog);
    if(shadow_prog_fd < 0) {
        fprintf(stderr, "Error: Failed to get program fd\n");
        err = shadow_prog_fd;
        goto cleanup;
    }

    /* Attach XDP program to interface */
    err = bpf_xdp_attach(ifindex, shadow_prog_fd, 0, NULL);
    if(err) {
        fprintf(stderr, "Error: Failed to attach XDP program to %s: %s\n", ifname, strerror(-err));
        goto cleanup;
    }

    /* Find the TC program by name */
    header_prog = bpf_object__find_program_by_name(obj, "fix_header");
    if(!header_prog) {
        fprintf(stderr, "Error: TC program 'fix_header' not found in objet file\n");
        err = -1;
        goto cleanup;
    }

    /* Get the program fd */
    header_prog_fd = bpf_program__fd(header_prog);
    if(header_prog_fd < 0) {
        fprintf(stderr, "Error: Failed to get program fd\n");
        err = header_prog_fd;
        goto cleanup;
    }

    // Set hook params
    memset(&hook, 0, sizeof(hook));
    hook.ifindex = ifindex;
    hook.attach_point = BPF_TC_EGRESS;
    hook.sz = sizeof(struct bpf_tc_hook);

    /* Create TC hook */
    err = bpf_tc_hook_create(&hook);
    if(err && err !=-EEXIST) {
        fprintf(stderr, "Error: Could not create tc hook\n");
        goto cleanup;
    }

    // Set options params
    memset(&opts, 0, sizeof(opts));
    opts.prog_fd = header_prog_fd;
    opts.sz = sizeof(struct bpf_tc_opts);
    opts.flags = BPF_TC_F_REPLACE;
    
    /* Hook in TC program */
    err = bpf_tc_attach(&hook, &opts);
    if(err) {
        fprintf(stderr, "Error: Could not attach 'fix_header' program: %s\n", strerror(err));
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

    /* Add shadow ports */
    if(argc >= 5) {
        if(strcmp(argv[3], "--shadow")) {
            fprintf(stderr, "Error: Invalid argument '%s'\n", argv[3]);
            err = -1;
            goto cleanup;
        }

        /* Split the port string into individual ports */
        char *port_str = argv[4];
        const char *delimiter = ",";

        char *token;
        int port;

        // Get first port
        int idx = 0;
        token = strtok(port_str, delimiter);
        port = atoi(token);
        if(port >= 0 && port < MAX_PORT)
            shadow_ports[idx++] = port;

        // Get subsequent ports in a loop
        while(idx < MAX_PORT && (token = strtok(NULL, delimiter)) != NULL) {
            port = atoi(token);
            if(port >= 0 && port < MAX_PORT)
                shadow_ports[idx++] = port;
        }
    }

    /* Find the shadow ports map */
    shadow_map = bpf_object__find_map_by_name(obj, "shadow_ports");
    if(!shadow_map) {
        fprintf(stderr, "Error: Could not find 'shadow_ports' map in BPF object\n");
        err = -1;
        goto cleanup;
    }    

    /* Add shadow ports to BPF program */
    for(int i = 0; i < MAX_PORT; i++) {
        // -1 indicates end of list
        if(shadow_ports[i] == -1) break;

        __u8 shadowed = 1;

        err = bpf_map__update_elem(shadow_map, &shadow_ports[i], sizeof(__u16), &shadowed, sizeof(shadowed), 0);
        if(err) {
            fprintf(stderr, "Error: Could not add port %d to 'shadow_ports' map\n", shadow_ports[i]);
            goto cleanup;
        }
    }

    printf("Shadow ports initialized\n");

    /* Add honey pot ports */
    if(argc == 7) {
        if(strcmp(argv[5], "--honey")) {
            fprintf(stderr, "Error: Invalid argument '%s'\n", argv[5]);
            err = -1;
            goto cleanup;
        }

        /* Split the port string into individual ports */
        char *port_str = argv[6];
        const char *delimiter = ",";

        char *token;
        int port;

        // Get first port
        int idx = 0;
        token = strtok(port_str, delimiter);
        port = atoi(token);
        if(port >= 0 && port < MAX_PORT)
            honey_ports[idx++] = port;

        // Get subsequent ports in a loop
        while(idx < MAX_PORT && (token = strtok(NULL, delimiter)) != NULL) {
            port = atoi(token);
            if(port >= 0 && port < MAX_PORT)
                honey_ports[idx++] = port;
        }
    }

    /* Find the honey pot ports map */
    honey_map = bpf_object__find_map_by_name(obj, "honey_ports");
    if(!honey_map) {
        fprintf(stderr, "Error: Could not find 'honey_ports' map in BPF object\n");
        err = -1;
        goto cleanup;
    }    

    /* Add honey pot ports to BPF program */
    for(int i = 0; i < MAX_PORT; i++) {
        // -1 indicates end of list
        if(honey_ports[i] == -1) break;

        __u8 potted = 1;

        err = bpf_map__update_elem(honey_map, &honey_ports[i], sizeof(__u16), &potted, sizeof(potted), 0);
        if(err) {
            fprintf(stderr, "Error: Could not add port %d to 'honey_ports' map\n", honey_ports[i]);
            goto cleanup;
        }
    }

    printf("Honey ports initialized\n");

    /* Find the honey_lookup map */
    honey_lookup = bpf_object__find_map_by_name(obj, "honey_lookup");
    if(!honey_lookup) {
        fprintf(stderr, "Error: Could not find 'honey_lookup' map in BPF object\n");
        err = -1;
        goto cleanup;
    }

    // Used for listening for honey potted ports
    if((honey_sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) < 0) {
        fprintf(stderr, "Error: Could not create honeypot socket\n");
        err = -1;
        goto cleanup;
    }

    // Forcefully attach socket
    if(setsockopt(honey_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        fprintf(stderr, "Could not attach socket\n");
        err = -1;
        goto cleanup;
    }

    // Setting socket metadata
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(HONEY_PORT);

    // Binding socket to HONEY_PORT
    err = bind(honey_sock, (struct sockaddr *)&address, sizeof(address));
    if(err) {
        fprintf(stderr, "Error: Could not bind socket to port %d\n", HONEY_PORT);
        goto cleanup;
    }

    // Listen on HONEY_PORT
    err = listen(honey_sock, SOMAXCONN);
    if(err) {
        fprintf(stderr, "Error: Could not listen on port %d\n", HONEY_PORT);
        goto cleanup;
    }

    // Create epoll instance 
    epfd = epoll_create1(0);

    // Register the listening socket for read events
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = honey_sock;
    epoll_ctl(epfd, EPOLL_CTL_ADD, honey_sock, &ev);

    printf("Honey pot socket created.\n");

    printf("ShadowPort is now monitoring for connection attempts...\n");
    printf("Press Ctrl-C to detach and exit...\n");

    /* Main loop */
    while(running) {
        /* Logging */ 
        err = ring_buffer__poll(rb, 100);
        if(err < 0) {
            fprintf(stderr, "Error polling ring buffer: %s\n", strerror(-err));
            break;
        }
        if(err == -EINTR) {
            err = 0;
            break;
        }

        /* Honey pot handling */
        int n = epoll_wait(epfd, events, MAX_EVENTS, 100);
        //printf("%d\n", n);

        for(int i = 0; i < n; i++) {
            int fd = events[i].data.fd;

            if(fd == honey_sock) {
                // Accept all pending connections
                while(1) {
                    int client_fd = accept(honey_sock, NULL, NULL);
                    if(client_fd < 0) {
                        if(errno == EAGAIN || errno == EWOULDBLOCK) break;
                        else {
                            fprintf(stderr, "Error: Could not accept\n");
                            goto cleanup;
                        }
                    }


                    fcntl(client_fd, F_SETFL, O_NONBLOCK);

                    // Register client with epoll
                    struct epoll_event cev;
                    cev.events = EPOLLIN | EPOLLET;
                    cev.data.fd = client_fd;
                    epoll_ctl(epfd, EPOLL_CTL_ADD, client_fd, &cev);
                }
            } else {
                // Handle client data
                char buf[4096];
                ssize_t len = recv(fd, buf, sizeof(buf), 0);

                if(len > 0) {
                    struct sockaddr_in src_addr, dst_addr;
                    socklen_t addrlen = sizeof(struct sockaddr_in);

                    // Get the source info
                    err = getpeername(fd, (struct sockaddr *)&src_addr, &addrlen);
                    if(err) {
                        fprintf(stderr, "Error: Could not retrieve source IP info\n");
                        goto cleanup;
                    }

                    // Get the destination info
                    err = getsockname(honey_sock, (struct sockaddr *)&dst_addr, &addrlen);
                    if(err) {
                        fprintf(stderr, "Error: Could not get destination IP info\n");
                        goto cleanup;
                    }

                    struct conn_state_t key = {
                        .src_ip = src_addr.sin_addr.s_addr,
                        .dst_ip = dst_addr.sin_addr.s_addr,
                        .src_port = src_addr.sin_port,
                        .dst_port = dst_addr.sin_port,
                    };

                    __u16 orig_dst;
                    err = bpf_map__lookup_elem(honey_lookup, &key, sizeof(key), &orig_dst, sizeof(orig_dst), 0);
                    if(err) {
                        fprintf(stderr, "Could not find key in 'honey_lookup'\n");
                        goto cleanup;
                    }

                    printf("Connection came from %d\n", ntohs(orig_dst));
                } else if(len == 0) {
                    // Connection closed
                    close(fd);
                } else {
                    if(errno != EAGAIN && errno != EWOULDBLOCK) {
                        fprintf(stderr, "Error: Could not recv\n");
                        goto cleanup;
                    }
                }
            }
        }
    }

    printf("\nExiting main loop, starting cleanup...\n");

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

    // Clean up honey lookup
    int honey_lookup_fd;
    if((honey_lookup_fd = bpf_map__fd(honey_lookup)) >= 0) {
        bpf_map__unpin(honey_lookup, "/sys/fs/bpf/honey_lookup");
        close(honey_lookup_fd);
        printf("Honey lookup map cleaned up\n");
    }

    // Clean up honey ports
    int honey_map_fd;
    if((honey_map_fd = bpf_map__fd(honey_map)) >= 0) {
        close(honey_map_fd);
        printf("Honey ports map cleaned up\n");
    }

    // Clean up shadow ports
    int shadow_map_fd;
    if((shadow_map_fd = bpf_map__fd(shadow_map)) >= 0) {
        close(honey_map_fd);
        printf("Shadow ports map cleaned up\n");
    }

    // Clean up BPF object
    if(obj) {
        bpf_object__close(obj);
        printf("BPF object cleaned up\n");
    }

    // Clean up epoll events
    for(int i = 0; i < MAX_EVENTS; i++) {
        if(events[i].data.fd >= 0)
            close(events[i].data.fd);
    }

    printf("Honey pot events closed\n");

    printf("ShadowPort shutdown complete\n");    
    return err ? 1 : 0;
}