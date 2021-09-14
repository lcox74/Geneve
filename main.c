#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/stat.h>

#include <net/if.h>
#include <net/if_tun.h>

#include <netdb.h>
#include <event.h>
#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

/* Max size of a ethernet frame as per the ethernet standard */
#define MAX_ETHERNET_FRAME 1530

/* To hold tap data */
struct tap_config {
        int fd;
        unsigned int name;
        unsigned int vni;
};

/* To hold multiple tap data and main socket */
struct socket_config {
        struct tap_config *taps; /* List of tap devices */
        int tap_size;
        int fd;
};

/* Argument handler */
struct argument_container {
        sa_family_t af;
        const char *source_address, *destination_address;
        const char *source_port, *destination_port;

        bool daemonise;
        int timeout;
};

/* Event struct for TapX fd read event */
struct tap_event {
        TAILQ_ENTRY(tap_event) entry;
        struct event ev;
};
TAILQ_HEAD(tap_event_queue, tap_event);

/* Event struct for Socket fd read/recv event */
struct socket_event {
        TAILQ_ENTRY(socket_event) entry;
        struct event ev;
};
TAILQ_HEAD(socket_event_queue, socket_event);

/* Base Functions */
__dead void         usage(void);
void                argument_handler(int, char**, struct argument_container*, 
                        struct socket_config*);

/* Utility functions */
int                 string_is_number(char*);

/* Tap utility functions */
void                append_tap_device(struct socket_config*, struct tap_config);
struct tap_config   get_tap_from_fd(struct socket_config, int);

/* Geneve specific functions */
int                 encapsulate_data(struct socket_config, struct tap_config, 
                        unsigned char*, int);
int                 decapsulate_data(struct socket_config, unsigned char*, int);
int                 geneve_header_size(unsigned char*, int, unsigned int);

/* System Setups */
void                setup_socket(struct socket_event_queue*, 
                        struct argument_container, struct socket_config*);
void                setup_tap(struct tap_event_queue*, struct tap_config*);
void                setup_events(struct socket_config*, 
                        struct argument_container);

__dead void
usage(void)
{
        extern char *__progname;
        fprintf(stderr, "usage: %s [-46d] [-l address] [-p port] -t 120\n\
            -e /dev/tapX@vni\n\
            server [port]\n", __progname);
        exit(64);
}

/*
 * Calculates the size of a Geneve header from a inbound socket packet. The max
 * size of a Geneve header is 260 bytes and the max size of a option is 124
 * bytes. If these dont meet or if the options don't add up then the packet gets
 * silently dropped as it isn't a valid Geneve encapsulated packet. 
 */
int
geneve_header_size(unsigned char* data, int size, unsigned int opt_len)
{
        int total_header_size = 8;
        int data_pointer = 8;

        /* Optionless */
        if (opt_len == 0) 
            return total_header_size;

        for (unsigned int i = 0; i < opt_len; i++) {
                /* Check if end of buffer */
                if (data_pointer > size)
                        return -1;

                int current_opt_size = (data[data_pointer + 3] & 0x1F) * 4;
                data_pointer += 4 + current_opt_size;

                /* Header can't bet more than 260 bytes */
                if (total_header_size > 260)
                        return -1;
        }
        
        return total_header_size;
}

/*
 * Searches the dynamic tap device list for a tap with a given file descriptor.
 * This is used to get the VNI and/or the device name in a tap device event.
 */
struct tap_config
get_tap_from_fd(struct socket_config config, int fd)
{
        for (int i = 0; i < config.tap_size; i++) {
                if (config.taps[i].fd == fd)
                        return config.taps[i];
        }

        errx(1, "Tap with file descriptor %d doesn't exist", fd);
        return (struct tap_config){ -1, 0, 0};
}

/*
 * Encapsulates an incoming tap device packet and sends it to the destination of
 * the socket. 
 * 
 * While encapsulating a Geneve header, following the Geneve spec,
 * gets created and added to the top of the packet. The header has no options
 * and only required the protocol type and VNI specified, this creates a 8 byte
 * header for tha packet.
 */
int
encapsulate_data(struct socket_config config, struct tap_config tap, 
    unsigned char* data, int size)
{
        unsigned char* encaped_data = malloc(size + 8);

        /* First 32-bits of Geneve Header */
        uint32_t geneve_header = htonl(0x6558);
        memcpy(encaped_data, &geneve_header, 4);

        /* Second 32-bits of Geneve Header */
        geneve_header = htonl(tap.vni << 8);
        memcpy(encaped_data + 4, &geneve_header, 4);

        /* Payload */
        memcpy(encaped_data + 8, data, size);

        return send(config.fd, encaped_data, size + 8, 0);
}

/*
 * Decapsulates an incoming docket packet. If the packet isn't a Geneve packet 
 * or doesn't follow the Geneve standard then the packet is silently dropped.
 * 
 * Otherwise the header gets read for its VNI and Ethertype of original payload
 * and gets filtered to the respected tap devices that are looking for those
 * particular packets, removing the header in the process.
 */
int decapsulate_data(struct socket_config config, 
    unsigned char* data, int size)
{
        if (size < 8) 
                return -1;

        /* Check version number */
        if ((data[0] >> 6) != 0) 
                return -1;

        /* Fetch VNI */
        unsigned int vni = (data[4] << 16) | (data[5] << 8) | (data[6] << 0);
        
        /* Get header size to remove */
        unsigned int option_len = (data[0] & 0x3F);
        int header_size = geneve_header_size(data, size, option_len);

        unsigned int ether_type = (data[header_size] << 8) | 
            (data[header_size + 1]);
        
        if (header_size < 0) 
                return -1;

        for (int i = 0; i < config.tap_size; i++) {
                if (config.taps[i].vni == vni) {
                    if ((ether_type == 0x0800 && vni != 4096) || 
                        (ether_type == 0x86DD && vni != 8192))
                            continue;

                    write(config.taps[i].fd, data + header_size, 
                        size - header_size);
                }
        } 

        return 0;
}

/*
 * Tap device event function. Checks if a read or timeout event is being
 * recieved. A read request will encapsulate the incoming packet and send it to
 * the destination as per the socket connection.
 * 
 * Timeout events close the tap.
 */
static void
on_tap_read(int fd, short ev, void *socket_config)
{
        if (ev == EV_READ) {
                unsigned char *buf = (unsigned char*)malloc(MAX_ETHERNET_FRAME);

                struct socket_config config = *(
                    (struct socket_config*)socket_config);
                struct tap_config tap = get_tap_from_fd(config, fd);

                int bytes;
                if ((bytes = read(fd, buf, MAX_ETHERNET_FRAME)) > 0) {
                        encapsulate_data(config, tap, buf, bytes);
                }
        } else if (ev == EV_TIMEOUT) {
                close(fd);
        }
}

/*
 * Socket event function. Checks whether it is recieving a read event or a 
 * timeout event. If a read event is present then decapsulate the packet, any
 * issues with the decapsulation process are silent and is silently dropped as
 * per the Geneve spec.
 * 
 * Timeout events close the socket and exit the program.
 */
static void
on_socket_read(int fd, short ev, void *socket_config)
{
        if (ev == EV_READ) {
                char *buf = (char*) malloc(6000);
                struct socket_config config = *(
                    (struct socket_config*)socket_config);

                int bytes;
                if ((bytes = recv(fd, buf, 6000, 0)) > 0) {
                        decapsulate_data(config, buf, bytes);
                }

        } else if (ev == EV_TIMEOUT) {
                close(fd);
        }
}

/*
 * Set up a single tap device and add it to the tap event queue. If the tapX
 * isn't able to open then the program will create the new tap device using
 * mknod(2) as this creates special devices rather than just files. The tap 
 * device should be read/writable and not blocking.
 */
void
setup_tap(struct tap_event_queue *queue, struct tap_config *config) {
        /* Create tap interface device name */
        char tap_device[IF_NAMESIZE];
        snprintf(tap_device, IF_NAMESIZE, "/dev/tap%du", config->name);

        /* Try to open the device, throw error if failed */
        if ((config->fd = open(tap_device, O_RDWR | O_NONBLOCK)) < 0) {
                if (errno == ENOENT) {
                        mknod(tap_device, 0600 | S_IFCHR, 
                            makedev(93, config->name));
                        if ((config->fd = open(tap_device, 
                            O_RDWR | O_NONBLOCK)) < 0) {
                                errx(errno, "%s \"%s\": %s", 
                                "Tried to create device, still unable to open",
                                tap_device, gai_strerror(errno));
                        }
                } else {
                        errx(errno, "Unable to open tap device \"%s\": %s",
                            tap_device, gai_strerror(errno));
                }
        }

        /* Setup the tap event fd and add to the event queue */
        struct tap_event *e;
        e = (struct tap_event*) malloc(sizeof(*e));
        event_set(&e->ev, config->fd, 0, NULL, NULL);
        TAILQ_INSERT_TAIL(queue, e, entry);

        if (TAILQ_EMPTY(queue))
                errx(1, "Failed to add tap device to event queue");
}

/*
 * Set up the UDP socket connection to the given destination. By default the
 * port will be `6081` as specified in the Geneve spec.
 * 
 * The socket will also bind to a port on the local system, any IP is used 
 * unless specified. If a local port isn't specified then it will use the same
 * port as the destination port. This allows multiple connections through the
 * same socket.
 */
void
setup_socket(struct socket_event_queue *queue, struct argument_container args,
    struct socket_config *config)
{
        struct addrinfo hints, *destination, *source, *res;
        int err, saved_errno;
        const char* saved_err_cause;

        /* Get destination address info for destination connect and socket */
        memset(&hints, 0, sizeof (struct addrinfo));
        hints.ai_family = args.af;
        hints.ai_socktype = SOCK_DGRAM;

        if ((err = getaddrinfo(args.destination_address, args.destination_port, 
            &hints, &destination)) < 0) {
                errx(1, "Failed to get destination address %s at port %s : %s", 
                    args.destination_address, args.destination_port, 
                    gai_strerror(err));
        }

        /* Create socket to valid/operational destination */
        for(res = destination; res != NULL; res = res->ai_next) {
                if ((config->fd = socket(res->ai_family, res->ai_socktype, 
                        res->ai_protocol)) < 0) {
                        saved_err_cause = "Unable to create socket";
                        saved_errno = errno;
                        continue;
                }
                break;  
        }

        if (config->fd == -1)
                errx(saved_errno, "%s : %s", saved_err_cause, 
                    gai_strerror(saved_errno));

        /* Get source address info for local bind */
        memset(&hints, 0, sizeof (struct addrinfo));
        hints.ai_family = args.af;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_flags = AI_PASSIVE;

        if ((err = getaddrinfo(args.source_address, args.source_port, 
            &hints, &source)) < 0) {
                errx(1, "Failed to get source address %s at port %s : %s", 
                    args.source_address, args.source_port, 
                    gai_strerror(err));
        }

        /* Bind to local address and/or port */
        if ((err = bind(config->fd, source->ai_addr, source->ai_addrlen)) < 0) {
                errx(1, "Failed to bind to address %s at port %s : %s", 
                    args.source_address, args.source_port, gai_strerror(err));
        }

        /* Connect to destination address */
        if ((err = connect(config->fd, res->ai_addr, res->ai_addrlen)) < 0) {
                errx(1, "Failed to connect to address %s at port %s : %s", 
                    args.destination_address, args.destination_port, 
                    gai_strerror(err));
        }

        /* Clean address infos */
        freeaddrinfo(destination);
}

/*
 * Checkes a given string and returns if the whole thing is a number, used to
 * validate arguments.
 */
int
string_is_number(char *in)
{
        int length = strlen(in);
        for (int i = 0; i < length; i++)
        {
                if (isdigit(in[i]) == 0)
                    return 0;
        }
        return 1;
}

/*
 * Append the new tap device to the socket dynamic tap list. Don't allow for 
 * duplicate taps as it will cause issues.
 */
void
append_tap_device(struct socket_config* config, struct tap_config new_tap)
{
        /* Check for duplicate taps */
        for (int i = 0; i < config->tap_size; i++) {
                if (config->taps[i].name == new_tap.name)
                    return;
        }

        /* Reallocate space for the array, and add new tap to end */
        config->taps = (struct tap_config*) realloc(config->taps, 
            sizeof(struct tap_config) * ((config->tap_size) + 1));
        
        config->taps[(config->tap_size)++] = new_tap;
}

/*
 * Sets up the events along side invoking tap and socket setups. Events call
 * when there the file descriptors of the taps and socket have something to read
 * from, or if there is a timeout.
 * 
 * The event queue will run until the timeout occurs of if there was no timeout
 * set, then the process will have to be manually killed.
 */
void
setup_events(struct socket_config *config, struct argument_container args)
{
        struct timeval tv = { args.timeout, 0 };

        struct tap_event *tap_ev;
        struct tap_event_queue tap_queue = 
            TAILQ_HEAD_INITIALIZER(tap_queue);

        struct socket_event *sock_ev;
        struct socket_event_queue sock_queue = 
            TAILQ_HEAD_INITIALIZER(sock_queue);

        /* Set up the event queues */
        for (int i = 0; i < config->tap_size; i++)
                setup_tap(&tap_queue, &config->taps[i]);
        setup_socket(&sock_queue, args, config);

        /* Setup the socket event fd and add to the event queue */
        struct socket_event *e;
        e = (struct socket_event*) malloc(sizeof(*e));
        event_set(&e->ev, config->fd, 0, NULL, NULL);
        TAILQ_INSERT_TAIL(&sock_queue, e, entry);

        /* Error checking the queues to make sure they arent empty */
        if (TAILQ_EMPTY(&sock_queue))
                errx(1, "Failed to add socket to event queue");
        if (TAILQ_EMPTY(&tap_queue))
                errx(1, "Failed to add taps to event queue");
        
        /* Start up event handling and loop */
        event_init();
        TAILQ_FOREACH(tap_ev, &tap_queue, entry) {
                event_set(&tap_ev->ev, EVENT_FD(&tap_ev->ev), 
                    EV_READ | EV_PERSIST, on_tap_read, config);
                event_add(&tap_ev->ev, (args.timeout <= 0) ? NULL : &tv);
        }

        TAILQ_FOREACH(sock_ev, &sock_queue, entry) {
                event_set(&sock_ev->ev, EVENT_FD(&sock_ev->ev), 
                    EV_READ | EV_PERSIST, on_socket_read, config);
                event_add(&sock_ev->ev, (args.timeout <= 0) ? NULL : &tv);
        }
        event_dispatch();
}

/*
 * Handles and processes arguments passed in through the program initialisation.
 * If something doesn't follow the usage format then it will throw a usage error
 * and quit the application.
 */
void
argument_handler(int argc, char *argv[], struct argument_container *args, 
    struct socket_config *config) 
{
        int ch, tap = 0, vni = 0, timer_flag = 0;
        while ((ch = getopt(argc, argv, "46dt:l:p:e:")) != -1) {
                switch (ch) {
                case '4':
                        args->af = AF_INET;
                        break;
                case '6':
                        args->af = AF_INET6;
                        break;
                case 'd':
                        args->daemonise = false;
                        break;
                case 't':
                        timer_flag++;
                        if (string_is_number(optarg) == 0)
                                usage();
                        args->timeout = atoi(optarg);
                        break;
                case 'l':
                        args->source_address = (strcmp(optarg, "*") == 0) ? 
                            NULL : optarg;
                        break;
                case 'p':
                        args->source_port = optarg;
                        break;
                case 'e':
                        if (sscanf(optarg, "/dev/tap%d@%d", &tap, &vni) < 2)
                                usage();
                        append_tap_device(config, 
                            (struct tap_config) { -1, tap, vni });
                        break;        
                default:
                        usage();
                        break;
                }
        }
        argc -= optind;
        argv += optind;

        if (argc <= 0 || argc > 2)
                usage();

        /* Required */
        args->destination_address = argv[0];
        if (config->tap_size <= 0 || timer_flag == 0)
                usage();

        /* Optional destination port */
        if (argc == 2) 
                args->destination_port = argv[1];

        /* Bind port handling */
        args->source_port = (args->source_port == NULL) ? 
            args->destination_port : args->source_port;
}

/*
 * Geneve is a Network Virtualization application that can support mutliple
 * tunnels over a single UDP connection. 
 * 
 * The Geneve protocol works by encapsulating packets from the local side of the 
 * machine before sending it to the specified server to handle. On the receiving 
 * side the protocol incoming packets from a UDP bind get decapsulated and 
 * filtered to the respected virtual interfaces specified with the `-e` flag via 
 * their respected Virtual Network Identity numbers (VNI).
 * 
 * Taps can share a VNI, but a single tap can only have a single VNI assigned to
 * it, creating a 1:M relationship.
 * 
 * As the protocol used is UDP packets can be recieved by the binded port, 
 * and address (if given) as well as from the destination device. This alongside
 * the multiple taps able to be set up creates a bi-directional multi-tunnel
 * virtualized connection.
 */
int
main(int argc, char *argv[])
{
        struct argument_container args = { AF_UNSPEC, NULL, NULL, NULL, "6081", 
            true, -1 };

        /* Set up a master config holding the file descriptors of all devices */
        struct socket_config master_config;
        master_config.taps = (struct tap_config*) malloc(
            sizeof(struct tap_config) * 2);
        master_config.tap_size = 0;
        master_config.fd = -1;

        /* Handle the passed in program arguments */
        argument_handler(argc, argv, &args, &master_config);

        /* Daemonise the progam by default unless specified otherwise */
        if (args.daemonise) {
                if (daemon(0, 0) < 0)
                        errx(errno, "Failed to Daemonise program: %s", 
                            gai_strerror(errno));
        }

        /* Setup the events and start the event loop */
        setup_events(&master_config, args);

        return 0;
}
