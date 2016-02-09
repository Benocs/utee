/* utee - transparent udp tee proxy
 *
 * support for:
 *  * round-robin load-balance
 *  ** hash-based load-balance
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

#include "uthash.h"

#define BUFLEN 4096
#define MAXTHREADS 1024

#define HASH_MOD(key, keylen, num_bkts, hashv, bkt)                           \
do {                                                                          \
    hashv = *key;                                                             \
    bkt = (*key) % num_bkts;                                                  \
} while (0)

#define HASH_BER_MOD(key, keylen, num_bkts, hashv, bkt)                       \
do {                                                                          \
    unsigned _hb_keylen=(unsigned)keylen;                                     \
    const unsigned char *_hb_key=(const unsigned char*)(key);                 \
    (hashv) = 0;                                                              \
    while (_hb_keylen-- != 0U) {                                              \
        (hashv) = 33 * hashv ^ *_hb_key++;                                    \
    }                                                                         \
    bkt = (hashv) % (num_bkts);                                               \
} while (0)

#define HASH_JEN_32(key, keylen, num_bkts, hashv, bkt)                        \
do {                                                                          \
    hashv = (*key +0x7ed55d16) + (*key<<12);                                  \
    hashv = (hashv^0xc761c23c) ^ (hashv>>19);                                 \
    hashv = (hashv+0x165667b1) + (hashv<<5);                                  \
    hashv = (hashv+0xd3a2646c) ^ (hashv<<9);                                  \
    hashv = (hashv+0xfd7046c5) + (hashv<<3);                                  \
    hashv = (hashv^0xb55a4f09) ^ (hashv>>16);                                 \
                                                                              \
    bkt = (hashv) % (num_bkts);                                               \
} while (0)

// default hashing for IP addresses is to simply mod them by the number of bkts
#ifndef HASH_ADDR
#define HASH_ADDR HASH_MOD
#endif

struct statistics {
    uint64_t in_bytecnt;
    uint64_t out_bytecnt;
};

struct s_features {
    uint8_t distribute;
    uint8_t load_balanced_dist;
    uint8_t hash_based_dist;
    uint8_t duplicate;
};

struct hashable {
    // TODO: if there shall be IPv6-support, increase the address space
    uint32_t addr;
    struct sockaddr_storage* output;
    uint64_t pkt_cnt;
    UT_hash_handle hh;
};

struct thread_data {
    int thread_id;
    int sockfd;
    struct sockaddr_in* targets;
    uint32_t num_targets;
    struct statistics stats;
    struct s_features features;
    struct hashable* hashtable;
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
    udph->check = 0;
    update_udp_header(udph, udp_payload_len, source, dest);
}

struct sockaddr_storage* hash_based_output(struct sockaddr_storage *their_addr,
                                           struct thread_data* td) {

    uint32_t hashvalue = 0;
    uint32_t target = 0;

    uint32_t tmp = ntohl(((struct sockaddr_in*)their_addr)->sin_addr.s_addr);

    // (key, keylen, num_bkts, hashv, bkt)
    HASH_ADDR(
            &tmp,
            sizeof(tmp),
            td->num_targets,
            hashvalue,
            target
            );


#if defined(DEBUG) || defined(HASH_DEBUG)
    struct sockaddr_storage *sin;

    sin = (struct sockaddr_storage*)&(td->targets[target]);
    char addrbuf0[INET6_ADDRSTRLEN];
    char addrbuf1[INET6_ADDRSTRLEN];
    fprintf(stderr, "hash result: key: %s (%u), hash value: %u, target: %s:%u (%u)\n",
            inet_ntop(AF_INET,
                get_in_addr((struct sockaddr *)their_addr),
                addrbuf0, sizeof(addrbuf0)),
            ntohl(((struct sockaddr_in*)their_addr)->sin_addr.s_addr),
            hashvalue,
            inet_ntop(AF_INET,
                get_in_addr((struct sockaddr *)sin),
                addrbuf1, sizeof(addrbuf1)),
            ntohs(((struct sockaddr_in*)sin)->sin_port),
            target);
#endif

    return (struct sockaddr_storage*)&(td->targets[target]);
}

int8_t ht_add(struct hashable **ht, uint32_t addr, struct sockaddr_storage* output) {
    struct hashable *ht_e;

    HASH_FIND_INT(*ht, &addr, ht_e);
    if (ht_e == NULL) {
        if ((ht_e = (struct hashable*)malloc(sizeof(struct hashable))) == NULL) {
            perror("allocate new hashtable element");
            return -1;
        }
        ht_e->addr = addr;
        HASH_ADD_INT(*ht, addr, ht_e);
    }
    ht_e->output = output;

    return 0;
}

struct sockaddr_storage* ht_get(struct hashable **ht, uint32_t addr) {
    struct hashable *ht_e;

    HASH_FIND_INT(*ht, &addr, ht_e);
    if (ht_e == NULL)
        return NULL;

    return ht_e->output;
}


struct hashable* ht_get_add(struct hashable **ht, uint32_t addr, struct sockaddr_storage* output,
                  uint8_t overwrite) {
    struct hashable *ht_e;

#if defined(DEBUG) || defined(HASH_DEBUG)
    char addrbuf0[INET6_ADDRSTRLEN];
    char addrbuf1[INET6_ADDRSTRLEN];
    uint8_t added = 0;
#endif

    HASH_FIND_INT(*ht, &addr, ht_e);
    if (ht_e == NULL) {
#if defined(DEBUG) || defined(HASH_DEBUG)
        fprintf(stderr, "ht: addr: %s not found. adding output: %s:%u\n",
            inet_ntop(AF_INET, (struct sockaddr_in *)&(addr), addrbuf0,
                sizeof(addrbuf0)),
            inet_ntop(AF_INET,
                get_in_addr((struct sockaddr *)output),
                addrbuf1, sizeof(addrbuf1)),
            ntohs(((struct sockaddr_in *)output)->sin_port));
        added = 1;
#endif
        if ((ht_e = (struct hashable*)malloc(sizeof(struct hashable))) == NULL) {
            perror("allocate new hashtable element");
            return NULL;
        }
        ht_e->addr = addr;
        ht_e->output = output;
        HASH_ADD_INT(*ht, addr, ht_e);
    }

    if (overwrite)
#if defined(DEBUG) || defined(HASH_DEBUG)
    {
#endif
        ht_e->output = output;
#if defined(DEBUG) || defined(HASH_DEBUG)
        if (!added)
            fprintf(stderr, "ht: addr: %s found. overwriting. using new output: %s:%u\n",
                inet_ntop(AF_INET, (struct sockaddr_in *)&(addr), addrbuf0,
                    sizeof(addrbuf0)),
                inet_ntop(AF_INET,
                    get_in_addr((struct sockaddr *)ht_e->output),
                    addrbuf1, sizeof(addrbuf1)),
                ntohs(((struct sockaddr_in *)output)->sin_port));
    }
    else if (!added) {
        fprintf(stderr, "ht: addr: %s found. not overwriting. using output: %s:%u\n",
            inet_ntop(AF_INET, (struct sockaddr_in *)&(addr), addrbuf0,
                sizeof(addrbuf0)),
            inet_ntop(AF_INET,
                get_in_addr((struct sockaddr *)ht_e->output),
                addrbuf1, sizeof(addrbuf1)),
            ntohs(((struct sockaddr_in *)output)->sin_port));
    }
#endif

    return ht_e;
}

void *tee(void *arg0) {
    struct thread_data *td = (struct thread_data *)arg0;
    struct s_features *features = &(td->features);
    struct statistics *stats = &(td->stats);
    struct hashable** hashtable = &(td->hashtable);
    struct hashable* ht_e;

    // incoming packets
    int numbytes = 0;
    struct sockaddr_storage their_addr;
    socklen_t addr_len = sizeof(their_addr);

    // outgoing packets
    char datagram[BUFLEN];
    struct iphdr *iph = (struct iphdr *)datagram;
    struct udphdr *udph = (/*u_int8_t*/void *)iph + sizeof(struct iphdr);
    struct sockaddr_in *sin = &(td->targets[td->thread_id]);

    memset(datagram, 0, BUFLEN);
    // Set appropriate fields in headers
    setup_ip_header(iph, 0, 0, 0);
    setup_udp_header(udph, 0, 0, 0);
    char *data = (char *)udph + sizeof(struct udphdr);

#ifdef DEBUG
        char addrbuf0[INET6_ADDRSTRLEN];
        char addrbuf1[INET6_ADDRSTRLEN];
#endif

    int ssock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(ssock < 0){
        fprintf(stderr, "listener %d: Cannot open raw socket.\n", td->thread_id);
        exit(1);
    }

    while (1) {
        if ((numbytes = recvfrom(td->sockfd, data, BUFLEN-sizeof(struct iphdr)-sizeof(struct udphdr), 0,
            (struct sockaddr *)&their_addr, &addr_len)) == -1) {
            perror("recvfrom");
            continue;
        }

        if (numbytes > 1472) {
#ifdef DEBUG
            fprintf(stderr, "listener %d: packet is %d bytes long cropping to 1472\n", td->thread_id, numbytes);
#endif
            numbytes = 1472;
        }

        data[numbytes] = '\0';

        stats->in_bytecnt += sizeof(struct iphdr) + sizeof(struct udphdr) + numbytes;

        if (features->hash_based_dist || features->load_balanced_dist)
            sin = (struct sockaddr_in*)hash_based_output(&their_addr, td);

        if (features->load_balanced_dist) {
            ht_e = (struct hashable*) ht_get_add(hashtable,
                   ((struct sockaddr_in*)&their_addr)->sin_addr.s_addr,
                   (struct sockaddr_storage*)sin, 0);
            if (ht_e == NULL) {
                fprintf(stderr, "listener %d: Error while adding element to hashtable\n", td->thread_id);
                exit(1);
            }
            sin = (struct sockaddr_in*)ht_e->output;
        }

#ifdef DEBUG
        if (features->hash_based_dist || features->load_balanced_dist)
            fprintf(stderr, "hash result for addr: target: %s:%u (count: %lu)\n",
                    inet_ntop(AF_INET,
                        get_in_addr((struct sockaddr *)sin),
                        addrbuf1, sizeof(addrbuf1)),
                    ntohs(((struct sockaddr_in*)sin)->sin_port),
                    ht_e->pkt_cnt);
#endif

        update_udp_header(udph, numbytes, ((struct sockaddr_in*)&their_addr)->sin_port, sin->sin_port);
        update_ip_header(iph, sizeof(struct udphdr) + numbytes,
                         ((struct sockaddr_in*)&their_addr)->sin_addr.s_addr,
                         sin->sin_addr.s_addr);

        //if (!(features->duplicate))
        //    break;

#ifdef DEBUG
        //char addrbuf0[INET6_ADDRSTRLEN];
        //char addrbuf1[INET6_ADDRSTRLEN];
        fprintf(stderr, "listener %d: got packet from %s\n",
            td->thread_id,
            inet_ntop(their_addr.ss_family,
                get_in_addr((struct sockaddr *)&their_addr),
                addrbuf0, sizeof(addrbuf0)));
        fprintf(stderr, "listener %d: packet is %d bytes long\n", td->thread_id, numbytes);
        fprintf(stderr, "listener %d: packet contains \"%s\"\n", td->thread_id, data);
        fprintf(stderr, "listener %d: sending packet: %s:%u => %s:%u: len: %u\n",
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

        if (sendto(ssock, datagram, iph->tot_len, 0, (struct sockaddr *) sin, sizeof(*sin)) < 0) {
            perror("sendto failed");
            fprintf(stderr, "pktlen: %u\n", iph->tot_len);
        }
        else {
            stats->out_bytecnt += sizeof(struct iphdr) + sizeof(struct udphdr) + numbytes;
            if (features->load_balanced_dist)
                ht_e->pkt_cnt++;
        }
    }
}

void *duplicate(void *arg0) {
    uint16_t cnt;

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
    struct sockaddr_in sin;

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
            //exit(1);
            continue;
        }

        if (numbytes > 1472) {
#ifdef DEBUG
            fprintf(stderr, "listener %d: packet is %d bytes long cropping to 1472\n", td->thread_id, numbytes);
#endif
            numbytes = 1472;
        }

        data[numbytes] = '\0';

#ifdef DEBUG
        char addrbuf0[INET6_ADDRSTRLEN];
        char addrbuf1[INET6_ADDRSTRLEN];
        fprintf(stderr, "listener %d: got packet from %s\n",
            td->thread_id,
            inet_ntop(their_addr.ss_family,
                get_in_addr((struct sockaddr *)&their_addr),
                addrbuf0, sizeof(addrbuf0)));
        fprintf(stderr, "listener %d: packet is %d bytes long\n", td->thread_id, numbytes);
        fprintf(stderr, "listener %d: packet contains \"%s\"\n", td->thread_id, data);
        fprintf(stderr, "listener %d: crafting new packet...\n", td->thread_id);
#endif

        stats->in_bytecnt += sizeof(struct iphdr) + sizeof(struct udphdr) + numbytes;

        // get main output: targets[0]
        // check whether features->duplicate == 1
        // if yes, iterate over remaining targets and also send packets to them
        for (cnt=0; cnt < td->num_targets; cnt++) {

            sin = td->targets[cnt];

            update_udp_header(udph, numbytes, ((struct sockaddr_in*)&their_addr)->sin_port, sin.sin_port);
            update_ip_header(iph, sizeof(struct udphdr) + numbytes,
                            ((struct sockaddr_in*)&their_addr)->sin_addr.s_addr,
                            sin.sin_addr.s_addr);

#ifdef DEBUG
            fprintf(stderr, "listener %d: sending packet: %s:%u => %s:%u: len: %u\n",
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
                fprintf(stderr, "pktlen: %u\n", iph->tot_len);
            }
            else {
                stats->out_bytecnt += sizeof(struct iphdr) + sizeof(struct udphdr) + numbytes;
            }

            if (!(features->duplicate))
                break;
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
    fprintf(stderr, "usage: %s -l <listenaddr:port> -m <r|d> -n <num_threads> "
                    "[-H] [-L] <targetaddr:port> [targetaddr:port [...]]\n"
                    "\tNote: num_threads must be >= number of target addresses", argv[0]);
    exit(1);
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

    uint8_t loadbalanced_dist_enabled = 0;
    uint8_t hash_based_dist_enabled = 0;

    time_t now;

    int index;
    int c;

    opterr = 0;
    while ((c = getopt (argc, argv, "l:m:n:LH")) != -1)
    switch (c) {
        case 'l':
            split_addr(optarg, listenaddr, &listenport);
#ifdef DEBUG
            fprintf(stderr, "listen address: %s:%u\n", listenaddr, listenport);
#endif
        break;
        case 'H':
            hash_based_dist_enabled = 1;
#ifdef DEBUG
            fprintf(stderr, "use hash-based while distributing\n");
#endif
        break;
        case 'L':
            loadbalanced_dist_enabled = 1;
#ifdef DEBUG
            fprintf(stderr, "use load-balancing while distributing\n");
#endif
        break;
        case 'n':
            num_threads = atoi(optarg);
#ifdef DEBUG
            fprintf(stderr, "number of threads: %u\n", num_threads);
#endif
        break;
        case 'm':
            switch (*optarg) {
                case 'r':
                    mode = 'r';
#ifdef DEBUG
                    fprintf(stderr, "mode: round-robin distribution\n");
#endif
                break;
                case 'd':
                    mode = 'd';
#ifdef DEBUG
                    fprintf(stderr, "mode: duplicate\n");
#endif
                break;
                default:
                    mode = 255;
#ifdef DEBUG
                    fprintf(stderr, "invalid mode 0x%x\n", mode);
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
    fprintf(stderr, "setting up listener socket...\n");
#endif
    lsock = open_listener_socket(listenaddr, listenport);

    bzero(tds, sizeof(tds));
    // this one loops over all threads
    for (cnt = 0; cnt < num_threads; cnt++) {
        tds[cnt].thread_id = cnt;
        tds[cnt].sockfd = lsock;
        tds[cnt].targets = targets;
        tds[cnt].num_targets = argc - optind;
        tds[cnt].hashtable = NULL;
        switch (mode) {
            case 'r':
                tds[cnt].features.distribute = 1;
                tds[cnt].features.load_balanced_dist = loadbalanced_dist_enabled;
                tds[cnt].features.hash_based_dist = hash_based_dist_enabled;
            break;
            case 'd':
                tds[cnt].features.duplicate = 1;
                optional_output_enabled = 1;
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
        fprintf(stderr, "relaying to: %s:%u\n", addrbuf, portbuf);
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
    fprintf(stderr, "starting tee...\n");
#endif

    // main thread is the 'extra' stats-thread. use it to catch/handle signals
    fprintf(stderr, "#ts\tlistener\tin_bytecnt\tout_bytecnt\n");
    while (1) {
        if (reset_stats) {
            for (cnt = 0; cnt < num_threads; cnt++) {
                tds[cnt].stats.in_bytecnt = 0;
                tds[cnt].stats.out_bytecnt = 0;
            }
            reset_stats = 0;
        }
        if (stats_enabled) {
            now = time(0);
            for (cnt = 0; cnt < num_threads; cnt++) {
                fprintf(stdout, "%lu\t%u\t%lu\t%lu\n",
                        (unsigned long)now,
                        cnt,
                        tds[cnt].stats.in_bytecnt,
                        tds[cnt].stats.out_bytecnt);
            }
        }

        sleep(1);
    }

    return 0;
}
