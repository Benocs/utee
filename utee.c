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
#include <sys/ioctl.h>
#include <linux/sockios.h>
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

struct s_target {
#if defined ENABLE_IPV6
    struct sockaddr_storage dest;
#else
    struct sockaddr dest;
#endif
    socklen_t dest_len;
    int fd;
};

struct s_statistics {
    uint64_t in_bytecnt;
    uint64_t out_bytecnt;
    uint64_t in_packets;
    uint64_t out_packets;
};

struct s_features {
    uint8_t distribute;
    uint8_t load_balanced_dist;
    uint8_t hash_based_dist;
    uint8_t duplicate;
};

struct s_hashable {
    // TODO: if there shall be IPv6-support, increase the address space
    uint32_t addr;
    struct s_target* target;
    uint64_t pkt_cnt;
    UT_hash_handle hh;
};

struct s_thread_data {
    int thread_id;
    int sockfd;
    struct s_target* targets;
    uint32_t num_targets;
    struct s_statistics stats;
    struct s_features features;
    struct s_hashable* hashtable;
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

struct s_target* hash_based_output(struct sockaddr_storage *their_addr,
                                           struct s_thread_data* td) {

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

    return (struct s_target*)&(td->targets[target]);
}

struct s_hashable* ht_get(struct s_hashable **ht, uint32_t addr) {
    struct s_hashable *ht_e;

    HASH_FIND_INT(*ht, &addr, ht_e);

    return ht_e;
}

struct s_hashable* ht_get_add(struct s_hashable **ht, uint32_t addr, struct s_target* target,
                  uint8_t overwrite) {
    struct s_hashable *ht_e;

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
                get_in_addr((struct sockaddr *)&(target->dest)),
                addrbuf1, sizeof(addrbuf1)),
            ntohs(((struct sockaddr_in *)&(target->dest))->sin_port));
        added = 1;
#endif
        if ((ht_e = (struct s_hashable*)malloc(sizeof(struct s_hashable))) == NULL) {
            perror("allocate new hashtable element");
            return NULL;
        }
        ht_e->addr = addr;
        ht_e->target = target;
        ht_e->pkt_cnt = 0;
        HASH_ADD_INT(*ht, addr, ht_e);
    }

    if (overwrite)
#if defined(DEBUG) || defined(HASH_DEBUG)
    {
#endif
        ht_e->target = target;
#if defined(DEBUG) || defined(HASH_DEBUG)
        if (!added)
            fprintf(stderr, "ht: addr: %s found. overwriting. using new output: %s:%u\n",
                inet_ntop(AF_INET, (struct sockaddr_in *)&(addr), addrbuf0,
                    sizeof(addrbuf0)),
                inet_ntop(AF_INET,
                    get_in_addr((struct sockaddr *)&(ht_e->target->dest)),
                    addrbuf1, sizeof(addrbuf1)),
                ntohs(((struct sockaddr_in *)&(target->dest))->sin_port));
    }
    else if (!added) {
        fprintf(stderr, "ht: addr: %s found. not overwriting. using output: %s:%u\n",
            inet_ntop(AF_INET, (struct sockaddr_in *)&(addr), addrbuf0,
                sizeof(addrbuf0)),
            inet_ntop(AF_INET,
                get_in_addr((struct sockaddr *)&(ht_e->target->dest)),
                addrbuf1, sizeof(addrbuf1)),
            ntohs(((struct sockaddr_in *)&(target->dest))->sin_port));
    }
#endif

    return ht_e;
}

void *tee(void *arg0) {
    // TODO: refactor socket names (src, dest, ...)

    struct s_thread_data *td = (struct s_thread_data *)arg0;
    struct s_features *features = &(td->features);
    struct s_statistics *stats = &(td->stats);
    struct s_hashable** hashtable = &(td->hashtable);
    struct s_hashable* ht_e;

    // incoming packets
    int numbytes = 0;
    struct sockaddr_storage their_addr;
    socklen_t addr_len = sizeof(their_addr);

    // outgoing packets
    char datagram[BUFLEN];
    struct iphdr *iph = (struct iphdr *)datagram;
    struct udphdr *udph = (/*u_int8_t*/void *)iph + sizeof(struct iphdr);
    struct s_target *target = &(td->targets[td->thread_id]);

#if defined ENABLE_IPV6
#else
    struct sockaddr_in *sin = (struct sockaddr_in *)&(target->dest);
#endif

    memset(datagram, 0, BUFLEN);
    // Set appropriate fields in headers
    setup_ip_header(iph, 0, 0, 0);
    setup_udp_header(udph, 0, 0, 0);
    char *data = (char *)udph + sizeof(struct udphdr);

#if defined(DEBUG) || defined(DEBUG_ERRORS)
      char addrbuf0[INET6_ADDRSTRLEN];
#endif
#if defined(DEBUG) || defined(HASH_DEBUG) || defined(DEBUG_ERRORS)
      char addrbuf1[INET6_ADDRSTRLEN];
#endif

#ifdef DEBUG_SOCKET_BUFFERS
    uint64_t outstandingBytes, sendBuffSize, rcvBuffSize;
    socklen_t optlen = sizeof(sendBuffSize);
    getsockopt(ssock, SOL_SOCKET, SO_SNDBUF, &sendBuffSize, &optlen);
    getsockopt(td->sockfd, SOL_SOCKET, SO_RCVBUF, &rcvBuffSize, &optlen);

    ioctl(ssock, SIOCOUTQ, &outstandingBytes);
    fprintf(stderr, "listener %d: send buffer: size: %lu, outstanding bytes: %lu\n",
            td->thread_id, sendBuffSize, outstandingBytes);

    ioctl(td->sockfd, SIOCINQ, &outstandingBytes);
    fprintf(stderr, "listener %d: recv buffer: size: %lu, outstanding bytes: %lu\n",
            td->thread_id, rcvBuffSize, outstandingBytes);
#endif

#ifdef USE_SELECT
    fd_set wfds;
    struct timeval tv;
    int retval;
    FD_ZERO(&wfds);
#endif

    while (1) {
        if ((numbytes = recvfrom(td->sockfd, data, BUFLEN-sizeof(struct iphdr)-sizeof(struct udphdr), 0,
            (struct sockaddr *)&their_addr, &addr_len)) == -1) {
            perror("recvfrom");
            continue;
        }

#ifdef DEBUG_SOCKET_BUFFERS
        ioctl(ssock, SIOCOUTQ, &outstandingBytes);
        if ((outstandingBytes/2) >= sendBuffSize)
            fprintf(stderr, "listener %d: send buffer: size: %lu, outstanding bytes: %lu\n",
                    td->thread_id, sendBuffSize, outstandingBytes);

        ioctl(td->sockfd, SIOCINQ, &outstandingBytes);
        if ((outstandingBytes/2) >= rcvBuffSize)
            fprintf(stderr, "listener %d: recv buffer: size: %lu, outstanding bytes: %lu\n",
                    td->thread_id, rcvBuffSize, outstandingBytes);
#endif

        if (numbytes > 1472) {
#ifdef DEBUG_ERRORS
            fprintf(stderr, "ERROR: listener %d: packet is %d bytes long cropping to 1472\n", td->thread_id, numbytes);
#endif
            numbytes = 1472;
        }

        data[numbytes] = '\0';

        stats->in_bytecnt += sizeof(struct iphdr) + sizeof(struct udphdr) + numbytes;
        stats->in_packets++;

        if (features->hash_based_dist || features->load_balanced_dist) {
            target = (struct s_target*)hash_based_output(&their_addr, td);
            sin = (struct sockaddr_in*)&(target->dest);
        }

        if (features->load_balanced_dist) {
            ht_e = (struct s_hashable*) ht_get_add(hashtable,
                   ((struct sockaddr_in*)&their_addr)->sin_addr.s_addr,
                   target, 0);

            if (ht_e == NULL) {
                fprintf(stderr, "listener %d: Error while adding element to hashtable\n", td->thread_id);
                exit(1);
            }
            target = ht_e->target;
            sin = (struct sockaddr_in*)&(target->dest);
        }

#if defined(DEBUG) || defined(HASH_DEBUG)
        if (features->hash_based_dist || features->load_balanced_dist)
            fprintf(stderr, "listener %d: hash result for addr: target: %s:%u (count: %lu)\n",
                    td->thread_id,
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

#ifdef DEBUG
        fprintf(stderr, "listener %d: got packet from %s:%d\n",
            td->thread_id,
            inet_ntop(their_addr.ss_family,
                get_in_addr((struct sockaddr *)&their_addr),
                addrbuf0, sizeof(addrbuf0)),
            ntohs(((struct sockaddr_in*)&their_addr)->sin_port));
        fprintf(stderr, "listener %d: packet is %d bytes long\n", td->thread_id, numbytes);
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

#ifdef USE_SELECT
        do {
            do {
                tv.tv_sec = 0;
                tv.tv_usec = 100000;
                FD_SET(target->fd, &wfds);
                retval = select((target->fd)+1, NULL, &wfds, NULL, &tv);

                if (retval == -1)
                    perror("select()");
            } while (retval <= 0);
#endif
            int32_t written;
            if ((written = sendto(target->fd, datagram, iph->tot_len, 0, (struct sockaddr *) sin, sizeof(*sin))) < 0) {
                perror("sendto failed");
                fprintf(stderr, "%lu - listener %d: error in write %s - %d\n", time(NULL), td->thread_id, strerror(errno), errno);
#ifdef USE_SELECT
                retval = -1;
#endif
            }
            else {
                stats->out_bytecnt += sizeof(struct iphdr) + sizeof(struct udphdr) + numbytes;
                stats->out_packets++;
                if (features->load_balanced_dist)
                    ht_e->pkt_cnt++;
                if ( written != iph->tot_len) {
                    // TODO: handle this short write - TODO: how to handle?
                    //retval

#ifdef DEBUG_ERRORS
                    fprintf(stderr, "ERROR: listener %d: short write: sent packet: %s:%u => %s:%u: len: %u written: %d\n",
                        td->thread_id,
                        inet_ntop(AF_INET,
                            (struct sockaddr_in *)&(iph->saddr),
                            addrbuf0, sizeof(addrbuf0)),
                        ntohs(udph->source),
                        inet_ntop(AF_INET,
                            (struct sockaddr_in *)&(iph->daddr),
                            addrbuf1, sizeof(addrbuf1)),
                        ntohs(udph->dest),
                        iph->tot_len, written);
#endif
                }
            }
#ifdef USE_SELECT
        } while (retval <= 0);
#endif
    }
}

void *duplicate(void *arg0) {
    // TODO: refactor me / merge into *tee
#if 0
    uint16_t cnt;

    struct s_thread_data *td = (struct s_thread_data *)arg0;
    struct s_features *features = &(td->features);
    struct s_statistics *stats = &(td->stats);

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
        fprintf(stderr, "Could not open raw socket\n");
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
        stats->in_packets++;

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
                stats->out_packets++;
            }

            if (!(features->duplicate))
                break;
        }
    }
#endif
    return NULL;
}

int setsocksize(int s, int level, int optname, void *optval, socklen_t optlen) {
    int ret;
    socklen_t len = sizeof(socklen_t);
    socklen_t value;
    socklen_t saved;

    memcpy(&value, optval, sizeof(socklen_t));

    getsockopt(s, level, optname, &saved, &len);
    if (value > saved) {
        for (; value; value >>= 1) {
            ret = setsockopt(s, level, optname, &value, optlen);
            if (ret >= 0) break;
        }
        if (!value)
            setsockopt(s, level, optname, &saved, len);
    }

    return ret;
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

int prepare_sending_socket(struct sockaddr *addr, socklen_t len, uint32_t pipe_size) {
    int s = 0;

    if ((s = socket(addr->sa_family, SOCK_RAW, IPPROTO_RAW)) == -1) {
        fprintf(stderr, "ERROR: cannot create sending socket: %s\n", strerror(errno));
        exit(1);
    }

    if (pipe_size) {
        socklen_t optlen = sizeof(pipe_size);
        int saved = 0, obtained = 0;

        getsockopt(s, SOL_SOCKET, SO_SNDBUF, &saved, &optlen);
        setsocksize(s, SOL_SOCKET, SO_SNDBUF, &pipe_size, sizeof(pipe_size));
        getsockopt(s, SOL_SOCKET, SO_SNDBUF, &obtained, &optlen);

        if (obtained < saved) {
            setsocksize(s, SOL_SOCKET, SO_SNDBUF, &saved, optlen);
            getsockopt(s, SOL_SOCKET, SO_SNDBUF, &obtained, &optlen);
        }
#ifdef LOG_INFO
        fprintf(stderr, "INFO: sending socket: pipe_size: obtained=%d target=%u saved=%u\n", obtained, pipe_size, saved);
#endif
    }

#ifdef DEBUG
    char addrbuf[INET6_ADDRSTRLEN];
    fprintf(stderr, "connecting to target: %s:%d\n",
        inet_ntop(AF_INET,
            get_in_addr((struct sockaddr *)(addr)),
            addrbuf, sizeof(addrbuf)),
        ntohs(((struct sockaddr_in*)addr)->sin_port));
#endif
    if (connect(s, addr, len) == -1) {
        fprintf(stderr, "ERROR: connect(): %s\n", strerror(errno));
        exit(1);
    }

    return(s);
}

void init_sending_sockets(struct s_target* targets,
        uint32_t num_targets,
        char *raw_targets[],
        uint32_t pipe_size) {

    struct s_target *target = NULL;
    struct sockaddr *sa;
    uint16_t recv_idx;
    int err;
    char dest_addr[256];
    char dest_serv[256];

    char addrbuf[INET6_ADDRSTRLEN];
    uint16_t portbuf;

    for (recv_idx = 0; recv_idx < num_targets; recv_idx++) {
        target = &targets[recv_idx];

        split_addr(raw_targets[recv_idx], addrbuf, &portbuf);

        ((struct sockaddr_in*)&(target->dest))->sin_family = AF_INET;
        ((struct sockaddr_in*)&(target->dest))->sin_addr.s_addr = inet_addr(addrbuf);
        ((struct sockaddr_in*)&(target->dest))->sin_port = htons(portbuf);

        sa = (struct sockaddr *) &target->dest;
        target->dest_len = sizeof(target->dest);

        if (sa->sa_family != 0) {
            if ((err = getnameinfo(sa, target->dest_len, dest_addr, sizeof(dest_addr),
                    dest_serv, sizeof(dest_serv), NI_NUMERICHOST)) == -1) {
                fprintf(stderr, "ERROR: getnameinfo: %d\n", err);
                exit(1);
            }
        }

        target->fd = prepare_sending_socket((struct sockaddr *) &target->dest, target->dest_len, pipe_size);

#ifdef DEBUG
        fprintf(stderr, "receiver: %s:%d :: fd: %d\n",
            inet_ntop(AF_INET,
                get_in_addr((struct sockaddr *)&(target->dest)),
                addrbuf, sizeof(addrbuf)),
            ((struct sockaddr_in*)&(target->dest))->sin_port,
            target->fd);
#endif
    }
}

int open_listener_socket(char* laddr, int lport, uint32_t pipe_size) {
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

    if (pipe_size) {
        socklen_t optlen = sizeof(pipe_size);
        int saved = 0, obtained = 0;

        getsockopt(lsock, SOL_SOCKET, SO_RCVBUF, &saved, &optlen);
        setsocksize(lsock, SOL_SOCKET, SO_RCVBUF, &pipe_size, optlen);
        getsockopt(lsock, SOL_SOCKET, SO_RCVBUF, &obtained, &optlen);

        //if (obtained < saved) {
        //    setsocksize(lsock, SOL_SOCKET, SO_RCVBUF, &saved, optlen);
        //    getsockopt(lsock, SOL_SOCKET, SO_RCVBUF, &obtained, &optlen);
        //}
#ifdef LOG_INFO
        fprintf(stderr, "INFO: listening socket: pipe_size: obtained=%d target=%u saved=%u\n", obtained, pipe_size, saved);
#endif
    }

    setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, (void *)&lsock_option, sizeof(lsock_option));

    if (bind(lsock, (struct sockaddr *)&listener_addr, sizeof(listener_addr)) == -1) {
        close(lsock);
        perror("listener: bind");
        return -1;
    }

    return lsock;
}

// variables that are changed when a signal arrives
uint8_t stats_enabled = 0;
uint8_t reset_stats = 0;
uint8_t optional_output_enabled = 0;

struct s_thread_data tds[MAXTHREADS];
uint16_t num_threads = 0;

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
                    "\tNote: num_threads must be >= number of target "
                    "addresses\n", argv[0]);
    exit(1);
}

int main(int argc, char *argv[]) {

    struct s_target targets[MAXTHREADS];

    char listenaddr[INET6_ADDRSTRLEN];
    uint16_t listenport = 0;
    pthread_t thread[MAXTHREADS];
    uint8_t cnt;
    int lsock;

    unsigned char mode = 0xFF;

    uint8_t loadbalanced_dist_enabled = 0;
    uint8_t hash_based_dist_enabled = 0;

    // 64 MB SND/RCV buffers
    uint32_t pipe_size = 67108864;

    time_t now;

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
    lsock = open_listener_socket(listenaddr, listenport, pipe_size);

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
    init_sending_sockets(targets, argc - optind, &(argv[optind]), pipe_size);

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
    fprintf(stderr, "#ts\tlistener\tin_bytecnt\tout_bytecnt\tin_packets\tout_packets\n");
    while (1) {
        if (reset_stats) {
            for (cnt = 0; cnt < num_threads; cnt++) {
                tds[cnt].stats.in_bytecnt = 0;
                tds[cnt].stats.out_bytecnt = 0;
                tds[cnt].stats.in_packets = 0;
                tds[cnt].stats.out_packets = 0;
            }
            reset_stats = 0;
        }
        if (stats_enabled) {
            now = time(0);
            for (cnt = 0; cnt < num_threads; cnt++) {
                fprintf(stdout, "%lu\t%u\t%lu\t%lu\t%lu\t%lu\n",
                        (unsigned long)now,
                        cnt,
                        tds[cnt].stats.in_bytecnt,
                        tds[cnt].stats.out_bytecnt,
                        tds[cnt].stats.in_packets,
                        tds[cnt].stats.out_packets
                        );
            }
        }

        sleep(1);
    }

    return 0;
}
