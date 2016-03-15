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

#include "smp.h"
#include "uthash.h"

#ifndef GIT_REVISION
  #define GIT_REVISION "<unknown>"
#endif

#ifndef COMPILE_TIME
  #define COMPILE_TIME "<unknown>"
#endif

#ifndef MD5_SUM
  #define MD5_SUM "<unknown>"
#endif

/*
 * TODO:
 * * implement full IPv6 support
 */

#define BUFLEN 4096
#define MAXTHREADS 1024
#define MAXOPTIMIZATIONITERATIONS 20

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

// default hashing for IP addresses is to simply mod them by the number of targets
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
    // per output / target stats
    uint64_t packetcnt;
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
    // per hitter / source stats
    uint64_t packetcnt;
    UT_hash_handle hh;
};

struct s_thread_data {
    int thread_id;
    int sockfd;
    struct s_target* targets;
    uint32_t num_targets;
    struct s_features features;
    struct s_hashable* hashtable;

    uint16_t last_used_master_hashtable_idx;
};

// variables that are changed when a signal arrives
uint8_t optional_output_enabled = 0;

struct s_thread_data tds[MAXTHREADS];
uint16_t num_threads = 0;

struct s_hashable* master_hashtable_ro = NULL;
uint16_t master_hashtable_idx = 0;

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
    // IP checksum is calculated by kernel
    iph->check = 0;

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

struct s_target* hash_based_output(struct sockaddr_storage *source_addr,
                                           struct s_thread_data* td) {

    uint32_t hashvalue = 0;
    uint32_t target = 0;

    uint32_t tmp = ntohl(((struct sockaddr_in*)source_addr)->sin_addr.s_addr);

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
        uint64_t packetcnt, uint8_t overwrite, uint8_t sum_packetcnt) {
    struct s_hashable *ht_e;

#if defined(DEBUG) || defined(HASH_DEBUG)
    char addrbuf0[INET6_ADDRSTRLEN];
    char addrbuf1[INET6_ADDRSTRLEN];
#endif
#if defined(DEBUG) || defined(HASH_DEBUG)
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
        ht_e->packetcnt = packetcnt;
        HASH_ADD_INT(*ht, addr, ht_e);
    }
    else if (overwrite) {
        ht_e->target = target;
        if (sum_packetcnt) {
#if defined(DEBUG) || defined(HASH_DEBUG)
            fprintf(stderr, "ht: summing packetcnt. %lu + %lu = ", ht_e->packetcnt, packetcnt);
#endif
            ht_e->packetcnt += packetcnt;
#if defined(DEBUG) || defined(HASH_DEBUG)
            fprintf(stderr, "%lu\n", ht_e->packetcnt);
#endif
        }
        else {
#if defined(DEBUG) || defined(HASH_DEBUG)
            fprintf(stderr, "ht: overwriting packetcnt. old: %lu  new: %lu\n", ht_e->packetcnt, packetcnt);
#endif
            ht_e->packetcnt = packetcnt;
        }

#if defined(DEBUG) || defined(HASH_DEBUG)
        fprintf(stderr, "ht: addr: %s found. overwriting. using new output: %s:%u\n",
            inet_ntop(AF_INET, (struct sockaddr_in *)&(addr), addrbuf0,
                sizeof(addrbuf0)),
            inet_ntop(AF_INET,
                get_in_addr((struct sockaddr *)&(ht_e->target->dest)),
                addrbuf1, sizeof(addrbuf1)),
            ntohs(((struct sockaddr_in *)&(target->dest))->sin_port));
#endif
    }

#if defined(DEBUG) || defined(HASH_DEBUG)
    if (!added) {
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

void ht_iterate(struct s_hashable *ht) {
    struct s_hashable *s;
    char addrbuf0[INET6_ADDRSTRLEN];
    char addrbuf1[INET6_ADDRSTRLEN];

    for(s=ht; s != NULL; s=s->hh.next) {
        fprintf(stderr, "ht_iter: count: %lu\taddr: %s / %u - target: %s:%u\n",
            s->packetcnt,
            inet_ntop(AF_INET, (struct sockaddr_in *)&(s->addr), addrbuf0,
                sizeof(addrbuf0)),
            ntohl(s->addr),
            inet_ntop(AF_INET,
                get_in_addr((struct sockaddr *)&(s->target->dest)),
                addrbuf1, sizeof(addrbuf1)),
            ntohs(((struct sockaddr_in *)&(s->target->dest))->sin_port));
    }
}

void ht_find_max(struct s_hashable *ht,
        struct s_target *target,
        struct s_hashable **ht_e_max) {

    struct s_hashable *s;
    struct s_hashable *t = *ht_e_max;

#if defined(DEBUG) || defined(HASH_DEBUG)
    char addrbuf0[INET6_ADDRSTRLEN];
    char addrbuf1[INET6_ADDRSTRLEN];
#endif

    for(s=ht; s != NULL; s=s->hh.next) {
        if (s->target == target && t && s->packetcnt > t->packetcnt) {
            t = s;
        }

#if defined(DEBUG) || defined(HASH_DEBUG)
        fprintf(stderr, "ht_iter: count: %lu\taddr: %s, target: %s:%u\n",
            s->packetcnt,
            inet_ntop(AF_INET, (struct sockaddr_in *)&(s->addr), addrbuf0,
                sizeof(addrbuf0)),
            inet_ntop(AF_INET,
                get_in_addr((struct sockaddr *)&(s->target->dest)),
                addrbuf1, sizeof(addrbuf1)),
            ntohs(((struct sockaddr_in *)&(s->target->dest))->sin_port));
#endif
    }

    if (t != NULL) {
        *ht_e_max = t;

#if defined(DEBUG) || defined(HASH_DEBUG)
        fprintf(stderr, "ht_iter: max: count: %lu\taddr: %s, target: %s:%u\n",
            t->packetcnt,
            inet_ntop(AF_INET, (struct sockaddr_in *)&(t->addr), addrbuf0,
                sizeof(addrbuf0)),
            inet_ntop(AF_INET,
                get_in_addr((struct sockaddr *)&(t->target->dest)),
                addrbuf1, sizeof(addrbuf1)),
            ntohs(((struct sockaddr_in *)&(t->target->dest))->sin_port));
#endif
    }
}

void ht_find_best(struct s_hashable *ht,
        struct s_target *target,
        uint64_t excess_packets,
        struct s_hashable **ht_e_best) {

    struct s_hashable *s;
    struct s_hashable *t = *ht_e_best;

    uint64_t abs_current = excess_packets;
    uint64_t abs_candidate;

#if defined(DEBUG) || defined(HASH_DEBUG)
    char addrbuf0[INET6_ADDRSTRLEN];
    char addrbuf1[INET6_ADDRSTRLEN];

    uint64_t tcnt = 0;

    fprintf(stderr, "ht_find_best: excess_packets: %lu\n", excess_packets);
#endif

    for(s=ht; s != NULL; s=s->hh.next) {
        // not our target. skip
        if (s->target != target)
            continue;

#if defined(DEBUG) || defined(HASH_DEBUG)
        tcnt += s->packetcnt;
#endif
        // do not ever over shoot
        if (s->packetcnt > excess_packets)
            continue;

        abs_candidate = excess_packets - s->packetcnt;

        if (abs_candidate < abs_current) {
            abs_current = abs_candidate;

            t = s;
        }
    }

    if (t != NULL) {
        *ht_e_best = t;
#if defined(DEBUG) || defined(HASH_DEBUG)
        fprintf(stderr, "ht_find_best: tot target pkts: %lu\n", tcnt);
        fprintf(stderr, "ht_find_best: best: count: %lu\taddr: %s, target: %s:%u\n",
            t->packetcnt,
            inet_ntop(AF_INET, (struct sockaddr_in *)&(t->addr), addrbuf0,
                sizeof(addrbuf0)),
            inet_ntop(AF_INET,
                get_in_addr((struct sockaddr *)&(t->target->dest)),
                addrbuf1, sizeof(addrbuf1)),
            ntohs(((struct sockaddr_in *)&(t->target->dest))->sin_port));
#endif
    }
}

void ht_copy(struct s_hashable *ht_from, struct s_hashable **ht_to) {
    struct s_hashable *s;

    for(s=ht_from; s != NULL; s=s->hh.next) {
        ht_get_add(ht_to,
                s->addr,
                s->target,
                s->packetcnt,
                1,
                0);
    }
}

void ht_reset_counters(struct s_hashable *ht) {
    struct s_hashable *s;

    for(s=ht; s != NULL; s=s->hh.next) {
        s->packetcnt = 0;
        // TODO: need memory barrier here as target is always shared between master and all threads
        s->target->packetcnt = 0;
    }
}

void ht_delete_all(struct s_hashable *ht) {
    struct s_hashable *s, *tmp;

    HASH_ITER(hh, ht, s, tmp) {
        HASH_DEL(ht, s);
        free(s);
    }
}

void *tee(void *arg0) {
    struct s_thread_data *td = (struct s_thread_data *)arg0;
    struct s_features *features = &(td->features);
    struct s_hashable** hashtable = &(td->hashtable);
    struct s_hashable* ht_e;

    // incoming packets
    int numbytes = 0;
    struct sockaddr_storage source_addr;
    socklen_t addr_len = sizeof(source_addr);

    // outgoing packets
    char datagram[BUFLEN];
    struct iphdr *iph = (struct iphdr *)datagram;
    struct udphdr *udph = (/*u_int8_t*/void *)iph + sizeof(struct iphdr);
    struct s_target *target = &(td->targets[td->thread_id]);

#if defined ENABLE_IPV6
#else
    struct sockaddr_in *target_addr = (struct sockaddr_in *)&(target->dest);
#endif

    memset(datagram, 0, BUFLEN);
    // Set appropriate fields in headers
    setup_ip_header(iph, 0, 0, 0);
    setup_udp_header(udph, 0, 0, 0);
    char *data = (char *)udph + sizeof(struct udphdr);

#if defined(DEBUG) || defined(LOG_ERROR)
      char addrbuf0[INET6_ADDRSTRLEN];
#endif
#if defined(DEBUG) || defined(HASH_DEBUG) || defined(LOG_ERROR)
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
        if (td->last_used_master_hashtable_idx != master_hashtable_idx) {
#ifdef DEBUG_VERBOSE
            // print hashtable of thread 0 (they're all the same)
            if (td->thread_id == 0 && td->last_used_master_hashtable_idx == 0) {
                fprintf(stderr, "listener %d: orig hashtable:\n",
                        td->thread_id);
                ht_iterate(td->hashtable);
                fprintf(stderr, "\n");
            }
#endif
#ifdef LOG_DEBUG
            fprintf(stderr, "listener %d: new master hash map available (%u)\n",
                    td->thread_id, master_hashtable_idx);
            fprintf(stderr, "listener %d: current hashtable:\n",
                    td->thread_id);
            ht_iterate(td->hashtable);
            fprintf(stderr, "listener %d: master hashtable:\n",
                    td->thread_id);
            ht_iterate(master_hashtable_ro);
#endif

            // copy: from, to
            ht_copy(master_hashtable_ro, hashtable);
            td->hashtable = *hashtable;
            hashtable = &(td->hashtable);
            td->last_used_master_hashtable_idx = master_hashtable_idx;

#ifdef DEBUG
            fprintf(stderr, "listener %d: new hashtable:\n",
                    td->thread_id);
            ht_iterate(td->hashtable);
            fprintf(stderr, "\n");

#endif
#ifdef DEBUG_VERBOSE
            // print hashtable of thread 0 (they're all the same)
            if (td->thread_id == 0) {
                fprintf(stderr, "listener %d: new hashtable:\n",
                        td->thread_id);
                ht_iterate(td->hashtable);
                fprintf(stderr, "\n");
            }
#endif
        }

        if ((numbytes = recvfrom(td->sockfd, data, BUFLEN-sizeof(struct iphdr)-sizeof(struct udphdr), 0,
            (struct sockaddr *)&source_addr, &addr_len)) == -1) {
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
#ifdef LOG_ERROR
            fprintf(stderr, "ERROR: listener %d: packet is %d bytes long cropping to 1472\n", td->thread_id, numbytes);
#endif
            numbytes = 1472;
        }

        data[numbytes] = '\0';

        if (features->hash_based_dist || features->load_balanced_dist) {
            target = (struct s_target*)hash_based_output(&source_addr, td);
            target_addr = (struct sockaddr_in*)&(target->dest);
        }

        if (features->load_balanced_dist) {
            ht_e = (struct s_hashable*) ht_get_add(hashtable,
                   ((struct sockaddr_in*)&source_addr)->sin_addr.s_addr,
                   target, 0, 0, 0);

            if (ht_e == NULL) {
                fprintf(stderr, "ERROR: listener %d: Error while adding element to hashtable\n", td->thread_id);
                exit(1);
            }

            target = ht_e->target;
            target_addr = (struct sockaddr_in*)&(target->dest);
        }

#if defined(DEBUG) || defined(HASH_DEBUG)
        if (features->hash_based_dist || features->load_balanced_dist)
            fprintf(stderr, "listener %d: hash result for addr: target: %s:%u (count: %lu)\n",
                    td->thread_id,
                    inet_ntop(AF_INET,
                        get_in_addr((struct sockaddr *)target_addr),
                        addrbuf1, sizeof(addrbuf1)),
                    ntohs(((struct sockaddr_in*)target_addr)->sin_port),
                    ht_e->packetcnt);
#endif

        update_udp_header(udph, numbytes,
                ((struct sockaddr_in*)&source_addr)->sin_port,
                target_addr->sin_port);

        update_ip_header(iph, sizeof(struct udphdr) + numbytes,
                         ((struct sockaddr_in*)&source_addr)->sin_addr.s_addr,
                         target_addr->sin_addr.s_addr);

#ifdef DEBUG
        fprintf(stderr, "listener %d: got packet from %s:%d\n",
            td->thread_id,
            inet_ntop(source_addr.ss_family,
                get_in_addr((struct sockaddr *)&source_addr),
                addrbuf0, sizeof(addrbuf0)),
            ntohs(((struct sockaddr_in*)&source_addr)->sin_port));
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
            if ((written = sendto(target->fd, datagram, iph->tot_len, 0, (struct sockaddr *) target_addr, sizeof(*target_addr))) < 0) {
                perror("sendto failed");
                fprintf(stderr, "%lu - listener %d: error in write %s - %d\n", time(NULL), td->thread_id, strerror(errno), errno);
#ifdef USE_SELECT
                retval = -1;
#endif
            }
            else {
                if (features->load_balanced_dist) {
                    // NOTE: some small errors / off-by-sth is allowed. no mutex
                    // pthread_mutex_lock(&(td->mutex_read_tds));

                    // NOTE: need smp_atomic_inc for target-cnt as it is shared between all threads
                    // NOTE: don't neet smp_atomic_inc for src as they are thread-local in hash maps

                    // update per source packetcnt
                    ht_e->packetcnt++;
                    // update per target packetcnt
                    // TODO: need memory barrier here as target is always shared between master and all threads
                    target->packetcnt++;

                    // pthread_mutex_unlock(&(td->mutex_read_tds));
                }

                if ( written != iph->tot_len) {
                    // handle this short write - log and move on
#ifdef LOG_ERROR
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
    pthread_exit(NULL);
    // TODO: free memory
}

void *duplicate(void *arg0) {
    // TODO: refactor me / merge into *tee
#if 0
    uint16_t cnt;

    struct s_thread_data *td = (struct s_thread_data *)arg0;
    struct s_features *features = &(td->features);

    // incoming packets
    int numbytes = 0;
    struct sockaddr_storage source_addr;
    socklen_t addr_len = sizeof(source_addr);

    // outgoing packets
    char datagram[BUFLEN];
    struct iphdr *iph = (struct iphdr *)datagram;
    struct udphdr *udph = (/*u_int8_t*/void *)iph + sizeof(struct iphdr);
    struct sockaddr_in target_addr;

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
            (struct sockaddr *)&source_addr, &addr_len)) == -1) {
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
            inet_ntop(source_addr.ss_family,
                get_in_addr((struct sockaddr *)&source_addr),
                addrbuf0, sizeof(addrbuf0)));
        fprintf(stderr, "listener %d: packet is %d bytes long\n", td->thread_id, numbytes);
        fprintf(stderr, "listener %d: packet contains \"%s\"\n", td->thread_id, data);
        fprintf(stderr, "listener %d: crafting new packet...\n", td->thread_id);
#endif

        // check whether features->duplicate == 1
        // if yes, iterate over remaining targets and also send packets to them
        for (cnt=0; cnt < td->num_targets; cnt++) {

            target_addr = td->targets[cnt];

            update_udp_header(udph, numbytes, ((struct sockaddr_in*)&source_addr)->sin_port, target_addr.sin_port);
            update_ip_header(iph, sizeof(struct udphdr) + numbytes,
                            ((struct sockaddr_in*)&source_addr)->sin_addr.s_addr,
                            target_addr.sin_addr.s_addr);

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

            if (sendto(ssock, datagram, iph->tot_len, 0, (struct sockaddr *) &target_addr, sizeof(target_addr)) < 0) {
                perror("sendto failed");
                fprintf(stderr, "pktlen: %u\n", iph->tot_len);
            }

            if (!(features->duplicate))
                break;
        }
    }
#endif
    pthread_exit(NULL);
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

#ifdef LOG_INFO
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

uint8_t load_balance(struct s_thread_data* tds, uint16_t num_threads,
        uint64_t threshold, double reorder_threshold,
        struct s_hashable** master_hashtable) {

    struct s_hashable *s;

    uint16_t itcnt;
    uint16_t cnt;
    uint8_t time_to_load_balance = 0;
    uint8_t hit_reordering_threshold = 0;

    struct s_hashable* ht_e_best = NULL;

    // create a copy of current counters
    // this allows for the modification independent of ongoing forwarding of packets
    uint64_t per_target_pkt_cnt[MAXTHREADS];

    uint16_t target_min_idx;
    uint16_t target_max_idx;

    uint64_t tot_cnt = 0;

    uint64_t excess_packets;

    double ideal_avg = (1 / (double)tds[0].num_targets);
    double target_avg;

    // TODO: this is not overflow-safe (but only used when printing, so no bug)
    // TODO: clean code, commit. - test duplicate in legacy-utee, deploy, test new utee on 2nd output
    static uint64_t global_total_cnt = 0;

#if defined(DEBUG) || defined(LOG_INFO)
    char addrbuf0[INET6_ADDRSTRLEN];
    char addrbuf1[INET6_ADDRSTRLEN];
    char addrbuf2[INET6_ADDRSTRLEN];
#endif

    // NOTE: from s_hashable, the hitter-stats can be extracted
    // NOTE: from s_target the output stats can be extracted

    if (num_threads == 0)
        return 0;

    // create a copy of current counters
    // this allows for the modification independent of ongoing forwarding of packets
    for (cnt = 0; cnt < tds[0].num_targets; cnt++ ) {
        per_target_pkt_cnt[cnt] = tds[0].targets[cnt].packetcnt;
        tot_cnt += per_target_pkt_cnt[cnt];
    }

    // early abort if no packets were forwarded in last iteration
    if (!tot_cnt)
        return 0;

    if (tot_cnt > threshold)
        time_to_load_balance = 1;
    else
        return 0;

#if defined(DEBUG)
    fprintf(stderr, "len(master_hastable) before thread merging: %u\n", HASH_COUNT(*master_hashtable));
#endif
    // merge hashmaps
    for (cnt = 0; cnt < num_threads; cnt++) {
#if defined(DEBUG)
        fprintf(stderr, "merging thread hash maps into master. thread: %u\n", cnt);
#endif
#if defined(LOG_ERROR)
        if (tds[cnt].hashtable == *master_hashtable)
            fprintf(stderr, "[ERR] master hash table is same as thread's %u table\n", cnt);
#endif
#if defined(DEBUG)
        fprintf(stderr, "tds[%u].hashtable: %p - master: %p\n", cnt, tds[cnt].hashtable, *master_hashtable);
#endif
        for(s=tds[cnt].hashtable; s != NULL; s=s->hh.next) {
            // only copy ht_e if it has seen any packets within the last iteration
            if (s->packetcnt) {
                ht_get_add(master_hashtable, s->addr, s->target, s->packetcnt, 1, 1);
            }
        }
    }

#if defined(DEBUG)
    fprintf(stderr, "len(master_hastable) after thread merging: %u\n", HASH_COUNT(*master_hashtable));
#endif

    for(s=*master_hashtable; s != NULL; s=s->hh.next) {
        global_total_cnt += s->packetcnt;
    }

#if defined(LOG_INFO)
    // only print stats if there were any forwarded packets since last optimization iteration
    if (tot_cnt) {
        fprintf(stderr, "lb cnt stats. ideal=%.4f tot=%lu\n\t", ideal_avg, global_total_cnt);
        for (cnt = 0; cnt < tds[0].num_targets; cnt++ ) {
            fprintf(stderr, "%2u=%.4f ", cnt, per_target_pkt_cnt[cnt] / (double)tot_cnt);
            if (cnt && (cnt+1) % 8 == 0)
                fprintf(stderr, "\n\t");
        }
        fprintf(stderr, "\n");
    }
#endif

    for (itcnt = 0; itcnt < MAXOPTIMIZATIONITERATIONS; itcnt++) {
#if defined(LOG_INFO)
        fprintf(stderr, "optimization iteration: %u of max %u\n",
                itcnt+1, MAXOPTIMIZATIONITERATIONS);
#endif

        // find target with smallest counter and target with largest counter
        target_min_idx = 0;
        target_max_idx = 0;
        for (cnt = 1; cnt < tds[0].num_targets; cnt++ ) {
            if (per_target_pkt_cnt[cnt] < per_target_pkt_cnt[target_min_idx])
                target_min_idx = cnt;
            if (per_target_pkt_cnt[cnt] > per_target_pkt_cnt[target_max_idx])
                target_max_idx = cnt;
        }

        target_avg = per_target_pkt_cnt[target_min_idx] / (double)tot_cnt;
        if (((target_avg / ideal_avg) < 1) && (1 - (target_avg / ideal_avg) > reorder_threshold))
            hit_reordering_threshold = 1;
        else
            hit_reordering_threshold = 0;
#if defined(DEBUG)
        fprintf(stderr, "hit_reordering_threshold: %u\n", hit_reordering_threshold);
#endif

#if defined(DEBUG)
        fprintf(stderr, "load_balance: out_min: %s:%u (%lu), "
                "out_max: %s:%u (%lu)\n",
                inet_ntop(AF_INET,
                    get_in_addr((struct sockaddr *)&(tds[0].targets[target_min_idx].dest)),
                    addrbuf0, sizeof(addrbuf0)),
                ntohs(((struct sockaddr_in *)&(tds[0].targets[target_min_idx].dest))->sin_port),
                per_target_pkt_cnt[target_min_idx],
                inet_ntop(AF_INET,
                    get_in_addr((struct sockaddr *)&(tds[0].targets[target_max_idx].dest)),
                    addrbuf1, sizeof(addrbuf1)),
                ntohs(((struct sockaddr_in *)&(tds[0].targets[target_max_idx].dest))->sin_port),
                per_target_pkt_cnt[target_max_idx]
                );
#endif
        // if !hit_reordering_threshold, abort optimization
        if (!hit_reordering_threshold)
            break;

        // calculate ideal excess lines/hits
        excess_packets = per_target_pkt_cnt[target_max_idx] - per_target_pkt_cnt[target_min_idx];
#if defined(LOG_INFO)
        fprintf(stderr, "line diff: %lu - min(%u): %lu, max(%u): %lu, trying to shift up to %lu pkts\n",
                excess_packets,
                target_min_idx,
                per_target_pkt_cnt[target_min_idx],
                target_max_idx,
                per_target_pkt_cnt[target_max_idx],
                excess_packets/2);
#endif
        // find hitter in biggest target which is closest to excess_packets/2
        ht_find_best(*master_hashtable, &(tds[0].targets[target_max_idx]), excess_packets/2, &ht_e_best);


        // cannot find any matching hashtable entry. abort
        if (ht_e_best == NULL) {
            fprintf(stderr,  "[ERROR] no ht_e_best found\n");
            break;
        }

#if defined(LOG_INFO)

        fprintf(stderr, "moving high hitter: %s from: %s:%u (%p) to %s:%u (%p) (count: %lu)\n",
            inet_ntop(AF_INET, (struct sockaddr_in *)&(ht_e_best->addr), addrbuf0,
                sizeof(addrbuf0)),

            // from:
            inet_ntop(AF_INET,
                get_in_addr((struct sockaddr *)&(ht_e_best->target->dest)),
                addrbuf1, sizeof(addrbuf1)),
            ntohs(((struct sockaddr_in *)&(ht_e_best->target->dest))->sin_port),
            ht_e_best->target,

            // to:
            inet_ntop(AF_INET,
                get_in_addr((struct sockaddr *)&(tds[0].targets[target_min_idx].dest)),
                addrbuf2, sizeof(addrbuf2)),
            ntohs(((struct sockaddr_in *)&(tds[0].targets[target_min_idx].dest))->sin_port),
            &(tds[0].targets[target_min_idx]),

            ht_e_best->packetcnt);
#endif

        // move exporter (in ht_e_best) from target_max to target_min
        ht_e_best->target = &(tds[0].targets[target_min_idx]);
        ht_get_add(master_hashtable,
                ht_e_best->addr,
                ht_e_best->target,
                ht_e_best->packetcnt,
                1,
                0);

        // refresh counters
        per_target_pkt_cnt[target_max_idx] -= ht_e_best->packetcnt;
        per_target_pkt_cnt[target_min_idx] += ht_e_best->packetcnt;

    } // end of for (itcnt = 0; itcnt < MAXOPTIMIZATIONITERATIONS; itcnt++) {

    // delete last ro-hashtable
    ht_delete_all(master_hashtable_ro);
    // reset all counters in next hashtable
    ht_reset_counters(*master_hashtable);
    // reset all thread counters
    // TODO: need memory barrier here
    for (cnt = 0; cnt < tds[0].num_targets; cnt++ ) {
        tds[0].targets[cnt].packetcnt = 0;
    }
    fprintf(stderr, "\n===================================================\n");
    // set next hashtable as ro
    master_hashtable_ro = *master_hashtable;
    // release master pointer to next hashtable
    *master_hashtable = NULL;
    // increase hashtable version to signal threads that a new version is available
    master_hashtable_idx++;
#if defined(DEBUG)
    fprintf(stderr, "len(master_hastable) after swapping to ro: %u\n", HASH_COUNT(*master_hashtable));
#endif

    return time_to_load_balance;
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
                    "addresses\n\n"
                    "repository revision: %s\n"
                    "compile time:        %s\n"
                    "source MD5 sum:      %s\n",
                    argv[0], GIT_REVISION, COMPILE_TIME, MD5_SUM);
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

    struct s_hashable* master_hashtable = NULL;

    // default: load balance every 50e6 lines, min difference between targets: 10%
    uint64_t threshold = 50e6;
    double reorder_threshold = 0.1;

    // 64 MB SND/RCV buffers
    uint32_t pipe_size = 67108864;

    int c;

    opterr = 0;
    while ((c = getopt (argc, argv, "l:m:n:i:t:LH")) != -1)
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
        case 'i':
            threshold = atoi(optarg);
#ifdef DEBUG
            fprintf(stderr, "load balance every: %lu lines\n", threshold);
#endif
        break;
        case 't':
            reorder_threshold = atof(optarg);
#ifdef DEBUG
            fprintf(stderr, "load balance inter-target threshold: %.2f\n", reorder_threshold);
#endif
        break;
        default:
            usage(argc, argv);
    }
    if (mode == 0xFF || num_threads == 0 || listenport == 0 || (argc - optind > num_threads))
        usage(argc, argv);

    signal(SIGUSR1, sig_handler_toggle_optional_output);

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
        tds[cnt].last_used_master_hashtable_idx = 0;
        // pthread_mutex_init(&(tds[cnt].mutex_read_tds), NULL);

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
    while (1) {

        if (loadbalanced_dist_enabled) {
            load_balance(tds, num_threads, threshold, reorder_threshold,
                    &master_hashtable);
        }

        sleep(1);
    }

    // for (cnt = 0; cnt < num_threads; cnt++) {
    //     pthread_mutex_destroy(&(tds[cnt].mutex_read_tds));
    // }
    pthread_exit(NULL);
    return 0;
}
