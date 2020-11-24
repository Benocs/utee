/* utee - transparent udp tee proxy
 *
 * Copyright (C) 2016-2020 Benocs
 * Author: Robert Wuttke <robert@benocs.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
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

/* vim: foldmarker={,}:foldmethod=marker */

#define _GNU_SOURCE

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

#include "libutee.h"

/* The max BATCH_SIZE is 1024.
 * The kernel refuses to send more than that in one batch */
#define BATCH_SIZE_MAX    1024
/* Maximum packet size utee can handle. Larger packets will be dropped. */
#define PKT_BUFSIZE 1500
/* Total allowed time in seconds to read one batch of packets */
#define READ_BATCH_TIMEOUT 1

/* Macros to help accessing header fields in a packet */
#define IPUDP_HDR_SIZE (sizeof(struct iphdr) + sizeof(struct udphdr))
#define get_ip_hdr(dgram) ((struct iphdr *)dgram)
#define get_udp_hdr(dgram) ((struct udphdr *)((/*u_int8_t*/void *)dgram + sizeof(struct iphdr)))
#define IOVEC_HDR 0
#define IOVEC_PAYLOAD 1

// variables that are changed when a signal arrives
volatile uint8_t optional_output_enabled = 0;
volatile uint8_t run_flag = 1;

struct s_thread_data tds[MAXTHREADS];
uint8_t num_threads = 0;

atomic_t master_hashtable_idx;

/*
 * TODO:
 * * implement full IPv6 support
 */

unsigned short checksum (unsigned short *buf, int nwords) {
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr_storage *sa) {
    if (sa->ss_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

// TODO: this is not IPv6 safe
void update_ip_header(struct iphdr *iph, uint16_t ip_payload_len,
                      uint32_t saddr, uint32_t daddr) {
    iph->tot_len = sizeof(struct iphdr) + ip_payload_len;
    iph->saddr = saddr;
    iph->daddr = daddr;
}

// TODO: this is not IPv6 safe
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

// TODO: this is not IPv6 safe
uint64_t create_ht_key_from_addr(struct sockaddr_storage* addr) {
    if (addr->ss_family == AF_INET) {
        return (uint64_t)ntohl(((struct sockaddr_in*)addr)->sin_addr.s_addr);
    }
    else {
        // TODO: this is not IPv6 safe
        return 0;
    }
}

const char* get_ip(struct sockaddr_storage* addr, char* addrbuf) {
    return inet_ntop(addr->ss_family, get_in_addr(addr), addrbuf, INET6_ADDRSTRLEN);
}

uint16_t get_port(struct sockaddr_storage* addr) {
    if (addr->ss_family == AF_INET)
        return ntohs(((struct sockaddr_in *)addr)->sin_port);
    else
        return ntohs(((struct sockaddr_in6 *)addr)->sin6_port);
}

const char* get_ip4_uint(uint32_t addr, char* addrbuf) {
    return inet_ntop(AF_INET, &addr, addrbuf, INET_ADDRSTRLEN);
}

uint16_t get_port4_uint(uint16_t port) {
    return ntohs(port);
}

void cp_sockaddr(struct sockaddr_storage* src, struct sockaddr_storage* dst) {
    uint8_t cnt;

    //ht_e->source = *source;

    if (src->ss_family == AF_INET) {
        ((struct sockaddr_in *)dst)->sin_family = ((struct sockaddr_in *)src)->sin_family;
        ((struct sockaddr_in *)dst)->sin_port = ((struct sockaddr_in *)src)->sin_port;
        ((struct sockaddr_in *)dst)->sin_addr = ((struct sockaddr_in *)src)->sin_addr;
    }
    else {
        ((struct sockaddr_in6 *)dst)->sin6_family = ((struct sockaddr_in6 *)src)->sin6_family;
        ((struct sockaddr_in6 *)dst)->sin6_port = ((struct sockaddr_in6 *)src)->sin6_port;
        ((struct sockaddr_in6 *)dst)->sin6_flowinfo = ((struct sockaddr_in6 *)src)->sin6_flowinfo;
        ((struct sockaddr_in6 *)dst)->sin6_scope_id = ((struct sockaddr_in6 *)src)->sin6_scope_id;

        for (cnt=0; cnt<16; cnt++)
        ((struct sockaddr_in6 *)dst)->sin6_addr.s6_addr[cnt] = \
            ((struct sockaddr_in6 *)src)->sin6_addr.s6_addr[cnt];
    }
}

struct s_target* hash_based_output(uint64_t key, struct s_thread_data* td) {

    uint32_t hashvalue = 0;
    uint32_t target = 0;

    // (key, keylen, num_bkts, hashv, bkt)
    HASH_ADDR(
            &key,
            sizeof(key),
            td->num_targets,
            hashvalue,
            target
            );

#if defined(HASH_DEBUG) && defined(DEBUG_VERBOSE)
    fprintf(stderr, "%lu - hash_based_output: key: %lx\ttarget: %u\n",
        time(NULL), key, target);
#endif

    return (struct s_target*)&(td->targets[target]);
}

struct s_hashable* ht_get(struct s_hashable **ht, uint64_t key) {
    struct s_hashable *ht_e = NULL;

    HASH_FIND(hh, *ht, &key, sizeof(key), ht_e);

    return ht_e;
}

struct s_hashable* ht_get_add(struct s_hashable **ht, uint64_t key,
        struct sockaddr_storage* source, struct s_target* target,
        uint64_t itemcnt, uint8_t overwrite, uint8_t sum_itemcnt) {
    struct s_hashable *ht_e = NULL;
#if defined(HASH_DEBUG)
    char addrbuf0[INET6_ADDRSTRLEN];
    char addrbuf1[INET6_ADDRSTRLEN];
    char addrbuf2[INET6_ADDRSTRLEN];
    uint8_t added = 0;
#endif

    HASH_FIND(hh, *ht, &key, sizeof(key), ht_e);
    if (ht_e == NULL) {
#if defined(HASH_DEBUG)
        fprintf(stderr, "%lu - ht: key: 0x%lx, addr: %s:%u not found. adding output: %s:%u\n",
            time(NULL),
            key,
            get_ip(source, addrbuf0),
            get_port(source),
            get_ip(&(target->dest), addrbuf1),
            get_port(&(target->dest)));


        added = 1;
#endif
        if ((ht_e = (struct s_hashable*)malloc(sizeof(struct s_hashable))) == NULL) {
            perror("allocate new hashtable element");
            return NULL;
        }
        ht_e->key = key;
        cp_sockaddr(source, &(ht_e->source));
        ht_e->target = target;
        smp_mb__before_atomic();
        atomic_set(&(ht_e->itemcnt), itemcnt);
        smp_mb__after_atomic();
        HASH_ADD(hh, *ht, key, sizeof(key), ht_e);
    }
    else if (overwrite) {
        //ht_e->key = key;
        ht_e->target = target;
        smp_mb__before_atomic();
        if (sum_itemcnt) {
#if defined(HASH_DEBUG)
            fprintf(stderr, "%lu - ht: summing itemcnt. %lu + %lu = ",
                    time(NULL),
                    atomic_read(&(ht_e->itemcnt)), itemcnt);
#endif
            atomic_add(itemcnt, &(ht_e->itemcnt));
#if defined(HASH_DEBUG)
            fprintf(stderr, "%lu\n", atomic_read(&(ht_e->itemcnt)));
#endif
        }
        else {
#if defined(HASH_DEBUG)
            fprintf(stderr, "%lu - ht: overwriting itemcnt. old: %lu  new: %lu\n",
                    time(NULL),
                    atomic_read(&(ht_e->itemcnt)), itemcnt);
#endif
            atomic_set(&(ht_e->itemcnt), itemcnt);
        }
        smp_mb__after_atomic();

#if defined(HASH_DEBUG)
        fprintf(stderr, "%lu - ht: key: 0x%lx, addr: %s:%u found. overwriting. using new output: %s:%u\n",
            time(NULL),
            key,
            get_ip(source, addrbuf0),
            get_port(source),
            get_ip(&(ht_e->target->dest), addrbuf1),
            get_port(&(ht_e->target->dest)));
#endif
    }

#if defined(HASH_DEBUG)
    if (!added) {
        fprintf(stderr, "%lu - ht: key: 0x%lx, addr: %s:%u found. not overwriting. using output: %s:%u. ht_key: 0x%lx, ht_addr: %s:%u\n",
            time(NULL),
            key,
            get_ip(source, addrbuf0),
            get_port(source),
            get_ip(&(ht_e->target->dest), addrbuf1),
            get_port(&(ht_e->target->dest)),
            ht_e->key,
            get_ip(&(ht_e->source), addrbuf2),
            get_port(&(ht_e->source))
            );
    }
#endif
    return ht_e;
}

void ht_iterate(struct s_hashable *ht) {
    struct s_hashable *s;
    char addrbuf0[INET6_ADDRSTRLEN];
    char addrbuf1[INET6_ADDRSTRLEN];

    smp_mb__before_atomic();
    for(s=ht; s != NULL; s=s->hh.next) {
        fprintf(stderr, "%lu - ht_iter: count: %lu\taddr: %s:%u - target: %s:%u\n",
            time(NULL),
            atomic_read(&(s->itemcnt)),
            get_ip(&(s->source), addrbuf0),
            get_port(&(s->source)),
            get_ip(&(s->target->dest), addrbuf1),
            get_port(&(s->target->dest)));
    }
}

void ht_find_max(struct s_hashable *ht,
        struct s_target *target,
        struct s_hashable **ht_e_max) {

    struct s_hashable *s;
    struct s_hashable *t = *ht_e_max;

#if defined(HASH_DEBUG) || defined(LOAD_BALANCE_DEBUG)
    char addrbuf0[INET6_ADDRSTRLEN];
    char addrbuf1[INET6_ADDRSTRLEN];
#endif

    smp_mb__before_atomic();
    for(s=ht; s != NULL; s=s->hh.next) {
        if (s->target == target && t && atomic_read(&(s->itemcnt)) > atomic_read(&(t->itemcnt))) {
            t = s;
        }

#if defined(HASH_DEBUG) || defined(LOAD_BALANCE_DEBUG)
        fprintf(stderr, "%lu - ht_iter: count: %lu\taddr: %s:%u, target: %s:%u\n",
            time(NULL),
            atomic_read(&(s->itemcnt)),
            get_ip(&(s->source), addrbuf0),
            get_port(&(s->source)),
            get_ip(&(s->target->dest), addrbuf1),
            get_port(&(s->target->dest)));
#endif
    }

    if (t != NULL) {
        *ht_e_max = t;

#if defined(HASH_DEBUG) || defined(LOAD_BALANCE_DEBUG)
        fprintf(stderr, "%lu - ht_iter: max: count: %lu\taddr: %s:%u, target: %s:%u\n",
            time(NULL),
            atomic_read(&(t->itemcnt)),
            get_ip(&(t->source), addrbuf0),
            get_port(&(t->source)),
            get_ip(&(t->target->dest), addrbuf1),
            get_port(&(t->target->dest)));
#endif
    }
}

void ht_find_best(struct s_hashable *ht,
        struct s_target *target,
        uint64_t excess_items,
        struct s_hashable **ht_e_best) {

    struct s_hashable *s;
    struct s_hashable *t = *ht_e_best;

    uint64_t abs_current = excess_items;
    uint64_t abs_candidate;

#if defined(HASH_DEBUG) || defined(LOAD_BALANCE_DEBUG)
    char addrbuf0[INET6_ADDRSTRLEN];
    char addrbuf1[INET6_ADDRSTRLEN];

    uint64_t tcnt = 0;

    fprintf(stderr, "%lu - ht_find_best: excess_items: %lu\n", time(NULL), excess_items);
#endif

    smp_mb__before_atomic();
    for(s=ht; s != NULL; s=s->hh.next) {
        // not our target. skip
        if (s->target != target)
            continue;

#if (defined(HASH_DEBUG) || defined(LOAD_BALANCE_DEBUG))
        tcnt += atomic_read(&(s->itemcnt));
#endif
#if (defined(HASH_DEBUG) || defined(LOAD_BALANCE_DEBUG)) && defined(DEBUG_VERBOSE)

        fprintf(stderr, "%lu - ht_find_best: count: %lu\tkey: 0x%lx\taddr: %s:%u, target: %s:%u\n",
            time(NULL),
            atomic_read(&(s->itemcnt)),
            s->key,
            get_ip(&(s->source), addrbuf0),
            get_port(&(s->source)),
            get_ip(&(s->target->dest), addrbuf1),
            get_port(&(s->target->dest)));
#endif
        // do not ever over shoot
        if (atomic_read(&(s->itemcnt)) > excess_items)
            continue;

        abs_candidate = excess_items - atomic_read(&(s->itemcnt));

        if (abs_candidate < abs_current) {
            abs_current = abs_candidate;

            t = s;
        }
    }

    if (t != NULL) {
        *ht_e_best = t;
#if defined(HASH_DEBUG) || defined(LOAD_BALANCE_DEBUG)
        fprintf(stderr, "%lu - ht_find_best: tot target items: %lu\n", time(NULL), tcnt);
        fprintf(stderr, "%lu - ht_find_best: best: count: %lu\taddr: %s:%u, target: %s:%u\n",
            time(NULL),
            atomic_read(&(t->itemcnt)),
            get_ip(&(t->source), addrbuf0),
            get_port(&(t->source)),
            get_ip(&(t->target->dest), addrbuf1),
            get_port(&(t->target->dest)));
#endif
    }
}

uint32_t ht_target_count(struct s_hashable *ht, struct s_target *target) {

    uint32_t count = 0;
    struct s_hashable *s;

#if defined(HASH_DEBUG) || defined(LOAD_BALANCE_DEBUG)
    char addrbuf0[INET6_ADDRSTRLEN];
#endif

    smp_mb__before_atomic();
    for(s=ht; s != NULL; s=s->hh.next)
        if (s->target == target)
            count++;

#if defined(HASH_DEBUG) || defined(LOAD_BALANCE_DEBUG)
    fprintf(stderr, "%lu - ht_target_count: target: %s:%u, count: %u\n",
        time(NULL),
        get_ip(&(target->dest), addrbuf0),
        get_port(&(target->dest)),
        count);
#endif
    return count;
}

void ht_copy(struct s_hashable *ht_from, struct s_hashable **ht_to) {
    struct s_hashable *s;

#if defined(HASH_DEBUG)
    fprintf(stderr, "%lu - ht_copy: copying hashtable. ignore ht_get_add prints\n", time(NULL));
#endif
    smp_mb__before_atomic();
    for(s=ht_from; s != NULL; s=s->hh.next) {
        ht_get_add(ht_to,
                s->key,
                &(s->source),
                s->target,
                atomic_read(&(s->itemcnt)),
                1,
                0);
    }
    smp_mb__after_atomic();
#if defined(HASH_DEBUG)
    fprintf(stderr, "%lu - ht_copy: done copying hashtable.\n", time(NULL));
#endif
}

void ht_reset_counters(struct s_hashable *ht) {
    struct s_hashable *s;

    smp_mb__before_atomic();
    for(s=ht; s != NULL; s=s->hh.next) {
        atomic_set(&(s->itemcnt), 0);
        atomic_set(&(s->target->itemcnt), 0);
    }
    smp_mb__after_atomic();
}

void ht_delete_all(struct s_hashable *ht) {
    struct s_hashable *s, *tmp;

    HASH_ITER(hh, ht, s, tmp) {
        HASH_DEL(ht, s);
        free(s);
    }
    free(ht);
    ht = NULL;
}

void *demux(void *arg0) {
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

#if defined(DEBUG) || defined(LOG_ERROR) || defined(DEBUG_SOCKETS)
    char addrbuf0[INET6_ADDRSTRLEN];
#endif
#if defined(DEBUG) || defined(HASH_DEBUG) || defined(LOG_ERROR) || defined(DEBUG_SOCKETS)
    char addrbuf1[INET6_ADDRSTRLEN];
#endif

#if defined(USE_SELECT_READ) || defined(USE_SELECT_WRITE)
    fd_set rfds;
    fd_set wfds;
    struct timeval tv;
    int retval;
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
#endif

    while (run_flag) {
        smp_mb__before_atomic();
        if (atomic_read(&(td->last_used_master_hashtable_idx)) != atomic_read(&master_hashtable_idx)) {
#ifdef DEBUG_VERBOSE
            // print hashtable of thread 0 (they're all the same)
            if (td->thread_id == 0 && atomic_read(&(td->last_used_master_hashtable_idx)) == 0) {
                fprintf(stderr, "%lu - listener %d: orig hashtable:\n",
                        time(NULL), td->thread_id);
                ht_iterate(td->hashtable);
                fprintf(stderr, "\n");
            }
#endif
#ifdef DEBUG
            fprintf(stderr, "%lu - listener %d: new master hash map available (%lu)\n",
                    time(NULL), td->thread_id, atomic_read(&master_hashtable_idx));
#endif

            // set next hashtable
            td->hashtable_ro_old = td->hashtable;
            td->hashtable = td->hashtable_ro;
            td->hashtable_ro = NULL;
            hashtable = &(td->hashtable);
            atomic_set(&(td->last_used_master_hashtable_idx), atomic_read(&master_hashtable_idx));
            smp_mb__after_atomic();

#ifdef DEBUG_VERBOSE
            // print hashtable of thread 0 (they're all the same)
            if (td->thread_id == 0) {
                fprintf(stderr, "%lu - listener %d: new hashtable:\n",
                        time(NULL), td->thread_id);
                ht_iterate(*hashtable);
                fprintf(stderr, "\n");
            }
#endif
        }

#ifdef USE_SELECT_READ
        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        FD_SET(td->sockfd, &rfds);
        retval = select((td->sockfd)+1, &rfds, NULL, NULL, &tv);

        if (retval == -1) {
            perror("select()");
            continue;
        }
        else if (!retval) {
            continue;
        }
#endif
        if ((numbytes = recvfrom(td->sockfd, data, BUFLEN-sizeof(struct iphdr)-sizeof(struct udphdr), 0,
                (struct sockaddr *)&source_addr, &addr_len)) == -1) {
            perror("recvfrom");
            continue;
        }

        if (numbytes > 1472) {
#ifdef LOG_ERROR
            fprintf(stderr, "%lu - ERROR: listener %d: packet is %d bytes long cropping to 1472\n",
                    time(NULL), td->thread_id, numbytes);
#endif
            numbytes = 1472;
        }

        data[numbytes] = '\0';

        if (features->hash_based_dist || features->load_balanced_dist) {
            target = (struct s_target*)hash_based_output(
                    CREATE_HT_KEY(&source_addr), td);
            target_addr = (struct sockaddr_in*)&(target->dest);
        }

        if (features->load_balanced_dist) {
            ht_e = (struct s_hashable*) ht_get_add(hashtable,
                    CREATE_HT_KEY(&source_addr),
                    &source_addr,
                    target, 0, 0, 0);

            if (ht_e == NULL) {
                fprintf(stderr, "%lu - ERROR: listener %d: Error while adding element to hashtable\n",
                        time(NULL), td->thread_id);
                exit(1);
            }

            target = ht_e->target;
            target_addr = (struct sockaddr_in*)&(target->dest);
        }

#if defined(HASH_DEBUG)
        if (features->hash_based_dist || features->load_balanced_dist)
            smp_mb__before_atomic();
            fprintf(stderr, "%lu - listener %d: hash result for addr: target: %s:%u (count: %lu)\n",
                    time(NULL),
                    td->thread_id,
                    get_ip((struct sockaddr_storage *)target_addr, addrbuf0),
                    get_port((struct sockaddr_storage *)target_addr),
                    atomic_read(&(ht_e->itemcnt)));
#endif

        update_udp_header(udph, numbytes,
                ((struct sockaddr_in*)&source_addr)->sin_port,
                target_addr->sin_port);

        update_ip_header(iph, sizeof(struct udphdr) + numbytes,
                         ((struct sockaddr_in*)&source_addr)->sin_addr.s_addr,
                         target_addr->sin_addr.s_addr);

#ifdef DEBUG_SOCKETS
        fprintf(stderr, "%lu - listener %d: got packet from %s:%d\n",
            time(NULL),
            td->thread_id,
            get_ip(&source_addr, addrbuf0),
            get_port(&source_addr));
        fprintf(stderr, "%lu - listener %d: packet is %d bytes long\n",
                time(NULL), td->thread_id, numbytes);
        fprintf(stderr, "%lu - listener %d: sending packet: %s:%u => %s:%u: len: %u\n",
            time(NULL),
            td->thread_id,
            get_ip4_uint(iph->saddr, addrbuf0),
            get_port4_uint(udph->source),
            get_ip4_uint(iph->daddr, addrbuf1),
            get_port4_uint(udph->dest),
            iph->tot_len);
#endif

#ifdef USE_SELECT_WRITE
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
#ifdef USE_SELECT_WRITE
                retval = -1;
#endif
            }
            else {
                if (features->load_balanced_dist) {
                    // NOTE: need atomic_inc for target-cnt as it is shared between all threads

                    smp_mb__before_atomic();
                    if (features->lb_bytecnt_based) {
                        // update per source bytecnt
                        atomic_add(written, &(ht_e->itemcnt));
                        // update per target bytetcnt
                        atomic_add(written, &(target->itemcnt));
                    }
                    else {
                        // update per source packetcnt
                        atomic_inc(&(ht_e->itemcnt));
                        // update per target packetcnt
                        atomic_inc(&(target->itemcnt));
                    }
                    smp_mb__after_atomic();
                }

                if ( written != iph->tot_len) {
                    // handle this short write - log and move on
#ifdef LOG_ERROR
                    fprintf(stderr, "%lu - ERROR: listener %d: short write: sent packet: %s:%u => %s:%u: len: %u written: %d\n",
                        time(NULL),
                        td->thread_id,
                        get_ip4_uint(iph->saddr, addrbuf0),
                        get_port4_uint(udph->source),
                        get_ip4_uint(iph->daddr, addrbuf1),
                        get_port4_uint(udph->dest),
                        iph->tot_len, written);
#endif
                }
            }
#ifdef USE_SELECT_WRITE
        } while (retval <= 0);
#endif
    }

#ifdef LOG_INFO
    fprintf(stderr, "%lu - [listener %u] shutting down\n",
            time(NULL), td->thread_id);
#endif
    ht_delete_all(*hashtable);
    ht_delete_all(td->hashtable_ro);
    // only try to delete old hashtable if it still has entries. otherwise
    // the master-thread has already deleted it (for us)
    if (!(td->hashtable_ro_old == NULL))
        ht_delete_all(td->hashtable_ro_old);
    return NULL;
}

/*
 *
 * tee mmsg
 *
 */

void *tee(void *arg0) {
    struct s_thread_data *td = (struct s_thread_data *)arg0;
    struct s_features *features = &(td->features);

    /* The top level array serving as a buffer for all messages. */
    struct mmsghdr msgs[BATCH_SIZE_MAX];

    /* first iovec is for the ip/udp header when sending,
     * the second iovec is for the payload when receiving and sending.
     */
    struct iovec iovecs[BATCH_SIZE_MAX][2];
    char header_bufs[BATCH_SIZE_MAX][IPUDP_HDR_SIZE];
    char payload_bufs[BATCH_SIZE_MAX][PKT_BUFSIZE];
    struct sockaddr_in source_addresses[BATCH_SIZE_MAX];

    int recvmmsg_retval;
    int sendmmsg_retval;
    int sendmmsg_tosend;
    const uint8_t max_send_tries = 3;
    uint8_t send_retry_count;

    uint8_t target_cnt;
    uint16_t mmsg_cnt;
    struct timespec timeout;

    /* pointer pointing to the message that's currently being handled */
    struct msghdr* msg;

#ifdef DEBUG_SOCKETS
    char addrbuf0[INET6_ADDRSTRLEN];
    char addrbuf1[INET6_ADDRSTRLEN];
#endif

    memset(msgs, 0, sizeof(msgs));
    for (mmsg_cnt = 0; mmsg_cnt < td->batch_size; mmsg_cnt++) {
        iovecs[mmsg_cnt][IOVEC_HDR].iov_base = header_bufs[mmsg_cnt];
        iovecs[mmsg_cnt][IOVEC_HDR].iov_len = IPUDP_HDR_SIZE;

        iovecs[mmsg_cnt][IOVEC_PAYLOAD].iov_base = payload_bufs[mmsg_cnt];
        iovecs[mmsg_cnt][IOVEC_PAYLOAD].iov_len = PKT_BUFSIZE;

        msgs[mmsg_cnt].msg_hdr.msg_iov = &(iovecs[mmsg_cnt][IOVEC_PAYLOAD]);
        msgs[mmsg_cnt].msg_hdr.msg_iovlen = 1;

        msgs[mmsg_cnt].msg_hdr.msg_name = &(source_addresses[mmsg_cnt]);
        msgs[mmsg_cnt].msg_hdr.msg_namelen = sizeof(source_addresses[mmsg_cnt]);

        /* The msg_control structs are not used. */
        msgs[mmsg_cnt].msg_hdr.msg_controllen = 0;

        /* Initialize constant fields in headers */
        setup_ip_header(get_ip_hdr(header_bufs[mmsg_cnt]), 0, 0, 0);
        setup_udp_header(get_udp_hdr(header_bufs[mmsg_cnt]), 0, 0, 0);
    }

    while (run_flag) {
        timeout.tv_sec = READ_BATCH_TIMEOUT;
        timeout.tv_nsec = 0;

        /* Receive up to td->batch_size UDP packets but abort/stop waiting for new packets
         * if the total receive time exceeds timeout.
         */
        recvmmsg_retval = recvmmsg(td->sockfd, msgs, td->batch_size, MSG_WAITALL, &timeout);
        if (recvmmsg_retval == -1) {
            /* only print an error if errno is not EWOULDBLOCK.
             * EWOULDBLOCK is silently skipped as it's part of
             * normal operations to have times when there's no packet to read.
             */
            if (errno != EWOULDBLOCK) {
                perror("recvmmsg");
            }
            continue;
        }

        /* iterate over all outputs / target addresses */
        for (target_cnt=0; target_cnt < td->num_targets; target_cnt++) {
            sendmmsg_tosend = recvmmsg_retval;

            /* iterate over received packets */
            for (mmsg_cnt = 0; mmsg_cnt < recvmmsg_retval; mmsg_cnt++) {
                if (target_cnt == 0) {
                    msg = &(msgs[mmsg_cnt].msg_hdr);

                    if (msgs[mmsg_cnt].msg_len > 1472) {
#ifdef LOG_ERROR
                        fprintf(stderr, "%lu - ERROR: listener %d: packet is %d bytes long cropping to 1472\n",
                                time(NULL), td->thread_id, msgs[mmsg_cnt].msg_len);
#endif
                        msgs[mmsg_cnt].msg_len = 1472;
                    }
                    payload_bufs[mmsg_cnt][msgs[mmsg_cnt].msg_len] = 0;

                    /* update iov_len with msg_len.
                    * This will be used by the kernel as length of the payload
                    * when sending the packet to the target(s).
                    */
                    iovecs[mmsg_cnt][IOVEC_PAYLOAD].iov_len = msgs[mmsg_cnt].msg_len;

                    /* reset any msg_flags that have been set
                    * while reading the packet */
                    msg->msg_flags = 0;

                    /* When receiving a packet, msg_hdr.msg_name will be filled
                    * with the source IP address by the kernel.
                    * When sending a packet, a raw socket is used. As the outgoing
                    * "payload" data contains the IP and the UDP header, the
                    * msg_hdr.msg_name field is not being used. This is communicated
                    * to the kernel by setting the msg_hdr.msg_namelen field to 0.
                    *
                    * This is only done on the first iteration. In every other
                    * iteration,since the swapping already has been done, only the
                    * destination address is replaced.
                    */
                    msg->msg_namelen = 0;

                    /* ... and prepend the ip/udp headers to the payload */
                    msg->msg_iov = &(iovecs[mmsg_cnt][IOVEC_HDR]);
                    msg->msg_iovlen = 2;
                    msg->msg_controllen = 0;
                }

                /* set destination address and destination port for this target */
                update_ip_header(get_ip_hdr(header_bufs[mmsg_cnt]),
                        sizeof(struct udphdr) + iovecs[mmsg_cnt][IOVEC_PAYLOAD].iov_len,
                        ((struct sockaddr_in)(source_addresses[mmsg_cnt])).sin_addr.s_addr,
                        (*(struct sockaddr_in*)&(td->targets[target_cnt].dest)).sin_addr.s_addr);
                update_udp_header(get_udp_hdr(header_bufs[mmsg_cnt]),
                        iovecs[mmsg_cnt][IOVEC_PAYLOAD].iov_len,
                        ((struct sockaddr_in)(source_addresses[mmsg_cnt])).sin_port,
                        (*(struct sockaddr_in*)&(td->targets[target_cnt].dest)).sin_port);

#ifdef DEBUG_SOCKETS
                fprintf(stderr, "%lu - listener %d: sending packet: %s:%u => %s:%u: len: %u\n",
                    time(NULL),
                    td->thread_id,
                    get_ip4_uint(get_ip_hdr(header_bufs[mmsg_cnt])->saddr, addrbuf0),
                    get_port4_uint(get_udp_hdr(header_bufs[mmsg_cnt])->source),
                    get_ip4_uint(get_ip_hdr(header_bufs[mmsg_cnt])->daddr, addrbuf1),
                    get_port4_uint(get_udp_hdr(header_bufs[mmsg_cnt])->dest),
                    get_ip_hdr(header_bufs[mmsg_cnt])->tot_len);
#endif

            } /* for (mmsg_cnt = 0; mmsg_cnt < recvmmsg_retval; mmsg_cnt++) */

            /* hand over all packets to the kernel for sending them out.
             *
             * On success, sendmmsg() returns the number of messages sent
             * from msgvec; if this is less than vlen, the caller can retry
             * with a further sendmmsg() call to send the remaining messages.
             *
             * On error, -1 is returned, and errno is set to indicate the error.
             */
            send_retry_count = 0;
            while (sendmmsg_tosend > 0 && send_retry_count < max_send_tries) {
                sendmmsg_retval = sendmmsg(td->targets[target_cnt].fd, msgs, sendmmsg_tosend, 0);
                if (sendmmsg_retval < 0) {
                    // TODO: handle write error - question is how? simply abort/quit?
                    perror("sendmmsg");
                }
#ifdef LOG_ERROR
                else if (sendmmsg_retval < sendmmsg_tosend) {
                    fprintf(stderr, "%lu - ERROR: listener %d: short write: %d/%d packets sent\n",
                            time(NULL), td->thread_id, sendmmsg_retval, sendmmsg_tosend);
                }
#endif
                sendmmsg_tosend -= sendmmsg_retval;
                send_retry_count += 1;
            }

            /* If packet duplicaton mode is enabled,
             * iterate over remaining targets and also send packets to them.
             * Otherwise, abort here.
             *
             * This needs to be always checked as the duplication feature
             * can be disabled and enabled using SIGUSR1 which calls
             * sig_handler_toggle_optional_output() and toggles this variable.
             */
            if (!(features->duplicate))
                break;
        } /* for (target_cnt=0; target_cnt < td->num_targets; target_cnt++) */

        /* prepare packet buffer for next read */
        for (mmsg_cnt = 0; mmsg_cnt < td->batch_size; mmsg_cnt++) {
            iovecs[mmsg_cnt][IOVEC_PAYLOAD].iov_len = PKT_BUFSIZE;

            msgs[mmsg_cnt].msg_hdr.msg_iov = &(iovecs[mmsg_cnt][IOVEC_PAYLOAD]);
            msgs[mmsg_cnt].msg_hdr.msg_iovlen = 1;

            msgs[mmsg_cnt].msg_hdr.msg_namelen = sizeof(source_addresses[mmsg_cnt]);
        }
    } /* while (run_flag) */
#ifdef LOG_INFO
    fprintf(stderr, "%lu - [listener-%u] shutting down\n", time(NULL), td->thread_id);
#endif
    return NULL;
}

int setsocksize(int s, int level, int optname, void *optval, socklen_t optlen) {
    int ret = -1;
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
        fprintf(stderr, "%lu - ERROR: cannot create sending socket: %s\n",
                time(NULL), strerror(errno));
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
        fprintf(stderr, "%lu - INFO: sending socket: pipe_size: obtained=%d target=%u saved=%u\n",
                time(NULL), obtained, pipe_size, saved);
#endif
    }

#ifdef DEBUG
    char addrbuf[INET6_ADDRSTRLEN];
    fprintf(stderr, "%lu - connecting to target: %s:%d\n",
        time(NULL),
        get_ip((struct sockaddr_storage *)addr, addrbuf),
        get_port((struct sockaddr_storage *)addr));
#endif
    if (connect(s, addr, len) == -1) {
        fprintf(stderr, "%lu - ERROR: connect(): %s\n",
                time(NULL), strerror(errno));
        exit(1);
    }

    return(s);
}

void init_sending_sockets(struct s_target* targets,
        uint8_t num_targets,
        char *raw_targets[],
        uint32_t pipe_size) {

    struct s_target *target = NULL;
    struct sockaddr *sa;
    uint8_t recv_idx;
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
                fprintf(stderr, "%lu - ERROR: getnameinfo: %d\n",
                        time(NULL), err);
                exit(1);
            }
        }

        target->fd = prepare_sending_socket((struct sockaddr *) &target->dest, target->dest_len, pipe_size);

#ifdef LOG_INFO
        fprintf(stderr, "%lu - receiver: %s:%d :: fd: %d\n",
            time(NULL),
            get_ip((struct sockaddr_storage *)&(target->dest), addrbuf),
            get_port((struct sockaddr_storage *)&(target->dest)),
            target->fd);
#endif
    }
}

int open_listener_socket(char* laddr, int lport, uint32_t pipe_size) {
    struct sockaddr_in listener_addr;
    int lsock_option = 1;
    int lsock;

    /* socket receive timeout of 0.5 seconds */
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 500000;

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
        fprintf(stderr, "%lu - INFO: listening socket: pipe_size: obtained=%d target=%u saved=%u\n",
                time(NULL), obtained, pipe_size, saved);
#endif
    }

    if (setsockopt(lsock, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&tv, sizeof(struct timeval)) == -1) {
        close(lsock);
        perror("listener: setsockopt SO_RCVTIMEO");
        return -1;
    }
    if (setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, (void *)&lsock_option, sizeof(lsock_option)) == -1) {
        close(lsock);
        perror("listener: setsockopt SO_REUSEADDR");
        return -1;
    }
    if (bind(lsock, (struct sockaddr *)&listener_addr, sizeof(listener_addr)) == -1) {
        close(lsock);
        perror("listener: bind");
        return -1;
    }

    return lsock;
}

void load_balance(struct s_thread_data* tds, uint8_t num_threads,
        uint64_t threshold, double reorder_threshold,
        struct s_hashable** master_hashtable) {

    struct s_hashable *s;

    uint16_t itcnt;
    uint8_t cnt;
    uint8_t hit_reordering_threshold = 0;

    struct s_hashable* ht_e_best = NULL;

    // create a copy of current counters
    // this allows for the modification independent of ongoing forwarding of packets
    uint64_t per_target_item_cnt[MAXTHREADS];

    uint16_t target_min_idx = 0;
    uint16_t target_max_idx = 0;

    uint64_t tot_cnt = 0;
    uint64_t excess_items;

    double ideal_avg = (1 / (double)tds[0].num_targets);
    double target_avg;

    // NOTE: this is not overflow-safe (but only used when printing, so no bug)
    static uint64_t global_total_cnt = 0;

    uint8_t threads_reading_from_master;

    uint8_t invalidated_targets[MAXTHREADS];

#if defined(DEBUG) || defined(LOG_INFO)
    char addrbuf0[INET6_ADDRSTRLEN];
    char addrbuf1[INET6_ADDRSTRLEN];
    char addrbuf2[INET6_ADDRSTRLEN];
#endif

    // NOTE: from s_hashable, the hitter-stats can be extracted
    // NOTE: from s_target the output stats can be extracted

    if (num_threads == 0)
        return;

    // create a copy of current counters
    // this allows for the modification independent of ongoing forwarding of packets
    smp_mb__before_atomic();
    for (cnt = 0; cnt < tds[0].num_targets; cnt++ ) {
        per_target_item_cnt[cnt] = atomic_read(&(tds[0].targets[cnt].itemcnt));
        tot_cnt += per_target_item_cnt[cnt];
    }

    // early abort if no items were forwarded in last iteration
    if (!tot_cnt)
        return;

    if (tot_cnt < threshold) {
#if defined(DEBUG)
        fprintf(stderr, "%lu - not load balancing: tot_cnt < threshold: %lu < %lu\n",
                time(NULL), tot_cnt, threshold);
#endif
        return;
    }

    for (cnt = 0; cnt < num_threads; cnt++)
        invalidated_targets[cnt] = 0;

#if defined(DEBUG)
    fprintf(stderr, "%lu - len(master_hashtable) before thread merging: %u\n",
            time(NULL), HASH_COUNT(*master_hashtable));
#endif
    // merge hashmaps
    for (cnt = 0; cnt < num_threads; cnt++) {
#if defined(DEBUG)
        fprintf(stderr, "%lu - merging thread hash maps into master. thread: %u\n",
                time(NULL), cnt);
#endif
#if defined(LOG_ERROR)
        if (tds[cnt].hashtable == *master_hashtable)
            fprintf(stderr, "%lu - [ERR] master hash table is same as thread's %u table\n",
                    time(NULL), cnt);
#endif
#if defined(DEBUG)
        fprintf(stderr, "%lu - tds[%u].hashtable: %p - master: %p\n",
                time(NULL), cnt, tds[cnt].hashtable, *master_hashtable);
#endif
        smp_mb__before_atomic();
        for(s=tds[cnt].hashtable; s != NULL; s=s->hh.next) {
            // only copy ht_e if it has seen any items within the last iteration
            if (atomic_read(&(s->itemcnt))) {
                ht_get_add(master_hashtable, s->key, &(s->source), s->target,
                        atomic_read(&(s->itemcnt)), 1, 1);
            }
        }
    }

#if defined(DEBUG)
    fprintf(stderr, "%lu - len(master_hashtable) after thread merging: %u\n",
            time(NULL), HASH_COUNT(*master_hashtable));
#endif

    for(s=*master_hashtable; s != NULL; s=s->hh.next) {
        global_total_cnt += atomic_read(&(s->itemcnt));
    }

#if defined(LOG_INFO)
    // only print stats if there were any forwarded items since last optimization iteration
    if (tot_cnt) {
        fprintf(stderr, "%lu - lb cnt stats. ideal=%.4f thresh=[%.4f, %.4f] "
                "tot=%lu\nrelative counts:\n\t",
                time(NULL),
                ideal_avg,
                ideal_avg - (ideal_avg * (double) reorder_threshold),
                ideal_avg + (ideal_avg * (double) reorder_threshold),
                global_total_cnt);
        for (cnt = 0; cnt < tds[0].num_targets; cnt++ ) {
            fprintf(stderr, "%2u=%.4f ", cnt, per_target_item_cnt[cnt] / (double)tot_cnt);
            if (cnt && (cnt+1) % 8 == 0)
                fprintf(stderr, "\n\t");
        }
        fprintf(stderr, "\nabsolute counts:\n\t");
        for (cnt = 0; cnt < tds[0].num_targets; cnt++ ) {
            fprintf(stderr, "%2u=%lu ", cnt, per_target_item_cnt[cnt]);
            if (cnt && (cnt+1) % 8 == 0)
                fprintf(stderr, "\n\t");
        }
        fprintf(stderr, "\n");
    }
#endif

    for (itcnt = 0; itcnt < MAXOPTIMIZATIONITERATIONS; itcnt++) {
        ht_e_best = NULL;

        // find target with smallest counter and target with largest counter
        target_min_idx = 0;

        // initialize target_max_idx with first _valid_ target that
        // has more than one source
        for (cnt = 0; cnt < tds[0].num_targets; cnt++ ) {
            if (ht_target_count(*master_hashtable, &(tds[0].targets[cnt])) > 1 &&
                    (! invalidated_targets[cnt])) {
                target_max_idx = cnt;
                break;
            }
        }

        for (cnt = 0; cnt < tds[0].num_targets; cnt++ ) {
            if (per_target_item_cnt[cnt] < per_target_item_cnt[target_min_idx])
                target_min_idx = cnt;
            if (per_target_item_cnt[cnt] > per_target_item_cnt[target_max_idx] &&
                    ht_target_count(*master_hashtable, &(tds[0].targets[cnt])) > 1 &&
                    (! invalidated_targets[cnt]))
                target_max_idx = cnt;
        }

        // if target_max is in the invalidated_targets set, abort optimization as
        // we do not have an invalid target
        if (invalidated_targets[target_max_idx])
            break;

        // min and max target are the same (and thus all other ones with respect to min, max)
        // abort optimization in this case since shifting from and to the same target does not make sense
        if (target_min_idx == target_max_idx)
            break;

        target_avg = per_target_item_cnt[target_min_idx] / (double)tot_cnt;
        if (((target_avg / ideal_avg) < 1) && (1 - (target_avg / ideal_avg) > reorder_threshold))
            hit_reordering_threshold = 1;
        else
            hit_reordering_threshold = 0;
#if defined(DEBUG)
        fprintf(stderr, "%lu - hit_reordering_threshold: %u\n",
                time(NULL), hit_reordering_threshold);
#endif
        // if !hit_reordering_threshold, abort optimization
        if (!hit_reordering_threshold)
            break;

#if defined(LOG_INFO)
        fprintf(stderr, "%lu - optimization iteration: %u of max %u\n",
                time(NULL), itcnt+1, MAXOPTIMIZATIONITERATIONS);
#endif
#if defined(DEBUG)
        fprintf(stderr, "%lu - load_balance: out_min: %s:%u (%lu), "
                "out_max: %s:%u (%lu)\n",
                time(NULL),
                get_ip((struct sockaddr_storage *)&(tds[0].targets[target_min_idx].dest), addrbuf0),
                get_port((struct sockaddr_storage *)&(tds[0].targets[target_min_idx].dest)),
                per_target_item_cnt[target_min_idx],
                get_ip((struct sockaddr_storage *)&(tds[0].targets[target_max_idx].dest), addrbuf1),
                get_port((struct sockaddr_storage *)&(tds[0].targets[target_max_idx].dest)),
                per_target_item_cnt[target_max_idx]
                );
#endif

        // calculate ideal excess lines/hits
        // TODO: shouldn't this be changed to excess_items = target_avg / ideal_avg?

        excess_items = per_target_item_cnt[target_max_idx] - per_target_item_cnt[target_min_idx];
        // divide excess_items by two to evenly distriube excess items. if this is not done,
        // target_min_idx would immediately be an output with the most traffic
        excess_items = excess_items / 2;

        // if excess_items is 0, abort optimization (shifting 0 from somewhere to somewhere else is mindless)
        if (! excess_items)
            break;

#if defined(LOG_INFO)
        fprintf(stderr, "%lu - line diff: %lu - min(%u): %lu, max(%u): %lu, trying to shift up to %lu bytes\n",
                time(NULL),
                excess_items,
                target_min_idx,
                per_target_item_cnt[target_min_idx],
                target_max_idx,
                per_target_item_cnt[target_max_idx],
                excess_items);
#endif
        // find hitter in biggest target which is closest to excess_items
        ht_find_best(*master_hashtable, &(tds[0].targets[target_max_idx]), excess_items, &ht_e_best);


        // cannot find any matching hashtable entry. abort
        if (ht_e_best == NULL) {
            fprintf(stderr,  "%lu - [ERROR] no ht_e_best found. invalidating target: %u\n", time(NULL), target_max_idx);
            invalidated_targets[target_max_idx] = 1;
        }
        else {
#if defined(LOG_INFO)
            fprintf(stderr, "%lu - moving high hitter: %s:%u from: %s:%u (%p) to %s:%u (%p) (count: %lu)\n",
                time(NULL),
                get_ip(&(ht_e_best->source), addrbuf0),
                get_port(&(ht_e_best->source)),

                // from:
                get_ip(&(ht_e_best->target->dest), addrbuf1),
                get_port(&(ht_e_best->target->dest)),
                ht_e_best->target,

                // to:
                get_ip(&(tds[0].targets[target_min_idx].dest), addrbuf2),
                get_port(&(tds[0].targets[target_min_idx].dest)),
                &(tds[0].targets[target_min_idx]),

                atomic_read(&(ht_e_best->itemcnt)));
#endif

            // move exporter (in ht_e_best) from target_max to target_min
            ht_e_best->target = &(tds[0].targets[target_min_idx]);
            ht_get_add(master_hashtable,
                    ht_e_best->key,
                    &(ht_e_best->source),
                    ht_e_best->target,
                    atomic_read(&(ht_e_best->itemcnt)),
                    1,
                    0);

            // refresh counters
            per_target_item_cnt[target_max_idx] -= atomic_read(&(ht_e_best->itemcnt));
            per_target_item_cnt[target_min_idx] += atomic_read(&(ht_e_best->itemcnt));
        }
    } // end of for (itcnt = 0; itcnt < MAXOPTIMIZATIONITERATIONS; itcnt++) {

    smp_mb__before_atomic();
    // wait for all threads to release 'lock' on tds[cnt]->hashtable_ro
    do {
        threads_reading_from_master = 0;
        for (cnt = 0; cnt < num_threads; cnt++ ) {
            if (atomic_read(&(tds[cnt].last_used_master_hashtable_idx)) != atomic_read(&master_hashtable_idx))
                threads_reading_from_master = 1;
        }

        if (threads_reading_from_master) {
#if defined(LOG_WARN)
            fprintf(stderr, "%lu - waiting for threads to release master_hashtable\n",
                    time(NULL));
#endif
            sleep(1);
        }
    } while(threads_reading_from_master);

    // reset all counters in next hashtable
    ht_reset_counters(*master_hashtable);
    // delete last ro-hashtable and set next ro-hashtable
    for (cnt = 0; cnt < tds[0].num_targets; cnt++ ) {
        ht_delete_all(tds[cnt].hashtable_ro_old);
        ht_copy(*master_hashtable, &(tds[cnt].hashtable_ro));
    }
    // reset all thread counters
    for (cnt = 0; cnt < tds[0].num_targets; cnt++ ) {
        atomic_set(&(tds[0].targets[cnt].itemcnt), 0);
    }
    fprintf(stderr, "\n%lu ===================================================\n",
            time(NULL));

    smp_mb__after_atomic();
    ht_delete_all(*master_hashtable);
    // release master pointer to next hashtable
    *master_hashtable = NULL;
    // increase hashtable version to signal threads that a new version is available
    smp_mb__before_atomic();
    atomic_inc(&master_hashtable_idx);
    smp_mb__after_atomic();
#if defined(DEBUG)
    fprintf(stderr, "%lu - len(master_hashtable) after swapping to ro: %u\n",
            time(NULL), HASH_COUNT(*master_hashtable));
#endif
}

void sig_handler_toggle_optional_output(int signum) {
    uint16_t cnt;

    optional_output_enabled = (!optional_output_enabled);
#if defined(LOG_INFO)
    fprintf(stderr, "%lu - [signal] toggling optional output: %u\n",
            time(NULL), optional_output_enabled);
#endif

    for (cnt = 0; cnt < num_threads; cnt++) {
        tds[cnt].features.duplicate = optional_output_enabled;
    }
}

void sig_handler_shutdown(int signum) {
    run_flag = 0;
#if defined(LOG_INFO)
    fprintf(stderr, "%lu - [signal] requesting shutdown\n", time(NULL));
#endif
}

void sig_handler_ignore(int signum) {
#if defined(LOG_INFO)
    fprintf(stderr, "%lu - [signal] ignoring signal: %d\n",
            time(NULL), signum);
#endif
}

