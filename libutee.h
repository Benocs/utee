/* utee - transparent udp tee proxy
 *
 * Copyright (C) 2016 Benocs
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

#ifndef __LIBUTEE_H_
#define __LIBUTEE_H_

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
#define MAXOPTIMIZATIONITERATIONS 500

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
    struct sockaddr_storage dest;
    socklen_t dest_len;
    int fd;
    // per output / target stats
    atomic_t itemcnt;
};

struct s_features {
    uint8_t distribute;
    uint8_t load_balanced_dist;
    uint8_t hash_based_dist;
    uint8_t duplicate;
    uint8_t lb_bytecnt_based;
};

struct s_hashable {
    uint64_t key;
    struct sockaddr_storage source;
    struct s_target* target;
    // per hitter / source stats
    atomic_t itemcnt;
    UT_hash_handle hh;
};

struct s_thread_data {
    int thread_id;
    int sockfd;
    struct s_target* targets;
    uint32_t num_targets;
    struct s_features features;
    struct s_hashable* hashtable;

    atomic_t last_used_master_hashtable_idx;
};

unsigned short checksum (unsigned short *buf, int nwords);

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr_storage *sa);

// TODO: this is not IPv6 safe
void update_ip_header(struct iphdr *iph, uint16_t ip_payload_len,
                      uint32_t saddr, uint32_t daddr);

// TODO: this is not IPv6 safe
void setup_ip_header(struct iphdr *iph, uint16_t ip_payload_len,
                     uint32_t saddr, uint32_t daddr);

void update_udp_header(struct udphdr *udph, uint16_t udp_payload_len,
                       uint16_t source, uint16_t dest);

void setup_udp_header(struct udphdr *udph, uint16_t udp_payload_len,
                      uint16_t source, uint16_t dest);

// TODO: this is not IPv6 safe
uint64_t create_key_from_addr(struct sockaddr_storage* addr);

const char* get_ip(struct sockaddr_storage* addr, char* addrbuf);
uint16_t get_port(struct sockaddr_storage* addr);

const char* get_ip4_uint(uint32_t addr, char* addrbuf);
uint16_t get_port4_uint(uint16_t port);

void cp_sockaddr(struct sockaddr_storage* src, struct sockaddr_storage* dst);

struct s_target* hash_based_output(uint64_t key, struct s_thread_data* td);

struct s_hashable* ht_get(struct s_hashable **ht, uint64_t key);

struct s_hashable* ht_get_add(struct s_hashable **ht, uint64_t key,
        struct sockaddr_storage* source, struct s_target* target,
        uint64_t itemcnt, uint8_t overwrite, uint8_t sum_itemcnt);

void ht_iterate(struct s_hashable *ht);

void ht_find_max(struct s_hashable *ht,
        struct s_target *target,
        struct s_hashable **ht_e_max);

void ht_find_best(struct s_hashable *ht,
        struct s_target *target,
        uint64_t excess_items,
        struct s_hashable **ht_e_best);

uint32_t ht_target_count(struct s_hashable *ht, struct s_target *target);

void ht_copy(struct s_hashable *ht_from, struct s_hashable **ht_to);

void ht_reset_counters(struct s_hashable *ht);

void ht_delete_all(struct s_hashable *ht);

void *demux(void *arg0);

void *tee(void *arg0);

int setsocksize(int s, int level, int optname, void *optval, socklen_t optlen);

int split_addr(const char* addr, char* ip, uint16_t* port);

int prepare_sending_socket(struct sockaddr *addr, socklen_t len, uint32_t pipe_size);

void init_sending_sockets(struct s_target* targets,
        uint32_t num_targets,
        char *raw_targets[],
        uint32_t pipe_size);

int open_listener_socket(char* laddr, int lport, uint32_t pipe_size);

void load_balance(struct s_thread_data* tds, uint16_t num_threads,
        uint64_t threshold, double reorder_threshold,
        struct s_hashable** master_hashtable);

void sig_handler_toggle_optional_output(int signum);
void sig_handler_shutdown(int signum);
void sig_handler_ignore(int signum);

// variables that are changed when a signal arrives
extern volatile uint8_t optional_output_enabled;
extern volatile uint8_t run_flag;

extern struct s_thread_data tds[MAXTHREADS];
extern uint16_t num_threads;

extern struct s_hashable* master_hashtable_ro;
extern atomic_t master_hashtable_idx;

#endif /* __LIBUTEE_H_ */
