#ifndef __UTEE_H_
#define __UTEE_H_

/* utee - transparent udp tee proxy
 *
 * Copyright (C) 2016-2017 Benocs
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

/* This file contains definitions that define utee's behavior */

#include "libutee.h"

#include <stdint.h>
#include <netinet/ip.h>
//#include <sys/socket.h>

#if defined(DEBUG)
#undef uthash_noexpand_fyi
#define uthash_noexpand_fyi(tbl) DB_TRACE(LOG_DEBUG,                          \
        "bucket expansion inhibited")
#undef uthash_expand_fyi
#define uthash_expand_fyi(tbl) DB_TRACE(LOG_DEBUG, "expanding to %d buckets", \
        tbl->num_buckets)
#endif

#define UTEE_MODE_DISTRIBUTE    'd'
#define UTEE_MODE_DUPLICATE     't'
#define UTEE_MODE_INVALID       0

typedef struct {
    uint8_t  loadbalanced_dist_enabled;
    uint8_t  hash_based_dist_enabled;

    // load balance based on paket counts if 0
    // load balance based on byte counts if 1
    uint8_t  bytecnt_based;
    // default: load balance every threshold lines
    uint64_t threshold;
    // min difference between targets for load-balancing to kick in
    double   reorder_threshold;
} t_settings_distribute;

typedef struct {
} t_settings_duplicate;

typedef struct {
    uint8_t  enabled;
    uint32_t timeout;
    uint32_t threshold;
    uint32_t frequency_reset_interval;
    uint32_t pkt_src_id_idx;
    uint32_t pkt_id_idx;
    double   inner_ht_resize_factor;
} t_settings_deduplicate;

typedef struct {
    char listenaddr[INET6_ADDRSTRLEN];
    uint16_t listenport;
    t_target targets[MAXTHREADS];
    uint32_t num_targets;
    uint32_t num_threads;
    // SND/RCV socket buffers
    uint32_t pipe_size;

    unsigned char mode;
    t_settings_distribute distribute;
    t_settings_duplicate duplicate;

    t_settings_deduplicate deduplicate;
} t_settings;

#endif
