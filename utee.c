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
 *  * packet deduplication in addition to either load-balance or duplicate
 *
 * based on:
 *  * http://pastebin.com/CG8zscaA (Spoofed UDP Flooder v2.5.3 FINAL by ohnoes1479)
 *  * http://beej.us/guide/bgnet/
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <stdint.h>
#include <pthread.h>

#include "debug.h"
#include "libutee.h"

/*
 * TODO:
 * * implement full IPv6 support
 */

#if defined(DEBUG)
#undef uthash_noexpand_fyi
#define uthash_noexpand_fyi(tbl) DB_TRACE(LOG_DEBUG,                          \
        "bucket expansion inhibited")
#undef uthash_expand_fyi
#define uthash_expand_fyi(tbl) DB_TRACE(LOG_DEBUG, "expanding to %d buckets", \
        tbl->num_buckets)
#endif

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
    void *res;

    unsigned char mode = 0xFF;

    uint8_t loadbalanced_dist_enabled = 0;
    uint8_t hash_based_dist_enabled = 0;

    uint8_t deduplication_enabled = 0;
    uint32_t deduplication_timeout = 10;
    uint32_t deduplication_threshold = 1;
    uint32_t deduplication_frequency_reset_interval = 5;
    uint32_t deduplication_pkt_src_id_idx = 3;
    uint32_t deduplication_pkt_id_idx = 2;
    double deduplication_inner_ht_resize_factor = 4;

    // load balance based on paket counts if 0
    // load balance based on byte counts if 1
    uint8_t loadbalance_bytecnt_based = 0;

    struct s_hashable* master_hashtable = NULL;
    struct s_deduplication_hashable* deduplication_hashtable = NULL;

    // default: load balance every 50e6 lines, min difference between targets: 10%
    uint64_t threshold = 50e6;
    double reorder_threshold = 0.1;

    // 64 MB SND/RCV buffers
    uint32_t pipe_size = 67108864;

    uint32_t num_targets;

    int c;

    atomic_set(&master_hashtable_idx, 0);
    smp_mb__after_atomic();

    static char const optstr[] = "bd:DHl:Lm:n:p:P:i:I:r:R:t:T:v";

    db_setdebug(LOG_ALL);

    opterr = 0;
    while ((c = getopt (argc, argv, optstr)) != -1)
    switch (c) {
        case 'd':
            db_setdebug(atoi(optarg));
            break;
        case 'l':
            split_addr(optarg, listenaddr, &listenport);
            DB_TRACE(LOG_INFO, "listen address: %s:%u", listenaddr, listenport);
        break;
        case 'H':
            hash_based_dist_enabled = 1;
            DB_TRACE(LOG_INFO, "use hash-based while distributing");
        break;
        case 'L':
            loadbalanced_dist_enabled = 1;
            DB_TRACE(LOG_INFO, "use load-balancing while distributing");
        break;
        case 'D':
            deduplication_enabled = 1;
            DB_TRACE(LOG_INFO, "deduplicate incoming stream");
        break;
        case 'I':
            deduplication_threshold = strtoul(optarg, NULL, 10);
            DB_TRACE(LOG_INFO, "deduplicate maintenance every %u seconds",
                    deduplication_threshold);
        break;
        case 'r':
            deduplication_frequency_reset_interval = strtoul(optarg, NULL, 10);
            DB_TRACE(LOG_INFO,
                    "deduplicate update frequency interval %u seconds",
                    deduplication_frequency_reset_interval);
        break;
        case 'T':
            deduplication_timeout = strtoul(optarg, NULL, 10);
            DB_TRACE(LOG_INFO, "deduplicate timeout: %u seconds",
                    deduplication_timeout);
        break;
        case 'p':
            deduplication_pkt_src_id_idx = strtoul(optarg, NULL, 10);
            DB_TRACE(LOG_INFO, "deduplicate packet source id index: %u",
                    deduplication_pkt_src_id_idx);
        break;
        case 'P':
            deduplication_pkt_id_idx = strtoul(optarg, NULL, 10);
            DB_TRACE(LOG_INFO, "deduplicate packet id index: %u",
                    deduplication_pkt_id_idx);
        break;
        case 'R':
            deduplication_inner_ht_resize_factor = strtoul(optarg, NULL, 10);
            DB_TRACE(LOG_INFO,
                    "deduplicate inner hash table resize factor: %f",
                    deduplication_inner_ht_resize_factor);
        break;
        case 'b':
            loadbalance_bytecnt_based = 1;
        break;
        case 'n':
            num_threads = atoi(optarg);
            DB_TRACE(LOG_INFO, "number of threads: %u",
                    num_threads);
        break;
        case 'm':
            switch (*optarg) {
                case 'r':
                    mode = 'r';
                    DB_TRACE(LOG_INFO, "mode: round-robin distribution");
                break;
                case 'd':
                    mode = 'd';
                    DB_TRACE(LOG_INFO, "mode: duplicate");
                break;
                default:
                    mode = 255;
                    DB_TRACE(LOG_INFO, "invalid mode 0x%x", mode);
                    usage(argc, argv);
                break;
            }
        break;
        case 'i':
            threshold = strtoul(optarg, NULL, 10);
            DB_TRACE(LOG_INFO, "load balance every: %lu packets", threshold);
        break;
        case 't':
            reorder_threshold = atof(optarg);
            DB_TRACE(LOG_INFO, "load balance inter-target threshold: %.2f",
                    reorder_threshold);
        break;
        default:
            usage(argc, argv);
    }

    DB_CALL(LOG_INFO,
            if (loadbalance_bytecnt_based) {
                DB_TRACE(LOG_INFO,
                        "use load-balancing based on byte counters");
            }
            else {
                DB_TRACE(LOG_INFO,
                        "use load-balancing based on packet counters");
            }
        );

    DB_TRACE(LOG_ALL, "using debug level: %d", db_getdebug());

    num_targets = argc - optind;
    if (mode == 0xFF || num_threads == 0 || listenport == 0 ||
            (num_threads > MAXTHREADS) || (num_targets == 0))
        usage(argc, argv);

    signal(SIGUSR1, sig_handler_toggle_optional_output);
    signal(SIGTERM, sig_handler_shutdown);
    signal(SIGHUP, sig_handler_shutdown);
    signal(SIGINT, sig_handler_shutdown);
    signal(SIGUSR2, sig_handler_ignore);

    DB_TRACE(LOG_INFO, "setting up listener socket...");
    lsock = open_listener_socket(listenaddr, listenport, pipe_size);

    bzero(tds, sizeof(tds));
    // this one loops over all threads
    for (cnt = 0; cnt < num_threads; cnt++) {
        tds[cnt].thread_id = cnt;
        tds[cnt].sockfd = lsock;
        tds[cnt].targets = targets;
        tds[cnt].num_targets = num_targets;
        tds[cnt].hashtable = NULL;
        tds[cnt].hashtable_ro = NULL;
        tds[cnt].hashtable_ro_old = NULL;
        atomic_set(&(tds[cnt].last_used_master_hashtable_idx), 0);

        tds[cnt].deduplication_hashtable = &deduplication_hashtable;

        switch (mode) {
            case 'r':
                tds[cnt].features.distribute = 1;
                tds[cnt].features.load_balanced_dist = loadbalanced_dist_enabled;
                tds[cnt].features.hash_based_dist = hash_based_dist_enabled;
                tds[cnt].features.lb_bytecnt_based = loadbalance_bytecnt_based;
            break;
            case 'd':
                tds[cnt].features.duplicate = 1;
                optional_output_enabled = 1;
            break;
        }
        tds[cnt].features.deduplicate = deduplication_enabled;
        tds[cnt].feature_settings.deduplication_timeout = deduplication_timeout;

        tds[cnt].deduplication_pkt_src_id_idx = deduplication_pkt_src_id_idx;
        tds[cnt].deduplication_pkt_id_idx = deduplication_pkt_id_idx;
    }
    smp_mb__after_atomic();

    // initialize 'time'
    atomic_set(&now, 0);

    // set all targets
    init_sending_sockets(targets, argc - optind, &(argv[optind]), pipe_size);

    if (deduplication_enabled) {
        if (pthread_rwlock_init(&deduplication_lock, NULL) != 0) {
            DB_TRACE(LOG_CRITICAL, "lock init failed");
            exit(-1);
        }
    }

    // this one loops over all threads and starts them
    for (cnt = 0; cnt < num_threads; cnt++) {
        pthread_create(&thread[cnt], NULL, &tee, (void *) &tds[cnt]);
    }

    DB_TRACE(LOG_INFO, "starting utee...");

    // main thread to catch/handle signals, trigger load-balancing, if enabled
    while (run_flag) {

        if (loadbalanced_dist_enabled) {
            load_balance(tds, num_threads, threshold, reorder_threshold,
                    &master_hashtable);
        }

        if (deduplication_enabled) {
            deduplicate_maintenance(
                    tds,
                    num_threads,
                    deduplication_threshold,
                    deduplication_frequency_reset_interval,
                    deduplication_inner_ht_resize_factor,
                    &deduplication_lock);

            // TODO: check whether to delete old values from deduplication_hashtable
        }

        sleep(1);
    }
    DB_TRACE(LOG_INFO, "shutting down");

    for (cnt = 0; cnt < num_threads; cnt++) {
        pthread_join(thread[cnt], &res);
        if (res)
            free(res);
    }

    ht_delete_all(&master_hashtable);
    dedup_ht_delete_all(&deduplication_hashtable);
    return 0;
}
