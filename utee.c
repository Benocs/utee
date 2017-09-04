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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 *
 * support for:
 *  * round-robin load-balance
 *  ** hash-based load-balance
 *  * duplicate/relay
 *  * packet deduplication in addition to either load-balance or duplicate
 *
 * based on:
 *  * http://pastebin.com/CG8zscaA (Spoofed UDP Flooder v2.5.3 FINAL by
 *    ohnoes1479)
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
#include <strings.h>
#include <pthread.h>

#include "utee.h"
#include "debug.h"
#include "libutee.h"

/*
 * TODO:
 * * implement full IPv6 support
 */

void usage(int argc, char *argv[]) {
    fprintf(stderr,
            "usage: %s\n"
            "\t-l <listenaddr:port>\n"
            "\t-m <d|t>\n"
            "\t\td: distribute traffic over targets\n"
            "\t\tt: tee (duplicate) incoming traffic and send it to "
                "all targets\n"
            "\t-n <num_threads>\n"
            "\t<targetaddr:port> [targetaddr:port [...]]\n"
            "\n\tNote: num_threads must be >= number of target "
            "addresses\n"
            "\n\toptional feature switches for all modes\n"
            "\t[-D]\tdeduplicate packets\n"
            "\t[-a]\tanalyze mode (dry run): no packets will be send\n"
            "\n\toptional feature switches for mode 'distribute'\n"
            "\t[-H]\thash-based target selection\n"
            "\t[-L]\thash-based load balancing of targets\n"
            "\n\toptional load balance configuration\n"
            "\t[-i <load balance interval>]\n"
            "\t[-t <load balance inter-target threshold>]\n"
            "\t[-b]\tuse byte count instead of packets to measure load\n"
            "\n\toptional deduplication configuration\n"
            "\t[-f <deduplication inner hash table load factor>]\n"
            "\t[-I <deduplication maintenance interval>]\n"
            "\t[-p <deduplication packet source index>]\n"
            "\t[-P <deduplication packet id index>]\n"
            "\t[-r <deduplication frequency update interval>]\n"
            "\t[-R <deduplication inner hash table resize factor>]\n"
            "\t[-T <deduplication timeout>]\n"
            "\n\t"
            "\n\toptional logging configuration\n"
            "\t[-d <log level>]\n"
            "\t\thigher values result in more verbose logging\n"
            "\t\tdefined log levels:\n"
            "\t\tCRITICAL 10\n"
            "\t\tERROR    20\n"
            "\t\tWARNING  30\n"
            "\t\tINFO     40\n"
            "\t\tDEBUG    50\n"
            "\t\tDEBUG1   51\n"
            "\t\tDEBUG2   52\n"
            "\t\tDEBUG3   53\n"
            "\t\tDEBUG4   54\n"
            "\t\tDEBUG5   55\n"
            "\t\tDEBUG6   56\n"
            "\t\tDEBUG7   57\n"
            "\t\tDEBUG8   58\n"
            "\t\tDEBUG9   59\n"
            "\t\tALL     255\n"
            "\n"
            "repository revision: %s\n"
            "compile time:        %s\n"
            "source MD5 sum:      %s\n",
            argv[0], GIT_REVISION, COMPILE_TIME, MD5_SUM);
    exit(1);
}

void default_settings_deduplicate(t_settings_deduplicate* settings) {
    settings->enabled = 0;
    settings->timeout = 10;
    settings->threshold = 1;
    settings->frequency_reset_interval = 5;
    settings->pkt_src_id_idx = 3;
    settings->pkt_id_idx = 2;
    settings->inner_ht_load_factor = 4;
    settings->inner_ht_resize_factor = 4;
}

void default_settings_distribute(t_settings_distribute* settings) {
    settings->bytecnt_based = 0;
    // default: load balance every 50e6 lines
    settings->threshold = 50e6;
    // default: min difference between targets for load-balancing to kick in:
    // 10%
    settings->reorder_threshold = 0.1;
}

void default_settings_duplicate(t_settings_duplicate* settings) {
}

void default_settings(t_settings* settings) {
    // set default log level to INFO
    db_setdebug(LOG_INFO);
    // initialize master_hashtable_idx
    atomic_set(&master_hashtable_idx, 0);
    // initialize 'time'
    atomic_set(&now, 0);

    memset(settings, 0, sizeof(t_settings));

    // 64 MB SND/RCV socket buffers
    settings->pipe_size = 67108864;

    default_settings_deduplicate(&(settings->deduplicate));
    default_settings_distribute(&(settings->distribute));
    default_settings_duplicate(&(settings->duplicate));
}

void parse_argv(int argc, char *argv[], t_settings* settings) {
    static char const optstr[] = "abd:Df:Hl:Lm:n:p:P:i:I:r:R:t:T:v";
    int c;

    opterr = 0;
    while ((c = getopt (argc, argv, optstr)) != -1)
        switch (c) {
            case 'a':
                DB_TRACE(LOG_ALL, "packet analyze mode. "
                        "no packets will be send");
                settings->analyze_mode = 1;
                break;
            case 'd':
                db_setdebug(strtoul(optarg, NULL, 10));
                DB_TRACE(LOG_INFO,
                        "debug level: %u", db_getdebug());
                break;
            case 'f':
                settings->deduplicate.inner_ht_load_factor = strtoul(
                        optarg, NULL, 10);
                DB_TRACE(LOG_INFO,
                        "deduplicate inner hash table load factor: %u",
                        settings->deduplicate.inner_ht_load_factor);
            break;
            case 'l':
                split_addr(optarg, settings->listenaddr,
                        &(settings->listenport));
                DB_TRACE(LOG_INFO, "listen address: %s:%u",
                        settings->listenaddr, settings->listenport);
            break;
            case 'H':
                settings->distribute.hash_based_dist_enabled = 1;
                DB_TRACE(LOG_INFO, "use hash-based while distributing");
            break;
            case 'L':
                settings->distribute.loadbalanced_dist_enabled = 1;
                DB_TRACE(LOG_INFO, "use load-balancing while distributing");
            break;
            case 'D':
                settings->deduplicate.enabled = 1;
                DB_TRACE(LOG_INFO, "deduplicate incoming stream");
            break;
            case 'I':
                settings->deduplicate.threshold = strtoul(optarg, NULL, 10);
                DB_TRACE(LOG_INFO, "deduplicate maintenance every %u seconds",
                        settings->deduplicate.threshold);
            break;
            case 'r':
                settings->deduplicate.frequency_reset_interval = strtoul(
                        optarg, NULL, 10);
                DB_TRACE(LOG_INFO,
                        "deduplicate update frequency interval %u seconds",
                        settings->deduplicate.frequency_reset_interval);
            break;
            case 'T':
                settings->deduplicate.timeout = strtoul(optarg, NULL, 10);
                DB_TRACE(LOG_INFO, "deduplicate timeout: %u seconds",
                        settings->deduplicate.timeout);
            break;
            case 'p':
                settings->deduplicate.pkt_src_id_idx = strtoul(
                        optarg, NULL, 10);
                DB_TRACE(LOG_INFO, "deduplicate packet source id index: %u",
                        settings->deduplicate.pkt_src_id_idx);
            break;
            case 'P':
                settings->deduplicate.pkt_id_idx = strtoul(optarg, NULL, 10);
                DB_TRACE(LOG_INFO, "deduplicate packet id index: %u",
                        settings->deduplicate.pkt_id_idx);
            break;
            case 'R':
                settings->deduplicate.inner_ht_resize_factor = strtoul(
                        optarg, NULL, 10);
                DB_TRACE(LOG_INFO,
                        "deduplicate inner hash table resize factor: %u",
                        settings->deduplicate.inner_ht_resize_factor);
            break;
            case 'b':
                settings->distribute.bytecnt_based = 1;
            break;
            case 'n':
                settings->num_threads = atoi(optarg);
                num_threads = settings->num_threads;
                DB_TRACE(LOG_INFO, "number of threads: %u",
                        settings->num_threads);
            break;
            case 'm':
                settings->mode = *optarg;
                switch (settings->mode) {
                    case UTEE_MODE_DISTRIBUTE:
                        DB_TRACE(LOG_INFO, "mode: distribution");
                    break;
                    case UTEE_MODE_DUPLICATE:
                        DB_TRACE(LOG_INFO, "mode: tee (duplicate)");
                    break;
                    default:
                        DB_TRACE(LOG_INFO, "invalid mode 0x%X",
                                settings->mode);
                        settings->mode = UTEE_MODE_INVALID;
                        usage(argc, argv);
                    break;
                }
            break;
            case 'i':
                settings->distribute.threshold = strtoul(optarg, NULL, 10);
                DB_TRACE(LOG_INFO, "load balance every: %lu packets",
                        settings->distribute.threshold);
            break;
            case 't':
                settings->distribute.reorder_threshold = atof(optarg);
                DB_TRACE(LOG_INFO, "load balance inter-target threshold: %.2f",
                        settings->distribute.reorder_threshold);
            break;
            default:
                DB_TRACE(LOG_CRITICAL,
                        "unknown option: %c", c);
                usage(argc, argv);
        }

    settings->num_targets = argc - optind;
    if (settings->mode == UTEE_MODE_INVALID ||
            settings->num_threads == 0 ||
            settings->listenport == 0 ||
            settings->num_threads > MAXTHREADS ||
            settings->num_targets == 0)
        usage(argc, argv);

    DB_CALL(LOG_INFO,
            if (settings->distribute.bytecnt_based) {
                DB_TRACE(LOG_INFO,
                        "use load-balancing based on byte counters");
            }
            else {
                DB_TRACE(LOG_INFO,
                        "use load-balancing based on packet counters");
            }
        );

    DB_TRACE(LOG_ALL, "using debug level: %d", db_getdebug());
}

void setup_signals(void) {
    signal(SIGUSR1, sig_handler_toggle_optional_output);
    signal(SIGTERM, sig_handler_shutdown);
    signal(SIGHUP, sig_handler_shutdown);
    signal(SIGINT, sig_handler_shutdown);
    signal(SIGUSR2, sig_handler_ignore);
}

int setup_sockets(t_settings* settings) {
    DB_TRACE(LOG_INFO, "setting up listener socket...");
    // listening socket. shared by all threads
    return open_listener_socket(settings->listenaddr, settings->listenport,
            settings->pipe_size);
}

void setup_thread_data(t_settings* settings, int listen_socket,
        struct s_deduplication_hashable** deduplication_hashtable) {
    uint32_t thread_idx;

    bzero(tds, sizeof(tds));
    // this one loops over all threads
    for (thread_idx = 0; thread_idx < settings->num_threads; thread_idx++) {
        tds[thread_idx].thread_id = thread_idx;
        tds[thread_idx].sockfd = listen_socket;
        tds[thread_idx].targets = settings->targets;
        tds[thread_idx].num_targets = settings->num_targets;
        tds[thread_idx].hashtable = NULL;
        tds[thread_idx].hashtable_ro = NULL;
        tds[thread_idx].hashtable_ro_old = NULL;
        atomic_set(&(tds[thread_idx].last_used_master_hashtable_idx), 0);

        tds[thread_idx].deduplication_hashtable = deduplication_hashtable;

        switch (settings->mode) {
            case UTEE_MODE_DISTRIBUTE:
                tds[thread_idx].features.distribute = 1;
                tds[thread_idx].features.load_balanced_dist = \
                        settings->distribute.loadbalanced_dist_enabled;
                tds[thread_idx].features.hash_based_dist = \
                        settings->distribute.hash_based_dist_enabled;
                tds[thread_idx].features.lb_bytecnt_based = \
                        settings->distribute.bytecnt_based;
            break;
            case UTEE_MODE_DUPLICATE:
                tds[thread_idx].features.duplicate = 1;
                optional_output_enabled = 1;
            break;
        }
        tds[thread_idx].features.deduplicate = settings->deduplicate.enabled;
        tds[thread_idx].feature_settings.deduplication_timeout = \
                settings->deduplicate.timeout;

        tds[thread_idx].deduplication_pkt_src_id_idx = \
                settings->deduplicate.pkt_src_id_idx;
        tds[thread_idx].deduplication_pkt_id_idx = \
                settings->deduplicate.pkt_id_idx;

        tds[thread_idx].features.analyze = settings->analyze_mode;
    }
}

void threads_create(t_settings* settings, pthread_rwlock_t* deduplication_lock,
        pthread_t* threads) {
    uint32_t thread_idx;

    if (settings->deduplicate.enabled) {
        if (pthread_rwlock_init(deduplication_lock, NULL) != 0) {
            DB_TRACE(LOG_CRITICAL, "lock init failed");
            exit(-1);
        }
    }

    // this one loops over all threads and starts them
    for (thread_idx = 0; thread_idx < settings->num_threads; thread_idx++) {
        pthread_create(&threads[thread_idx], NULL, &tee,
                (void *) &tds[thread_idx]);
    }
}

void utee_shutdown(
        t_settings* settings,
        pthread_t* threads,
        struct s_hashable** master_hashtable,
        struct s_deduplication_hashable** deduplication_hashtable) {
    uint32_t thread_idx;
    void*    thread_result;

    for (thread_idx = 0; thread_idx < settings->num_threads; thread_idx++) {
        pthread_join(threads[thread_idx], &thread_result);
        if (thread_result)
            free(thread_result);
    }

    ht_delete_all(master_hashtable);
    dedup_ht_delete_all(deduplication_hashtable);
}

int main(int argc, char *argv[]) {
    t_settings settings;
    pthread_t  threads[MAXTHREADS];
    struct s_hashable* master_hashtable = NULL;
    struct s_deduplication_hashable* deduplication_hashtable = NULL;

    default_settings(&settings);
    parse_argv(argc, argv, &settings);
    setup_signals();
    setup_thread_data(&settings, setup_sockets(&settings),
            &deduplication_hashtable);
    smp_mb__after_atomic();

    // set all targets
    init_sending_sockets(settings.targets, argc - optind, &(argv[optind]),
            settings.pipe_size);

    // create and start worker threads
    threads_create(&settings, &deduplication_lock, threads);

    DB_TRACE(LOG_INFO, "starting utee...");
    // main thread to catch/handle signals, trigger load-balancing, if enabled
    while (run_flag) {

        if (settings.distribute.loadbalanced_dist_enabled) {
            load_balance(
                    tds,
                    settings.num_threads,
                    settings.distribute.threshold,
                    settings.distribute.reorder_threshold,
                    &master_hashtable);
        }

        if (settings.deduplicate.enabled) {
            deduplicate_maintenance(
                    tds,
                    settings.num_threads,
                    settings.deduplicate.threshold,
                    settings.deduplicate.frequency_reset_interval,
                    settings.deduplicate.inner_ht_load_factor,
                    settings.deduplicate.inner_ht_resize_factor,
                    &deduplication_lock);
        }

        sleep(1);
    }

    DB_TRACE(LOG_INFO, "shutting down");
    utee_shutdown(&settings, threads, &master_hashtable,
            &deduplication_hashtable);
    return 0;
}
