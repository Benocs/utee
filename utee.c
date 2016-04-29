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

/*
 * TODO:
 * * implement full IPv6 support
 */

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

    struct s_hashable* master_hashtable = NULL;

    // default: load balance every 50e6 lines, min difference between targets: 10%
    uint64_t threshold = 50e6;
    double reorder_threshold = 0.1;

    // 64 MB SND/RCV buffers
    uint32_t pipe_size = 67108864;

    uint32_t num_targets;

    int c;

    atomic_set(&master_hashtable_idx, 0);
    smp_mb__after_atomic();

    opterr = 0;
    while ((c = getopt (argc, argv, "l:m:n:i:t:LH")) != -1)
    switch (c) {
        case 'l':
            split_addr(optarg, listenaddr, &listenport);
#ifdef LOG_INFO
            fprintf(stderr, "%lu - listen address: %s:%u\n",
                    time(NULL), listenaddr, listenport);
#endif
        break;
        case 'H':
            hash_based_dist_enabled = 1;
#ifdef LOG_INFO
            fprintf(stderr, "%lu - use hash-based while distributing\n",
                    time(NULL));
#endif
        break;
        case 'L':
            loadbalanced_dist_enabled = 1;
#ifdef LOG_INFO
            fprintf(stderr, "%lu - use load-balancing while distributing\n",
                    time(NULL));
#endif
        break;
        case 'n':
            num_threads = atoi(optarg);
#ifdef LOG_INFO
            fprintf(stderr, "%lu - number of threads: %u\n",
                    time(NULL), num_threads);
#endif
        break;
        case 'm':
            switch (*optarg) {
                case 'r':
                    mode = 'r';
#ifdef LOG_INFO
                    fprintf(stderr, "%lu - mode: round-robin distribution\n",
                            time(NULL));
#endif
                break;
                case 'd':
                    mode = 'd';
#ifdef LOG_INFO
                    fprintf(stderr, "%lu - mode: duplicate\n",
                            time(NULL));
#endif
                break;
                default:
                    mode = 255;
#ifdef LOG_INFO
                    fprintf(stderr, "%lu - invalid mode 0x%x\n",
                            time(NULL), mode);
#endif
                    usage(argc, argv);
                break;
            }
        break;
        case 'i':
            threshold = strtoul(optarg, NULL, 10);
#ifdef LOG_INFO
            fprintf(stderr, "%lu - load balance every: %lu bytes\n",
                    time(NULL), threshold);
#endif
        break;
        case 't':
            reorder_threshold = atof(optarg);
#ifdef LOG_INFO
            fprintf(stderr, "%lu - load balance inter-target threshold: %.2f\n",
                    time(NULL), reorder_threshold);
#endif
        break;
        default:
            usage(argc, argv);
    }
    num_targets = argc - optind;
    if (mode == 0xFF || num_threads == 0 || listenport == 0 ||
            (num_threads > MAXTHREADS) || (num_targets == 0))
        usage(argc, argv);

    signal(SIGUSR1, sig_handler_toggle_optional_output);
    signal(SIGTERM, sig_handler_shutdown);
    signal(SIGHUP, sig_handler_shutdown);
    signal(SIGINT, sig_handler_shutdown);
    signal(SIGUSR2, sig_handler_ignore);

#ifdef LOG_INFO
    fprintf(stderr, "%lu - setting up listener socket...\n",
            time(NULL));
#endif
    lsock = open_listener_socket(listenaddr, listenport, pipe_size);


    bzero(tds, sizeof(tds));
    // this one loops over all threads
    for (cnt = 0; cnt < num_threads; cnt++) {
        tds[cnt].thread_id = cnt;
        tds[cnt].sockfd = lsock;
        tds[cnt].targets = targets;
        tds[cnt].num_targets = num_targets;
        tds[cnt].hashtable = NULL;
        atomic_set(&(tds[cnt].last_used_master_hashtable_idx), 0);

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
    smp_mb__after_atomic();

    // set all targets
    init_sending_sockets(targets, argc - optind, &(argv[optind]), pipe_size);

    // this one loops over all threads and starts them
    for (cnt = 0; cnt < num_threads; cnt++) {
        switch (mode) {
            case 'r':
                pthread_create(&thread[cnt], NULL, &demux, (void *) &tds[cnt]);
            break;
            case 'd':
                pthread_create(&thread[cnt], NULL, &tee, (void *) &tds[cnt]);
            break;
        }
    }

#ifdef LOG_INFO
    fprintf(stderr, "%lu - starting utee...\n", time(NULL));
#endif

    // main thread to catch/handle signals, trigger load-balancing, if enabled
    while (run_flag) {

        if (loadbalanced_dist_enabled) {
            load_balance(tds, num_threads, threshold, reorder_threshold,
                    &master_hashtable);
        }

        sleep(1);
    }
#ifdef LOG_INFO
    fprintf(stderr, "%lu - [main] shutting down\n", time(NULL));
#endif

    for (cnt = 0; cnt < num_threads; cnt++) {
        pthread_join(thread[cnt], &res);
        if (res)
            free(res);
    }

    ht_delete_all(master_hashtable);
    ht_delete_all(master_hashtable_ro);
    return 0;
}
