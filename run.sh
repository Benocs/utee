#!/bin/bash

##################################
# run utee
##################################

#
# start utee using strace
#
#strace_="strace -- "
strace_=

#
# start utee using valgrind
#
#valgrind_="valgrind --track-origins=yes --leak-check=full --show-leak-kinds=all -v"
#valgrind_="valgrind --track-origins=yes --leak-check=full --show-leak-kinds=all"
valgrind_=

#
# generate core dump on crash
#
ulimit_="ulimit -c unlimited"

listen_address="0.0.0.0"
listen_port=2056

#mode="d"
#mode_extra=""
mode="r"
#mode_extra="-L"
#mode_extra="-H"
#mode_extra=""

lb_every="1000000"
threshold="0.1"

number_of_threads=15

targets="10.0.1.2:2100 \
10.0.1.2:2101 \
10.0.1.2:2102 \
10.0.1.2:2103 \
10.0.1.2:2104 \
10.0.1.2:2105 \
10.0.1.2:2106 \
10.0.1.2:2107 \
10.0.1.2:2108 \
10.0.1.2:2109 \
10.0.1.2:2110 \
10.0.1.2:2111 \
10.0.1.2:2112 \
10.0.1.2:2113 \
10.0.1.2:2114"

# echo 268435456 > /proc/sys/net/core/rmem_max
${ulimit_}
${strace_} ${valgrind_} ./utee -l ${listen_address}:${listen_port} \
    -m ${mode} ${mode_extra} -n ${number_of_threads} \
    -i ${lb_every} -t ${threshold} \
    ${targets}
