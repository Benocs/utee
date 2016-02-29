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
# generate core dump on crash
#
ulimit_="ulimit -c unlimited"

listen_address="0.0.0.0"
listen_port=2055

mode="r"
mode_extra=
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

${ulimit_}
${strace_} ./utee -l ${listen_address}:${listen_port} \
    -m ${mode} ${mode_extra} -n ${number_of_threads} ${targets}
