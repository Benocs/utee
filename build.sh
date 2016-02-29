#!/bin/bash

##################################
# build utee
##################################

#
# enable info-level logging
#
log_flags="-DLOG_INFO"

#
# configure hash functions for address hashing and for hashmap key hashing
#
hash_flags="-DHASH_ADDR=HASH_JEN_32 -DHASH_FUNCTION=HASH_JEN"

#
# optional feature switches
#
extraflags="-DUSE_SELECT -DRCV_ON_RAW"

#
# debug flags
#
#debugflags="-DDEBUG -DDEBUG_ERRORS -DHASH_DEBUG"
debugflags=

#
# start utee using strace
#
#strace_="strace -- "
strace_=

#
# generate core dump on crash
#
ulimit_="ulimit -c unlimited; "

#
# (debug) build
#
gcc -g -Wall -o utee utee.c -lpthread ${extraflags} ${hash_flags} ${debugflags} ${log_flags} || exit 2
