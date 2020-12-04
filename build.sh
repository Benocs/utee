#!/bin/bash

##################################
# build utee
##################################

SOURCE="utee.c libutee.c"
BINARY=$(echo $SOURCE | cut -d. -f 1)

[ -e "${BINARY}" ] && rm -f "${BINARY}"

# The code can still be compiled without any of these directives present
# NOTE: all pre-processor fields are in "" - if they are not, the file won't compile !

GIT_REVISION=\"$(git log --pretty=oneline | head -n 1 | cut -d\  -f 1)\"
COMPILE_TIME=\"$(date +"%d.%m.%Y %H:%M:%S")\"
MD5_SUM=\"$(mkdir tmp_md5 && cp ${SOURCE} tmp_md5 && \
    tar cf tmp_md5.tar tmp_md5 && \
    md5sum tmp_md5.tar | cut -d\  -f 1; \
    rm -rf tmp_md5 tmp_md5.tar)\"

#
# enable info-level logging
#
log_flags="-DLOG_INFO -DLOG_WARN -DLOG_ERROR"

#
# configure hash functions for address hashing and for hashmap key hashing
#
hash_flags="-DHASH_ADDR=HASH_MOD -DHASH_FUNCTION=HASH_JEN"

#
# optional feature switches
#
extraflags=

#
# debug flags
#
debugflags=
#debugflags="-DDEBUG"
#debugflags="-DDEBUG -DDEBUG_VERBOSE"
#debugflags="-DDEBUG -DDEBUG_VERBOSE -DHASH_DEBUG"
#debugflags="-DDEBUG -DDEBUG_VERBOSE -DHASH_DEBUG -DDEBUG_SOCKETS"
#debugflags="-DDEBUG -DDEBUG_VERBOSE -DHASH_DEBUG -DDEBUG_SOCKETS -DLOAD_BALANCE_DEBUG"
#debugflags="-DDEBUG -DDEBUG_VERBOSE -DHASH_DEBUG -DLOAD_BALANCE_DEBUG"

#
# (debug) build
#
gcc -O2 -Wall -o ${BINARY} ${SOURCE} -lpthread \
    ${extraflags} ${hash_flags} ${debugflags} ${log_flags} \
    -DGIT_REVISION=$GIT_REVISION \
    -DCOMPILE_TIME="$COMPILE_TIME" \
    -DMD5_SUM=$MD5_SUM || exit 2
