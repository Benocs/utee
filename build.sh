#!/bin/bash

##################################
# build utee
##################################

SOURCE="utee.c libutee.c debug.c stderr.c kludge.c"
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
# When DEBUG is defined, the debug primitives will be compiled else not.
# To control the active debug level, use the -d<level> command line switch.
#
log_flags="-DDEBUG"

#
# configure hash functions for address hashing and for hashmap key hashing
#
hash_flags="-DHASH_ADDR=HASH_NOP -DHASH_FUNCTION=HASH_JEN -DHASH_PKT_ID=HASH_NOP"

#
# optional feature switches
#
#extraflags="-DRCV_ON_RAW"
extraflags="-DUSE_SELECT_WRITE -DRCV_ON_RAW"
#extraflags="-DUSE_SELECT_READ -DUSE_SELECT_WRITE -DRCV_ON_RAW"

#
# (debug) build
#
gcc -g -Wall -o ${BINARY} ${SOURCE} -lpthread \
    ${extraflags} ${hash_flags} ${debugflags} ${log_flags} \
    -DGIT_REVISION=$GIT_REVISION \
    -DCOMPILE_TIME="$COMPILE_TIME" \
    -DMD5_SUM=$MD5_SUM || exit 2
