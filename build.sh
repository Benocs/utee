#!/bin/bash

##################################
# build utee
##################################

SOURCE=utee.c
BINARY=$(echo $SOURCE | cut -d. -f 1)

# The code can still be compiled without any of these directives present
# NOTE: all pre-processor fields are in "" - if they are not, the file won't compile !

GIT_REVISION=\"$(git log --pretty=oneline | head -n 1 | cut -d\  -f 1)\"
COMPILE_TIME=\"$(date +"%d.%m.%Y %H:%M:%S")\"
MD5_SUM=\"$(md5sum ${SOURCE} |cut -d\  -f 1)\"

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
# (debug) build
#
gcc -g -Wall -o ${BINARY} ${SOURCE} -lpthread \
    ${extraflags} ${hash_flags} ${debugflags} ${log_flags} \
    -DGIT_REVISION=$GIT_REVISION \
    -DCOMPILE_TIME="$COMPILE_TIME" \
    -DMD5_SUM=$MD5_SUM || exit 2
