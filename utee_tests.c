#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include "libutee.h"

int main(int argc, char *argv[]) {
    uint64_t ref_key = 0x0101a8c000000708;
    uint64_t calced_key = 0;
    struct sockaddr_in ref_addr;
    struct sockaddr_in calced_addr;

    bzero(&ref_addr, sizeof(ref_addr));
    ref_addr.sin_family = AF_INET;
    ref_addr.sin_addr.s_addr = inet_addr("192.168.1.1");
    ref_addr.sin_port = htons(2055);
    printf("ref_addr: %u ref_port: %u\n", ref_addr.sin_addr.s_addr, ref_addr.sin_port);

    printf("reference key: %lu\n", ref_key);
    calced_key = create_key_from_addr((struct sockaddr_storage*)&ref_addr);
    printf("generated key: %lu\n", calced_key);
    get_addr_from_key(calced_key, (struct sockaddr_storage*)&calced_addr, AF_INET);
    printf("reconverted addr: %u, port: %u\n",
            calced_addr.sin_addr.s_addr,
            calced_addr.sin_port);
}
