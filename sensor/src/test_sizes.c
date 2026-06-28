#include <stdio.h>
#include "protocols.h"

int main(void) {
    printf("ether_header: %zu bytes\n", sizeof(struct ether_header));
    printf("ip_header: %zu bytes\n", sizeof(struct ip_header));
    return 0;
}