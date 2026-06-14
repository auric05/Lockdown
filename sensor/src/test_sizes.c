#include <stdio.h>
#include "protocols.h"

int main(void) {
    printf("ether_header: %zu bytes\n", sizeof(struct ether_header));
    return 0;
}