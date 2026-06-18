#ifndef PROTOCOLS_H
#define PROTOCOLS_H

#include <stdint.h>

struct ether_header {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t ether_type;
} __attribute__((packed));

#endif