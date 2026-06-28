#ifndef PROTOCOLS_H
#define PROTOCOLS_H

#include <stdint.h>

struct ether_header {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t ether_type;
} __attribute__((packed));

struct ip_header {
    uint8_t vhl;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dest_ip;
} __attribute__((packed));

#endif