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

struct udp_header {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
} __attribute__((packed));

struct tcp_header {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t sequence_number;
    uint32_t ack_number;
    uint8_t data_offset;
    uint8_t flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
} __attribute__((packed));

#endif