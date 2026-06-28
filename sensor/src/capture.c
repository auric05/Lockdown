#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <winsock2.h>
#include "protocols.h"

//argc = argument count, argv = argument strings. argv[0] = program name, argv[1] = interface description
int main(int argc, char *argv[]) {

    //if argc is not equal to 2 then we print the usage statemnet
    if (argc != 2) {
        printf("Usage: ./capture <interface description>\n");
        return 1;
    }

    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    //prints an error if it cannot find devices on the PC
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    //finding the devices on the PC and printing if they have been found, compare description to description letter by letter
    pcap_if_t *device = alldevs;
    int found = 0;
    while(device != NULL) {
        if(device->description != NULL && strcmp(device->description, argv[1]) == 0) {
            printf("Found interface: %s\n", device->name);
            found = 1;
            break;
        }
        device = device->next;
    }
    if(found == 1) {
        //open a live capture handle on the selected interface, 65536 is the buffer size, 0 = no promiscuous mode, 1000 is delivering packets
        //every 1000ms even if the buffer isn't full.
        pcap_t *handle = pcap_open_live(device->name, 65536, 0, 1000, errbuf);
        //any null check or incorrectness means pcap_freealldevs has to be called to release from memory
        if (handle == NULL) {
            fprintf(stderr, "Failed to open capture handle: %s\n", errbuf);
            pcap_freealldevs(alldevs);
            return 1;
        }
        //checking to make sure the interface is ethernet via DLT_EN10MB, DLT_EN10MB = 1 means Ethernet, required for our ether_header struct
        //to parse correctly
        if(pcap_datalink(handle) != DLT_EN10MB) {
            fprintf(stderr, "Interface is not Ethernet (link type: %d)\n", pcap_datalink(handle));
            pcap_close(handle);
            pcap_freealldevs(alldevs);
            return 1;
        }
        printf("Capture handle opened on: %s\n", argv[1]);
        struct pcap_pkthdr *header;
        const u_char *packet;
        int result;

        printf("Listening for packets...\n");

        while((result = pcap_next_ex(handle, &header, &packet)) >= 0) {
            if(result == 0) {
                continue;
            }
            printf("Packet captured | length: %d bytes\n", header->len);
            //cast raw packet bytes to ether_header struct, tells the compiler to interpret these bytes as an Ethernet frame
            struct ether_header *eth = (struct ether_header *)packet; 
            uint16_t type = ntohs(eth->ether_type);
            //printing via checking packet types IPv4, ARP, Unknown
            if(type == 0x0800) {
                struct ip_header *ip = (struct ip_header *)(packet + sizeof(struct ether_header));
                struct in_addr src_addr;
                struct in_addr dest_addr;
                src_addr.s_addr = ip->src_ip;
                dest_addr.s_addr = ip->dest_ip;
                printf("IPv4 packet\n");
                printf("  src: %s\n", inet_ntoa(src_addr));
                printf("  dst: %s\n", inet_ntoa(dest_addr));
                printf("  protocol: %d\n", ip->protocol);
                printf("  TTL: %d\n", ip->ttl);
            } else if(type == 0x0806) {
                printf("ARP packet\n");
            } else {
                printf("Unknown packet type: 0x%04x\n", type);
            }
        }
        pcap_close(handle);
    }
    if(found == 0) {
        printf("Interface not found");
    }
    pcap_freealldevs(alldevs);
    return 0;
}