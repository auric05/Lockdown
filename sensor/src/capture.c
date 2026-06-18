#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include "protocols.h"

int main(int argc, char *argv[]) {

    if (argc != 2) {
        printf("Usage: ./capture <interface description>\n");
        return 1;
    }

    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

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
    if(found == 0) {
        printf("Interface not found");
        }
        pcap_freealldevs(alldevs);
        return 0;
}