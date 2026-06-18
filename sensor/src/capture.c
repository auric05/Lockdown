#include <stdio.h>
#include <pcap.h>
#include "protocols.h"

int main(void) {

    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    pcap_if_t *device = alldevs;
    while(device != NULL) {
        printf("Device Name: %s, Device Description: %s\n", device->name, device->description);
        device = device->next;
    }

    pcap_freealldevs(alldevs);

    return 0;
}