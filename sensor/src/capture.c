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

    printf("Devices found successfully\n");

    printf("%s\n", pcap_lib_version());
    pcap_freealldevs(alldevs);
    return 0;
}