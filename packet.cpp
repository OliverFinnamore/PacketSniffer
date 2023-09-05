#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <cstring>
#include <netinet/in.h> // For byte-order functions

// Ethernet header structure
struct ethernet_header {
    uint8_t  dest_mac[6];
    uint8_t  source_mac[6];
    uint16_t type;
};

// ARP header structure
struct arp_header {
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t  hardware_len;
    uint8_t  protocol_len;
    uint16_t operation;
    uint8_t  sender_mac[6];
    uint32_t sender_ip;
    uint8_t  target_mac[6];
    uint32_t target_ip;
};

// IP header structure
struct ip_header {
    uint8_t  ihl:4, version:4;
    uint8_t  tos;
    uint16_t len;
    uint16_t id;
    uint16_t flag_offset;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t source_ip;
    uint32_t dest_ip;
};

// ICMP header structure
struct icmp_header {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
};

// TCP header structure
struct tcp_header {
    uint16_t source_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  offset:4, reserved:4;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;
};

// UDP header structure
struct udp_header {
    uint16_t source_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
};

// Packet handler callback function
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // Parse Ethernet header
    const ethernet_header *eth = reinterpret_cast<const ethernet_header*>(packet);

    // Check if it is an ARP packet
    if (ntohs(eth->type) == 0x0806) {  // ARP
        const arp_header *arp = reinterpret_cast<const arp_header*>(packet + sizeof(ethernet_header));
        printf("ARP Sender IP: %d.%d.%d.%d\n",
            arp->sender_ip & 0xFF, 
            (arp->sender_ip >> 8) & 0xFF, 
            (arp->sender_ip >> 16) & 0xFF, 
            (arp->sender_ip >> 24) & 0xFF);
        printf("ARP Target IP: %d.%d.%d.%d\n",
            arp->target_ip & 0xFF, 
            (arp->target_ip >> 8) & 0xFF, 
            (arp->target_ip >> 16) & 0xFF, 
            (arp->target_ip >> 24) & 0xFF);
    }
    // Check if it is an IPv4 packet
    else if (ntohs(eth->type) == 0x0800) {  // IPv4
        // Parse IP header and print information
        const ip_header *ip = reinterpret_cast<const ip_header*>(packet + sizeof(ethernet_header));
        printf("Source IP: %d.%d.%d.%d\n", 
            ip->source_ip & 0xFF, 
            (ip->source_ip >> 8) & 0xFF, 
            (ip->source_ip >> 16) & 0xFF, 
            (ip->source_ip >> 24) & 0xFF);
        printf("Destination IP: %d.%d.%d.%d\n", 
            ip->dest_ip & 0xFF, 
            (ip->dest_ip >> 8) & 0xFF, 
            (ip->dest_ip >> 16) & 0xFF, 
            (ip->dest_ip >> 24) & 0xFF);

        // Check if it is a TCP packet
        if (ip->protocol == 6) {  // TCP
            // Parse TCP header and print information
            const tcp_header *tcp = reinterpret_cast<const tcp_header*>(packet + sizeof(ethernet_header) + ip->ihl*4);
            printf("TCP Source Port: %d\n", ntohs(tcp->source_port));
            printf("TCP Destination Port: %d\n", ntohs(tcp->dest_port));
        }
         // Check if it is a UDP packet
        else if (ip->protocol == 17) {  // UDP
            // Parse UDP header and print information
            const udp_header *udp = reinterpret_cast<const udp_header*>(packet + sizeof(ethernet_header) + ip->ihl*4);
            printf("UDP Source Port: %d\n", ntohs(udp->source_port));
            printf("UDP Destination Port: %d\n", ntohs(udp->dest_port));
        }
        // Check if it is an ICMP packet
        else if (ip->protocol == 1) {  // ICMP
            // Parse ICMP header and print information
            const icmp_header *icmp = reinterpret_cast<const icmp_header*>(packet + sizeof(ethernet_header) + ip->ihl*4);
            printf("ICMP Type: %d\n", icmp->type);
            printf("ICMP Code: %d\n", icmp->code);
        }
    }

    printf("===========================================\n");
}

int main(int argc, char *argv[]) {
    // Check for minimum arguments
    if (argc < 2) {
        printf("Usage: %s <interface> [-tcp] [-udp] [-icmp] [-arp]\n", argv[0]);
        return 1;
    }

    // Initialize filter expression
    char filter_exp[100] = "";  // The filter expression
    bool hasFilter = false;

    // Parse command line arguments for filters
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-tcp") == 0) {
            if (hasFilter) strncat(filter_exp, " or ", sizeof(filter_exp) - strlen(filter_exp) - 1);
            strncat(filter_exp, "tcp", sizeof(filter_exp) - strlen(filter_exp) - 1);
            hasFilter = true;
        }
        else if (strcmp(argv[i], "-udp") == 0) {
            if (hasFilter) strncat(filter_exp, " or ", sizeof(filter_exp) - strlen(filter_exp) - 1);
            strncat(filter_exp, "udp", sizeof(filter_exp) - strlen(filter_exp) - 1);
            hasFilter = true;
        }
        else if (strcmp(argv[i], "-icmp") == 0) {
            if (hasFilter) strncat(filter_exp, " or ", sizeof(filter_exp) - strlen(filter_exp) - 1);
            strncat(filter_exp, "icmp", sizeof(filter_exp) - strlen(filter_exp) - 1);
            hasFilter = true;
        }
        else if (strcmp(argv[i], "-arp") == 0) {
            if (hasFilter) strncat(filter_exp, " or ", sizeof(filter_exp) - strlen(filter_exp) - 1);
            strncat(filter_exp, "arp", sizeof(filter_exp) - strlen(filter_exp) - 1);
            hasFilter = true;
        }
    }

    // Open capture handle
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
     // Check for errors
    if (handle == nullptr) {
        printf("Could not open device %s: %s\n", argv[1], errbuf);
        return 2;
    }

    // Set capture filter if provided
    if (hasFilter) {
        struct bpf_program fp;  // The compiled filter expression

        if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            printf("Could not parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return 2;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            printf("Could not install filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return 2;
        }
    }

    pcap_loop(handle, 0, packet_handler, nullptr);
    pcap_close(handle);

    return 0;
}