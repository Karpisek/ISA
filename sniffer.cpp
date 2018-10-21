#include <climits>//
// Created by Miroslav Karpíšek on 06/10/2018.
//

#include "sniffer.h"
#include "input.h"

int sniff(char *dev, int duration) {

    pcap_t *session;                        /* Session handle */
    char error_buffer[PCAP_ERRBUF_SIZE];    /* Error string */
    struct bpf_program filter_exp = {};		/* The compiled filter expression */
    b32 netmask;		                    /* The netmask of our sniffing device */
    b32 ip_address;                         /* The IP of our sniffing device */

    const b8 *packet;                       /* Packet that pcap gives us */
    struct pcap_pkthdr header = {};	        /* The header that pcap gives us */


    if (pcap_lookupnet(dev, &ip_address, &netmask, error_buffer) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);

        ip_address = 0;
        netmask = 0;
    }

    /* opens live capture */
    session = pcap_open_live(dev, BUFSIZ, 1, 1000, error_buffer);
    if (session == nullptr) {
        raise(ERR_INTERFACE_OPEN, std::string(error_buffer));
    }

    /* make sure we're capturing on an Ethernet device */
    if (pcap_datalink(session) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);
    }

    /* create sniff-filter */
    if(pcap_compile(session, &filter_exp, FILTER_EXPRESSION, 0, ip_address) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", FILTER_EXPRESSION, pcap_geterr(session));
        return(2);
    }

    /* activate sniff-filter */
    if(pcap_setfilter(session, &filter_exp) == -1){
        fprintf(stderr, "Couldn't install filter %s: %s\n", FILTER_EXPRESSION, pcap_geterr(session));
        return(2);
    }

    struct timeval time = {};
    gettimeofday(&time, nullptr);

    long timeout = time.tv_sec + duration;

    while(std::time(nullptr) < timeout) {
        packet = pcap_next(session, &header);

        if(packet != nullptr) {
            process_ether_header(packet);
        }
    }

    std::cout << std::endl << "Sniffer set up to listen" << std::endl;

    pcap_close(session);

    return 0;
}

int process_ether_header(const unsigned char *packet) {

    const struct ethernet_protocol *ethernet;   /* Ethernet header */

    /* typecast ethernet header */
    ethernet = (struct ethernet_protocol *) packet;

    // ### DEBUG PRINT ###
    std::cout << "-------------------" << std::endl;
    std::cout << "DEST: " << ether_ntoa((const struct ether_addr *) ethernet->mac_dest) << std::endl;
    std::cout << "SRC: " << ether_ntoa((const struct ether_addr *) ethernet->mac_host) << std::endl;
    // ### DEBUG PRINT ###

    // TODO: rozvetveni na ip6 header

    if(ntohs (ethernet->type) == ETHER_TYPE_IP4) {
        process_ip4_header(packet + ETHERNET_HEADER_LEN);
    }
    else if(ntohs (ethernet->type) == ETHER_TYPE_IP6) {
        process_ip6_header(packet + ETHERNET_HEADER_LEN);
    }
}

int process_ip4_header(const b8 *packet) {
    const struct ip4_protocol *ip;              /* Ip header       */

    /* typecast ip header */
    ip = (struct ip4_protocol*)(packet);


    if(IP_HEAD_LEN(ip) < 20) {
        raise(3, "wrong IP header cannot be smaller then 20 bytes");
    }

    /* ## DEBUG print IP dest address */
    char buf[INET_ADDRSTRLEN];
    if(inet_ntop(AF_INET, &ip->dst, buf, INET_ADDRSTRLEN) != nullptr) {
        std::cout << "DEST: " << buf << std::endl;
    } else {
        raise(12);
    }

    // print IP src address
    if(inet_ntop(AF_INET, &ip->src, buf, INET_ADDRSTRLEN) != nullptr) {
        std::cout << "SRC: " << buf << std::endl;
    } else {
        raise(12);
    }

    printf("size of ip: %d, protocol version: %d\n", IP_HEAD_LEN(ip), IP_VERSION(ip));
    // ######

    switch(ip->prt) {
        case PRT_UDP:
            break;

        case PRT_TCP:
            break;

        default:
            raise(123, "Error, not UDP nor TCP");
    }

    return 0;
}

int process_ip6_header(const b8 *packet) {
    raise(42, "IPv6 datagram not implemented");
    return 0;
}
