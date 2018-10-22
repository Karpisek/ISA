#include <climits>//
// Created by Miroslav Karpíšek on 06/10/2018.
//

#include "sniffer.h"
#include "input.h"

// TODO: timeout just callbacks to print !!! viz forum

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
    std::cout << std::endl << std::endl;
    DEBUG_DATAGRAM_PRINT("Ethernet");
    DEBUG_PRINT("SRC", ether_ntoa((const struct ether_addr *) ethernet->mac_dest));
    DEBUG_PRINT("SRC", ether_ntoa((const struct ether_addr *) ethernet->mac_host));


    if(ntohs (ethernet->type) ==  ETHER_TYPE_IP4) {
        process_ip4_header(packet + ETHERNET_HEADER_LEN);
    }
    else if(ntohs (ethernet->type) == ETHER_TYPE_IP6) {
        process_ip6_header(packet + ETHERNET_HEADER_LEN);
    }
}

int process_ip4_header(const b8 *packet) {
    const struct ip4_protocol *ip;              /* Ip header       */

    /* typecast ip header */
    ip = (struct ip4_protocol*) packet;


    if(IP_HEAD_LEN(ip) < 20) {
        raise(3, "wrong IP header cannot be smaller then 20 bytes");
    }

    /* ## DEBUG print IP dest address */
    DEBUG_DATAGRAM_PRINT("IP");
    char buf[INET_ADDRSTRLEN];
    if(inet_ntop(AF_INET, &ip->dst, buf, INET_ADDRSTRLEN) != nullptr) {
        DEBUG_PRINT("SRC", buf);
    } else {
        raise(12);
    }

    // print IP src address
    if(inet_ntop(AF_INET, &ip->src, buf, INET_ADDRSTRLEN) != nullptr) {
        DEBUG_PRINT("DEST", buf);
    } else {
        raise(12);
    }

    DEBUG_PRINT("size", IP_HEAD_LEN(ip));
    DEBUG_PRINT("version", IP_VERSION(ip));

    switch(ip->prt) {
        case PRT_UDP:
            process_upd_header(packet + IP_HEAD_LEN(ip));
            break;

        case PRT_TCP:
            process_tcp_header(packet);
            break;

        default:
            raise(123, "Error, not UDP nor TCP");
    }

    return 0;
}

// TODO: ip6 header
int process_ip6_header(const b8 *packet) {
    raise(42, "IPv6 datagram not implemented");
    return 0;
}

int process_upd_header(const b8 *packet) {
    const struct udp_protocol *udp;     /* UDP header */

    udp = (const struct udp_protocol *) packet;

    DEBUG_DATAGRAM_PRINT("UDP");
    DEBUG_PRINT("SRC", ntohs(udp->src));
    DEBUG_PRINT("DEST", ntohs(udp->dst));
    DEBUG_PRINT("LEN", ntohs(udp->len));

    process_dns_header(packet + UDP_HEAD_LEN);
}

// TODO: tcp_header
int process_tcp_header(const b8 *packet) {
    DEBUG_DATAGRAM_PRINT("TCP");

    raise(42, "tcp datagram not implemented");
    return 0;
}

int process_dns_header(const b8 *packet) {
    const dns_header *dns;   /* DNS header */

    dns = (const dns_header *) packet;

    DEBUG_DATAGRAM_PRINT("DNS");
    DEBUG_PRINT("ID", ntohs(dns->identification));

    DEBUG_PRINT("Q_NUM", ntohs(dns->questions_number));
    int n_ques = ntohs(dns->questions_number);

    DEBUG_PRINT("ANSW_NUM", ntohs(dns->answers_number));
    int n_answ = ntohs(dns->answers_number);

    DEBUG_PRINT("AUTH_NUM", ntohs(dns->authorities_number));
    int n_auth = ntohs(dns->authorities_number);

    DEBUG_PRINT("ADD_NUM", ntohs(dns->additions_number));
    int n_adds = ntohs(dns->additions_number);


    packet += DNS_HEAD_LEN;

    /* loop over questions */

    DEBUG_DATAGRAM_PRINT("Questions");
    for(int i = 0; i < n_ques; i++) {

        rr_question record = get_labeled_name(packet);
    }

    /* loop over answers */

    DEBUG_DATAGRAM_PRINT("Answers");
    for(int i = 0; i < n_answ; i++) {

    }

    /* loop over authorities */

    DEBUG_DATAGRAM_PRINT("Authorities");
    for(int i = 0; i < n_auth; i++) {

    }

    /* loop over additions */

    DEBUG_DATAGRAM_PRINT("Additions");
    for(int i = 0; i < n_adds; i++) {

    }

    return 0;
}

rr_question get_labeled_name(const b8 *packet) {

    rr_question *new_question;
    new_question = (rr_question *) malloc(sizeof(rr_question));


    int next_label_size = *packet;
    packet += sizeof(b8);

    new_question->qname = (b8 *) malloc(next_label_size * sizeof(b8));



    std::cout << next_label_size << std::endl;
    std::cout << std::hex << *packet << std::endl;
}

