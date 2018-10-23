#include <climits>//
// Created by Miroslav Karpíšek on 06/10/2018.
//

#include "sniffer.h"

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
            process_packet(packet);
        }
    }

    std::cout << std::endl << "Sniffer set up to listen" << std::endl;

    pcap_close(session);

    return 0;
}

void process_packet(const b8 *packet) {
    const b8* dns_datagram_start;

    ethernet_protocol* ethernet;
    ip4_protocol* ip4;
    udp_protocol* udp;
    dns_protocol* dns;

    /* L1 */
    ethernet = process_ether_header(&packet);
    packet += ETHERNET_HEADER_LEN;

    /* L2 */
    if(ntohs (ethernet->type) ==  ETHER_TYPE_IP4) {
        ip4 = process_ip4_header(packet);
        packet += IP_HEAD_LEN(ip4);

    }
    else if (ntohs (ethernet->type) == ETHER_TYPE_IP6) {
        process_ip6_header(packet);
        ip4 = nullptr;
    }

    /* L3 */
    switch(ip4->prt) {
        case PRT_UDP:
            udp = process_upd_header(packet);
            packet += UDP_HEAD_LEN;
            break;

        case PRT_TCP:
            process_tcp_header(packet);
            break;

        default:
            raise(123, "Error, not UDP nor TCP");
    }

    /* L4 */
    dns_datagram_start = packet;
    dns = process_dns(packet);
}

ethernet_protocol* process_ether_header(const unsigned char **packet) {

    ethernet_protocol *ethernet;   /* Ethernet header */

    /* typecast ethernet header */
    ethernet = (ethernet_protocol *) *packet;

    // ### DEBUG PRINT ###
    std::cout << std::endl << std::endl;
    DEBUG_DATAGRAM_PRINT("Ethernet");
    DEBUG_PRINT("SRC", ether_ntoa((const struct ether_addr *) ethernet->mac_dest));
    DEBUG_PRINT("SRC", ether_ntoa((const struct ether_addr *) ethernet->mac_host));

    return ethernet;
}

ip4_protocol* process_ip4_header(const b8 *packet) {
    ip4_protocol *ip;              /* Ip header       */

    /* typecast ip header */
    ip = (ip4_protocol *) packet;


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

    return ip;
}

// TODO: ip6 header
int process_ip6_header(const b8 *packet) {
    raise(42, "IPv6 datagram not implemented");
    return 0;
}

udp_protocol* process_upd_header(const b8 *packet) {
    udp_protocol *udp;     /* UDP header */

    udp = (udp_protocol *) packet;

    DEBUG_DATAGRAM_PRINT("UDP");
    DEBUG_PRINT("SRC", ntohs(udp->src));
    DEBUG_PRINT("DEST", ntohs(udp->dst));
    DEBUG_PRINT("LEN", ntohs(udp->len));
}

// TODO: tcp_header
int process_tcp_header(const b8 *packet) {
    DEBUG_DATAGRAM_PRINT("TCP");

    raise(42, "tcp datagram not implemented");
    return 0;
}

dns_protocol* process_dns(const b8 *packet) {
    dns_protocol *dns;              /* DNS protocol */
    const b8* dns_datagram_start;

    /* allocation memory for dns_protocol structure */
    dns = (dns_protocol *) malloc(sizeof(dns_protocol));

    /* pointing to dns_header */
    dns->header = get_dns_header(packet);
    packet += DNS_HEAD_LEN;


    /* loop over authorities */

    //DEBUG_DATAGRAM_PRINT("Authorities");
    for(int i = 0; i < n_auth; i++) {

    }

    /* loop over additions */

    //DEBUG_DATAGRAM_PRINT("Additions");
    for(int i = 0; i < n_adds; i++) {

    }



    dns->body = get_dns_body(&packet, dns->header);


    DEBUG_DATAGRAM_PRINT("Questions");
    for(int i = 0; i < ntohs(dns->header->questions_number); i++) {
        std::cout << dns->body->questions[i]->qname << " " << ntohs(dns->body->questions[i]->qclass) << " " << ntohs(dns->body->questions[i]->type) << std::endl;
    }

    DEBUG_DATAGRAM_PRINT("Answers");
    for(int i = 0; i < ntohs(dns->header->answers_number); i++) {
        std::cout << dns->body->records[i]->qname << " " << ntohs(dns->body->records[i]->qclass) << " " << ntohs(dns->body->records[i]->type) << std::endl;
    }

    return dns;
}

dns_header* get_dns_header(const b8 *packet) {
    return (dns_header *) packet;
}

//  TODO Free mem !!!
dns_body* get_dns_body(const b8 **packet, dns_header *header) {
    dns_body *body;

    body = (dns_body *) malloc(sizeof(dns_body));

    /* allocates memory for all question pointers */
    int ques_num = ntohs(header->questions_number);

    if((body->questions = (rr_question **) malloc(ques_num *sizeof(rr_question *))) == nullptr) {
        raise(1234, "Malloc error");
    }

    /* loop over questions */
    for(int i = 0; i < ques_num; i++) {
        body->questions[i] = get_query_record(packet);
    }


    /* allocates memory for all answer pointers */
    int answ_num = ntohs(header->answers_number);
    body->records = (rr_record **) malloc(answ_num * sizeof(rr_record *));

    /* loop over answers */
    for(int i = 0; i < answ_num; i++) {
        body->records[i] = get_answers_record(packet, (const b8 *)header);
    }

    return body;
}

// TODO: Free mem !!!
rr_question* get_query_record(const b8 **packet) {

    rr_question *question;
    question = (rr_question *) malloc(sizeof(rr_question));

    question->qname = get_name(packet);

    question->type = *(b16 *) *packet;
    *packet += sizeof(question->type);

    question->qclass = *(b16 *) *packet;
    *packet += sizeof(question->qclass);

    return question;
}

//TODO: free malloc !!!
rr_record *get_answers_record(const b8 **packet, const b8 *dns_datagram_start) {
    rr_record *answer;
    a_rdata* record;

    answer = (rr_record *) malloc(sizeof(rr_record));

    /*
     * NAME is stored in shortened format, first two bits are '1' rest is integer representing offset in octets from
     * DNS datagram start
     */
    int offset = ntohs(*(b16 *) *packet) & 0b0011111111111111;

    const b8 *name_start = dns_datagram_start + offset;

    answer->qname = get_name(&name_start);

    *packet += RESOURCE_RECORD_NAME_OFFSET;

    answer->type = *(b16 *) *packet;
    *packet += sizeof(answer->type);

    answer->qclass = *(b16 *) *packet;
    *packet += sizeof(answer->qclass);

    answer->ttl = *(b32 *) *packet;
    *packet += sizeof(answer->ttl);

    answer->len = *(b16 *) *packet;
    *packet += sizeof(answer->len);

    /*
    DEBUG_DATAGRAM_PRINT(answer->qname);
    DEBUG_PRINT("type", htons(answer->type));
    DEBUG_PRINT("class", htons(answer->qclass));
    DEBUG_PRINT("ttl", ntohl(answer->ttl));
    DEBUG_PRINT("len", htons(answer->len));
    */

    switch (htons(answer->qclass)) {
        case DNS_CLASS_IN:
            switch (htons(answer->type)) {

                case DNS_TYPE_A:
                    //record = get_a_record(*packet);
                    //*packet += RDATA_A_LEN;
                    break;

                case DNS_TYPE_AAAA:
                    break;

                case DNS_TYPE_CNAME:
                    break;

                case DNS_TYPE_MX:
                    break;

                case DNS_TYPE_SOA:
                    break;

                case DNS_TYPE_TXT:
                    break;

                default:
                    break;
                    //raise(128, "unsupported DNS rr_record TYPE");

            }
            break;

        default:
            break;
            //raise(128, "unsupported DNS rr_record CLASS");
    }


    //jump over data
    *packet += ntohs(answer->len);

    return answer;
}

// TODO: free malloc !!!
std::string get_name(const b8 **packet) {

    std::string name;

    int next_label_size = **packet;
    *packet += sizeof(b8);

    while(next_label_size != 0) {

        /* add characters to output string in range of defined label */
        for(int i = 0; i < next_label_size; i++) {
            name += **packet;
            (*packet)++;
        }

        next_label_size = **packet;
        *packet += sizeof(b8);

        /* add '.' between labels */
        if(next_label_size > 0) {
            name += '.';
        }

    }

    return name;
}

a_rdata *get_a_record(const b8 *packet) {
    return (a_rdata *) packet;
}


