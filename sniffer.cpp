//
// Created by Miroslav Karpíšek on 06/10/2018.
//

#include "sniffer.h"

// TODO: timeout just callbacks to print !!! viz forum

sniff_handler *init_interface(char *dev) {
    sniff_handler *handler;                 /* Session handle */
    char error_buffer[PCAP_ERRBUF_SIZE];    /* Error string */

    handler = (sniff_handler *) malloc(sizeof(sniff_handler));

    handler->dev = dev;

    if(pcap_lookupnet(dev, &handler->ip_address, &handler->netmask, error_buffer) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
    }

    /* opens live capture */
    handler->session = pcap_open_live(dev, BUFSIZ, 1, 1000, error_buffer);
    if(handler->session == nullptr) {
        raise(ERR_INTERFACE_OPEN, std::string(error_buffer));
    }

    return handler;
}

sniff_handler *init_file(char *filename) {
    sniff_handler *handler;                 /* Session handle */
    char error_buffer[PCAP_ERRBUF_SIZE];    /* Error string */

    handler = (sniff_handler *) malloc(sizeof(sniff_handler));

    handler->session = pcap_open_offline(filename, error_buffer);
    if(handler->session == nullptr) {
        raise(ERR_INTERFACE_OPEN, std::string(error_buffer));
    }

    return handler;
}

int sniff(sniff_handler *handler, int duration) {

    struct bpf_program filter_exp = {};		/* The compiled filter expression */
    const b8 *packet;                       /* Packet that pcap gives us */
    struct pcap_pkthdr header = {};	        /* The header that pcap gives us */

    char *dev = handler->dev;
    pcap_t *session = handler->session;
    b32 netmask = handler->netmask;

    /* make sure we're capturing on an Ethernet device */
    if (pcap_datalink(session) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);
    }

    /* create sniff-filter */
    if(pcap_compile(session, &filter_exp, FILTER_EXPRESSION, 0, netmask) == -1) {
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
    ethernet_protocol* ethernet;

    b8 transport_protocol;

    udp_protocol* udp;
    dns_protocol* dns;

    /* L2 */
    ethernet = process_ether_header(&packet);
    packet += ETHERNET_HEADER_LEN;

    /* L3 */
    if(ntohs (ethernet->type) ==  ETHER_TYPE_IP4) {
        ip4_protocol* ip4;
        ip4 = process_ip4_header(packet);

        transport_protocol = ip4->prt;

        packet += IP_HEAD_LEN(ip4);

    } else if (ntohs (ethernet->type) == ETHER_TYPE_IP6) {
        ip6_protocol* ip6;
        ip6 = process_ip6_header(packet);

        transport_protocol = ip6->next;

        packet += IP6_HEAD_LEN;

    } else {
        return;
    }

    /* L4 */
    switch(transport_protocol) {
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
    dns = process_dns(packet);

    DEBUG_DATAGRAM_PRINT("Questions");
    for(int i = 0; i < dns->header->questions_number; i++) {
        std::cout << dns->body->questions[i]->qname << " " << dns->body->questions[i]->qclass << " " << dns->body->questions[i]->type << std::endl;
    }

    DEBUG_DATAGRAM_PRINT("Answers");
    for(int i = 0; i < dns->header->answers_number; i++) {
        std::cout << dns->body->answers[i]->qname << std::endl;
        std::cout << "CLASS: " << dns->body->answers[i]->qclass << " TYPE: " << dns->body->answers[i]->type << std::endl;

        rr_record *record = dns->body->answers[i]->record;

        switch (record->type) {
            case A:
                DEBUG_PRINT("A", record->data.A->ip4);
                break;

            case AAAA:
                DEBUG_PRINT("AAAA", record->data.AAAA->ip6);
                break;

            case CNAME:
                DEBUG_PRINT("CNAME", record->data.CNAME->cname);
                break;

            case MX:
                DEBUG_PRINT("MX", record->data.MX->exchange);
                break;

            case NS:
                DEBUG_PRINT("NS", record->data.NS->nsname);
                break;

            case SOA:
                DEBUG_PRINT("SOA", record->data.SOA->mnname);
                break;

            case TXT:
                DEBUG_PRINT("TXT", record->data.TXT->text);
                break;

            default:
                break;
        }

        std::cout << std::endl;
    }
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

ip6_protocol* process_ip6_header(const b8 *packet) {
    ip6_protocol *ip6;

    ip6 = (ip6_protocol *) packet;

    /* ## DEBUG print IP dest address */
    DEBUG_DATAGRAM_PRINT("IP");
    char buf[INET6_ADDRSTRLEN];
    if(inet_ntop(AF_INET6, &ip6->dst, buf, INET6_ADDRSTRLEN) != nullptr) {
        DEBUG_PRINT("SRC", buf);
    } else {
        raise(12);
    }

    // print IP src address
    if(inet_ntop(AF_INET6, &ip6->src, buf, INET6_ADDRSTRLEN) != nullptr) {
        DEBUG_PRINT("DEST", buf);
    } else {
        raise(12);
    }

    DEBUG_PRINT("next header:", (int) ip6->next);

    return ip6;
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

    /* receiving dns_body */
    dns->body = get_dns_body(&packet, dns->header);

    return dns;
}

// todo free mem
dns_header* get_dns_header(const b8 *packet) {
    raw_dns_header *raw_header;
    dns_header *header;

    raw_header = (raw_dns_header *)packet;

    if((header = (dns_header *) malloc(sizeof(dns_header))) == nullptr){
        raise(1234, "Malloc error");
    }

    header->raw_header = raw_header;
    header->identification = ntohs(raw_header->identification);
    header->questions_number = ntohs(raw_header->questions_number);
    header->answers_number = ntohs(raw_header->answers_number);
    header->additions_number = ntohs(raw_header->additions_number);
    header->authorities_number = ntohs(raw_header->authorities_number);

    return header;
}

//  TODO Free mem !!!
dns_body* get_dns_body(const b8 **packet, dns_header *header) {
    dns_body *body;

    body = (dns_body *) malloc(sizeof(dns_body));

    /* allocates memory for all question pointers */
    int ques_num = header->questions_number;
    if((body->questions = (rr_question **) malloc(ques_num *sizeof(rr_question *))) == nullptr) {
        raise(1234, "Malloc error");
    }
    /* loop over questions */
    for(int i = 0; i < ques_num; i++) {
        body->questions[i] = get_query_record(packet, header->raw_header);
    }

    /* allocates memory for all answer pointers */
    int answ_num = header->answers_number;
    body->answers = (rr_answer **) malloc(answ_num * sizeof(rr_record *));

    /* loop over answers */
    for(int i = 0; i < answ_num; i++) {
        body->answers[i] = get_answers_record(packet, header->raw_header);
    }

    return body;
}

// TODO: Free mem !!!
rr_question* get_query_record(const b8 **packet, raw_dns_header *header) {
    rr_question *question;

    question = (rr_question *) malloc(sizeof(rr_question));

    question->qname = get_name(packet, header);

    question->type = htons(*(b16 *) *packet);
    *packet += sizeof(b16);

    question->qclass = htons(*(b16 *) *packet);
    *packet += sizeof(b16);

    return question;
}

//TODO: free malloc !!!
rr_answer *get_answers_record(const b8 **packet, raw_dns_header *header) {
    rr_answer *answer;

    answer = (rr_answer *) malloc(sizeof(rr_answer));

    /*
     * NAME is stored in shortened format, first two bits are '1' rest is integer representing offset in octets from
     * DNS datagram start
     */
    answer->qname = get_name(packet, header);
    *packet += RESOURCE_RECORD_NAME_OFFSET;

    answer->type = htons(*(b16 *) *packet);
    *packet += sizeof(b16);

    answer->qclass = htons(*(b16 *) *packet);
    *packet += sizeof(b16);

    answer->ttl = htonl(*(b32 *) *packet);
    *packet += sizeof(b32);

    answer->len = htons(*(b16 *) *packet);
    *packet += sizeof(b16);

    switch (answer->qclass) {
        case DNS_CLASS_IN:
            switch (answer->type) {

                case DNS_TYPE_A:
                    answer->record = get_a_record(*packet);
                    break;

                case DNS_TYPE_AAAA:
                    answer->record = get_aaaa_record(*packet);
                    break;

                case DNS_TYPE_CNAME:
                    answer->record = get_cname_record(*packet, header);
                    break;

                case DNS_TYPE_MX:
                    answer->record = get_mx_record(*packet, header);
                    break;

                case DNS_TYPE_NS:
                    answer->record = get_ns_record(*packet, header);
                    DEBUG_PRINT("NS", answer->record->data.NS->nsname);
                    break;

                case DNS_TYPE_SOA:
                    answer->record = get_soa_record(*packet, header);
                    break;

                case DNS_TYPE_TXT:
                    answer->record = get_txt_record(*packet, header);
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
    *packet += answer->len;

    return answer;
}

std::string get_name(const b8 **packet, raw_dns_header *header) {

    std::string name;

    if((ntohs(*(b16 *) *packet) & 0b1100000000000000) == 0b1100000000000000) {
        int offset = ntohs(*(b16 *) *packet) & 0b0011111111111111;
        const b8 *name_start = (const b8 *) header + offset;

        return name + get_name(&name_start, header);
    }

    int next_label_size = **packet;
    *packet += sizeof(b8);

    if(next_label_size == 0) {
        return "";
    }


    /* add characters to output string in range of defined label */
    for(int i = 0; i < next_label_size; i++) {
        name += **packet;
        (*packet)++;
    }

    name += '.';

    return name + get_name(packet, header);

}

// TODO: free mem !!!
rr_record* create_rr_record(rr_data data, rr_tag tag) {
    rr_record* new_data;

    new_data = (rr_record *) malloc(sizeof(rr_record));

    new_data->type = tag;
    new_data->data = data;

    return new_data;
}

// TODO: free mem !!!
rr_record* get_a_record(const b8 *packet) {
    char buf[INET_ADDRSTRLEN];
    rr_data data;
    a_record *record;

    record = (a_record *) malloc(sizeof(a_record));

    record->ip4 = inet_ntop(AF_INET, packet, buf, INET_ADDRSTRLEN);

    data.A = record;

    return create_rr_record(data, A);
}

// TODO: free mem !!!
rr_record* get_aaaa_record(const b8 *packet) {
    char buf[INET6_ADDRSTRLEN];
    rr_data data;
    aaaa_record *record;

    record = (aaaa_record *) malloc(sizeof(aaaa_record));

    record->ip6 = inet_ntop(AF_INET6, packet, buf, INET6_ADDRSTRLEN);

    data.AAAA = record;

    return create_rr_record(data, AAAA);
}

// TODO: free mem !!!
rr_record* get_cname_record(const b8 *packet, raw_dns_header *header) {
    rr_data data;
    cname_record *record;

    record = (cname_record *) malloc(sizeof(cname_record));

    record->cname = get_name(&packet, header);

    data.CNAME = record;

    return create_rr_record(data, CNAME);
}

// TODO: free mem !!!
rr_record* get_mx_record(const b8 *packet, raw_dns_header *header) {
    rr_data data;
    mx_record *record;

    record = (mx_record *) malloc(sizeof(mx_record));

    record->preference = ntohs( *(b16 *) packet);
    packet += sizeof(b16);

    record->exchange = get_name(&packet, header);

    data.MX = record;

    return create_rr_record(data, MX);
}

// TODO: free mem !!!
rr_record* get_ns_record(const b8 *packet, raw_dns_header *header) {
    rr_data data;
    ns_record *record;

    record = (ns_record *) malloc(sizeof(ns_record));

    record->nsname = get_name(&packet, header);

    data.NS = record;

    return create_rr_record(data, NS);
}

// TODO: free mem !!!
rr_record* get_soa_record(const b8 *packet, raw_dns_header *header) {
    rr_data data;
    soa_record *record;

    record = (soa_record *) malloc(sizeof(soa_record));

    record->mnname = get_name(&packet, header);
    record->rname = get_name(&packet, header);
    record->serial = ntohs( *(b32 *) packet);
    packet += sizeof(b32);

    record->refresh = ntohs( *(b32 *) packet);
    packet += sizeof(b32);

    record->retry = ntohs( *(b32 *) packet);
    packet += sizeof(b32);

    record->expire = ntohs( *(b32 *) packet);
    packet += sizeof(b32);

    record->minimum = ntohs( *(b32 *) packet);
    packet += sizeof(b32);


    data.SOA = record;

    return create_rr_record(data, SOA);
}

// TODO: free mem !!!
rr_record* get_txt_record(const b8 *packet, raw_dns_header *header) {
    rr_data data;
    txt_record *record;

    record = (txt_record *) malloc(sizeof(txt_record));

    record->length = *packet;
    packet++;

    for(int i = 0; i < record->length; i++) {
        record->text += *packet;
        packet++;
    }

    data.TXT = record;

    return create_rr_record(data, TXT);
}


