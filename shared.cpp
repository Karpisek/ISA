//
// Created by Miroslav Karpíšek on 25/10/2018.
//

#include "shared.h"

#define PORT "514"

std::vector <statistic *> global_statistics;
connection global_syslog_connection;
unsigned int global_sending_timeout;

void add_to_statistics(rr_answer *new_answer) {
    if(new_answer == nullptr) {
        return;
    }

    std::string new_stat = parse_stats(new_answer);

    for(auto stat : global_statistics) {
        if(stat->text == new_stat) {

            /* increment counter found the same record */
            stat->count++;
            return;
        }
    }

    auto *stat_object = new statistic;

    stat_object->text = new_stat;
    stat_object->count = 1;

    /* no statistics so far found */
    global_statistics.push_back(stat_object);

    delete new_answer;
}

int init_sender(const char *addr_str) {

    if(global_syslog_connection.enstablished) {
        return 1;
    }

    int socket_fd, succ;

    struct addrinfo hint = {};
    struct addrinfo *info;

    memset(&hint, 0, sizeof hint);  // make sure the struct is empty
    hint.ai_family = AF_UNSPEC;     // don't care IPv4 or IPv6
    hint.ai_socktype = SOCK_DGRAM;  // UDP stream sockets
    hint.ai_flags = AI_PASSIVE;     // fill in my IP for me

    /* get info about the host */
    succ = getaddrinfo(addr_str, PORT, &hint, &info);
    if(succ != 0) {
        raise(22132, "Host not found");
    }

    /* connect socket */
    socket_fd = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
    if(socket_fd < 0) {
        raise(55, "Socket failed");
    }

    succ = connect(socket_fd, info->ai_addr, info->ai_addrlen);
    if(succ < 0) {
        raise(66, "Connect failed");
    }

    printf("Successfully bound to port %s\n", PORT);

    global_syslog_connection = {true, socket_fd};

    return 0;
}

int close_connection() {

    if(!global_syslog_connection.enstablished) {
        return 1;
    }

    if(close(global_syslog_connection.connection) != 0) {
        printf("ERROR closing socket");
    }

    global_syslog_connection = {false, -1};

    return 0;
}

int syslog_send(std::string data_to_send) {

    if (!global_syslog_connection.enstablished) {
        return 1;
    }

    std::cout << data_to_send.c_str() << std::endl;
    send(global_syslog_connection.connection, data_to_send.c_str(), data_to_send.size(), 0);  // send data to the server
    return 0;
}

std::string parse_stats(rr_answer* answer) {

    std::string message;

    message += answer->qname;
    message += " ";

    switch (answer->type) {
        case DNS_TYPE_A:
            message += "A" ;
            message += " ";
            message += answer->record.A->ip4;
            break;

        case DNS_TYPE_AAAA:
            message += "AAAA";
            message += " ";
            message += answer->record.AAAA->ip6;
            break;

        case DNS_TYPE_CNAME:
            message += "CNAME";
            message += " ";
            message += answer->record.CNAME->cname;
            break;

        case DNS_TYPE_MX:
            message += "MX";
            message += " ";
            message += std::to_string(answer->record.MX->preference);
            message += " ";
            message += answer->record.MX->exchange;
            break;

        case DNS_TYPE_NS:
            message += "NS";
            message += " ";
            message += answer->record.NS->nsname;
            break;

        case DNS_TYPE_SOA:
            message += "SOA";
            message += " ";
            message += answer->record.SOA->mnname;
            message += " ";
            message += answer->record.SOA->rname;
            message += " ";
            message += std::to_string(answer->record.SOA->serial);
            message += " ";
            message += std::to_string(answer->record.SOA->refresh);
            message += " ";
            message += std::to_string(answer->record.SOA->retry);
            message += " ";
            message += std::to_string(answer->record.SOA->expire);
            message += " ";
            message += std::to_string(answer->record.SOA->minimum);
            break;

        case DNS_TYPE_TXT:
            message += "TXT";
            message += " ";
            message += answer->record.TXT->text;
            break;

        case DNS_TYPE_DNSKEY:
            message += "DNSKEY";
            message += " ";
            message += std::to_string(answer->record.DNSKEY->flags);
            message += " ";
            message += std::to_string(answer->record.DNSKEY->protocol);
            message += " ";
            message += std::to_string(answer->record.DNSKEY->algorithm);
            message += " ";
            message += answer->record.DNSKEY->public_key;
            break;

        case DNS_TYPE_DS:
            message += "DS";
            break;

        case DNS_TYPE_NSEC:
            message += "NSEC";
            message += " ";
            message += answer->record.NSEC->next_domain_name;
            message += " ";
            message += answer->record.NSEC->bit_maps;
            break;

        case DNS_TYPE_RSIG:
            message += "RSIG";
            message += " ";
            switch (answer->record.RSIG->type) {
                case DNS_TYPE_A:
                    message += "A" ;
                    break;

                case DNS_TYPE_AAAA:
                    message += "AAAA";
                    break;

                case DNS_TYPE_CNAME:
                    message += "CNAME";
                    break;

                case DNS_TYPE_MX:
                    message += "MX";
                    break;

                case DNS_TYPE_NS:
                    message += "NS";
                    break;

                case DNS_TYPE_SOA:
                    message += "SOA";
                    break;

                case DNS_TYPE_TXT:
                    message += "TXT";
                    break;

                case DNS_TYPE_DNSKEY:
                    message += "DNSKEY";
                    break;

                case DNS_TYPE_RSIG:
                    message += "RSIG";
                    break;

                case DNS_TYPE_DS:
                    message += "DS";
                    break;

                case DNS_TYPE_NSEC:
                    message += "NSEC";
                    break;

                default:
                    break;
            }

            message += " ";
            message += std::to_string(answer->record.RSIG->algorithm);
            message += " ";
            message += std::to_string(answer->record.RSIG->labels);
            message += " ";
            message += std::to_string(answer->record.RSIG->ttl);
            message += " ";
            message += std::to_string(answer->record.RSIG->expiration);
            message += " ";
            message += std::to_string(answer->record.RSIG->inception);
            message += " ";
            message += std::to_string(answer->record.RSIG->key_tag);
            message += " ";
            message += answer->record.RSIG->signers_name;
            message += " ";
            message += answer->record.RSIG->signature;

            break;

        default:
            break;
    }

    return message;
}

