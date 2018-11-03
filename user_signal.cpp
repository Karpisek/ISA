//
// Created by Miroslav Karpíšek on 25/10/2018.
//

#include <sys/time.h>
#include "user_signal.h"

void print_statistics(int signum) {

    int pid;
    pid = fork();

    if(pid == 0) {
        for(auto answer: global_statistics) {
            std::cout << parse_stats(answer) << std::endl;
        }

        std::cout << std::endl;
        exit(0);

    }

    /* ignoring signal */
    signal(SIGCHLD, SIG_IGN);
}

void send_statistics(int signum) {
    int pid;
    pid = fork();

    if(pid == 0) {
        for(auto answer: global_statistics) {
            syslog_send(generate_syslog_header() + parse_stats(answer));
        }

        exit(0);
    }

    /* ignoring signal */
    signal(SIGCHLD, SIG_IGN);

    /* setting up periodic alarm */
    alarm(global_sending_timeout);
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

    message += " ";
    message += std::to_string(answer->count);

    return message;
}

std::string generate_syslog_header() {

    /* priority value */
    int facility = FACILITY_LOCAL_0;
    int severity = SEVERITY_INFORMATIONAL;
    int priority = facility * 8 + severity;
    std::string priority_str = "<" + std::to_string(priority) + ">";

    /* version */
    int version = SYSLOG_VERSION;
    std::string version_str = std::to_string(version);

    /* timestamp */
    char timestamp_str[TIME_STR_BUFFER_SIZE];
    time_t timestamp = time(nullptr);
    struct tm *local_timestamp = localtime(&timestamp);

    strftime(timestamp_str, TIME_STR_BUFFER_SIZE, "%FT%TZ", local_timestamp);

    /* hostname is global*/
    char hostname_str[HOSTNAME_STR_BUFFER_SIZE];
    gethostname(hostname_str, HOSTNAME_STR_BUFFER_SIZE);

    /* app_name is global */

    /* structured data is NILVALUE */
    std::string structured_data = NIL_VALUE;

    std::string return_string;
    return_string += priority_str;
    return_string += version_str;
    return_string += " ";
    return_string += timestamp_str;
    return_string += " ";
    return_string += hostname_str;
    return_string += " ";
    return_string += APP_NAME;
    return_string += " ";
    return_string += structured_data;
    return_string += " ";

    return return_string;
}
