//
// Created by Miroslav Karpíšek on 25/10/2018.
//

#include "user_signal.h"

void print_statistics(int signum) {
    std::cout << "actual statistic size: " << global_statistics.size() << std::endl;
}

void send_statistics(int signum) {
    // spawn new process to copy and send
}

const char *get_statistic(rr_record* record) {

    switch (record->type) {
        case A:
            return ("A " + record->data.A->ip4).c_str();

        case AAAA:
            return ("AAAA " + record->data.AAAA->ip6).c_str();

        case CNAME:
            return ("CNAME " + record->data.CNAME->cname).c_str();

        case MX:
            return ("MX " + std::to_string(record->data.MX->preference) + " " + record->data.MX->exchange).c_str();

        case NS:
            return ("NS " + record->data.NS->nsname).c_str();

        case SOA:
            return ("SOA " + record->data.SOA->mnname).c_str();

        case TXT:
            return ("TXT " + record->data.TXT->text).c_str();

        default:
            break;
    }

    std::cout << std::endl;
}
