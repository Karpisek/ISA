//
// Created by Miroslav Karpíšek on 25/10/2018.
//

#include "user_signal.h"

void print_statistics(int signum) {

    int pid;

    pid = fork();

    if(pid == 0) {
        std::cout << "<smazat !!!> actual statistic size: " << global_statistics.size() << std::endl;

        for(auto record: global_statistics) {
            printf("%d\n", record->count);
            printf("%s\n", parse_stats(record));
        }

        std::cout << std::endl;
        exit(0);
    }

    if(pid < 0){
        raise(22, "Fork failed");
    }

    waitpid(-1, NULL, WNOHANG);

}

void send_statistics(int signum) {
    // spawn new process to copy and send
}

const char *parse_stats(rr_record* record) {

    std::string message;

    switch (record->type) {
        case A:
            message += "A" ;
            message += " ";
            message += record->data.A->ip4;
            break;

        case AAAA:
            message += "AAAA";
            message += " ";
            message += record->data.AAAA->ip6;
            break;

        case CNAME:
            message += "CNAME";
            message += " ";
            message += record->data.CNAME->cname;
            break;

        case MX:
            message += "MX";
            message += " ";
            message += std::to_string(record->data.MX->preference);
            message += " ";
            message += record->data.MX->exchange;
            break;

        case NS:
            message += "NS";
            message += " ";
            message += record->data.NS->nsname;
            break;

        case SOA:
            message += "SOA";
            message += " ";
            message += record->data.SOA->mnname;
            break;

        case TXT:
            message += "TXT";
            message += " ";
            message += record->data.TXT->text;
            break;

        default:
            break;
    }

    message += " ";
    message += std::to_string(record->count);

    return message.c_str();
}
