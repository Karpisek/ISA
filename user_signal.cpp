//
// Created by Miroslav Karpíšek on 25/10/2018.
//

#include <sys/time.h>
#include "user_signal.h"

void print_statistics(int signum) {

    int pid;
    pid = fork();

    if(pid == 0) {
        for(auto stat: global_statistics) {
            std::cout << stat->text << " " << std::to_string(stat->count) << std::endl;
        }

        std::cout << std::endl;
        exit(0);

    }

    /* ignoring signal */
    signal(SIGCHLD, SIG_IGN);
}

void timeout_signal(int signum) {
    int pid;
    pid = fork();

    if(pid == 0) {
        send_statistics();
        exit(0);
    }

    /* ignoring signal */
    signal(SIGCHLD, SIG_IGN);

    /* setting up periodic alarm */
    alarm(global_sending_timeout);
}

void send_statistics() {
    for(auto stat: global_statistics) {
        syslog_send(generate_syslog_header() + stat->text + " " + std::to_string(stat->count));
    }
}
