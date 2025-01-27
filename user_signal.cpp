//
// Created by Miroslav Karpíšek on 25/10/2018.
//

#include <sys/time.h>
#include "user_signal.h"

void program_can_end_signal(int signum) {
    (void) signum;

    global_forks--;
}

void print_statistics(int signum) {
    (void) signum; //in this project unused parameter

    int pid;
    pid = fork();
    global_forks++;

    if(pid == 0) {
        for(auto stat: global_statistics) {
            std::cout << stat->text << " " << std::to_string(stat->count) << std::endl;
        }

        std::cout << std::endl;
        exit(0);
    }

    /* ignoring signal */
    signal(SIGCHLD, program_can_end_signal);
}

void timeout_signal(int signum) {
    (void) signum;  //in this project unused parameter

    int pid;
    pid = fork();
    global_forks++;

    if(pid == 0) {
        send_statistics();
        exit(0);
    }

    /* ignoring signal */
    signal(SIGCHLD, program_can_end_signal);

    /* setting up periodic alarm */
    alarm((unsigned) global_parameters.timeout.value.i);
}

void close_signal(int signum) {
    (void) signum;  //in this project unused parameter

    close_socket();
    exit(0);
}

void send_statistics() {

    static std::string message;
    std::string new_message;

    if(global_parameters.concatenate.defined) {
        for(auto stat: global_statistics) {

            new_message = stat->text + " " + std::to_string(stat->count);

            if(message.length() + new_message.length() > 1000) {
                syslog_send(message.insert(0, generate_syslog_header()));
                message = "";
            } else {
                if(message.length() > 0){
                    message += " ";
                }

                message += new_message;
            }
        }

        if(message.length() > 0) {
            syslog_send(message.insert(0, generate_syslog_header()));
        }

    } else {

        for(auto stat: global_statistics) {
            new_message = generate_syslog_header() + stat->text + " " + std::to_string(stat->count);
            syslog_send(new_message);
        }
    }
}
