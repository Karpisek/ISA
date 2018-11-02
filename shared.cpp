//
// Created by Miroslav Karpíšek on 25/10/2018.
//

#include "shared.h"

#define PORT "514"

std::vector <rr_answer *> global_statistics;
connection global_syslog_connection;
unsigned int global_sending_timeout;

void add_to_statistics(rr_answer *new_answer) {
    if(new_answer == nullptr) {
        return;
    }

    for(auto answer : global_statistics) {
        if(*answer == *new_answer) {

            /* increment counter found the same record */
            answer->count++;
            return;
        }
    }

    /* no statistics so far found */
    global_statistics.push_back(new_answer);
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

    send(global_syslog_connection.connection, data_to_send.c_str(), data_to_send.size(), 0);  // send data to the server
    return 0;
}
