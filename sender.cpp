//
// Created by Miroslav Karpíšek on 25/10/2018.
//

#include <netdb.h>
#include "sender.h"

#define PORT "3490"

int init_sender(const char *addr_str) {
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

    return socket_fd;
}

int close_connection(int connection) {
    if(close(connection) != 0) {
        printf("ERROR closing socket");
    }

    return 0;
}

int syslog_send(int connection, char *data_to_send) {
    send(connection, data_to_send, 1024, 0);  // send data to the server

    return 0;
}