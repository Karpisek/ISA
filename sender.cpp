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
    hint.ai_socktype = SOCK_STREAM; // TCP stream sockets
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

int close_connection(int opened_connection) {
    if(close(opened_connection) != 0) {
        printf("ERROR closing socket");
    }
}

int parse_ip_address(const char *addr_str, struct addrinfo *info, struct in6_addr *addr) {

    int success = inet_pton(AF_INET, addr_str, addr);

    if(success == 1) {
        info->ai_family = AF_INET;
        info->ai_flags |= AI_NUMERICHOST;

        return 0;
    }
    if(success != 0) {
        return 1;
    }

    success = inet_pton(AF_INET6, addr_str, addr);
    if(success == 1) {

        info->ai_family = AF_INET6;
        info->ai_flags |= AI_NUMERICHOST;

        return 0;
    }


    return 1;
}