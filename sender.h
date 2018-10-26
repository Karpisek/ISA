//
// Created by Miroslav Karpíšek on 25/10/2018.
//

#ifndef ISA_SENDER_H
#define ISA_SENDER_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <cstdio>
#include <unistd.h>
#include <arpa/inet.h>

#include "error.h"

int init_sender(const char *addr_str);
int close_connection();
int parse_ip_address(const char *addr_str, struct addrinfo *info, struct in6_addr *addr);

#endif //ISA_SENDER_H
