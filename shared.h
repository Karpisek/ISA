//
// Created by Miroslav Karpíšek on 25/10/2018.
//

#ifndef ISA_SHARED_H
#define ISA_SHARED_H

#include <iostream>
#include <vector>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <cstdio>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include <cmath>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "records.h"
#include "error.h"

#define FACILITY_LOCAL_0 16
#define SEVERITY_INFORMATIONAL 6
#define SYSLOG_VERSION 1

#define TIME_STR_BUFFER_SIZE 80
#define HOSTNAME_STR_BUFFER_SIZE 80
#define NIL_VALUE "- - -"
#define APP_NAME "dns-export"

typedef struct _connection connection;
typedef struct _statistic statistic;
typedef struct _tcp_fragment tcp_fragment;
typedef struct _parameters parameters;
typedef struct _argument argument;
typedef union _arg_val arg_val;

struct _connection {
    bool enstablished;
    int connection;
    addrinfo *info;
    std::string local_address;
};

struct _statistic {
    std::string text;
    int count;
};

struct _tcp_fragment {
    std::string id;
    unsigned char packet[65535];
    unsigned long seq;
    int last;
};

union _arg_val {
    int i;
    char *str;
};

struct _argument {
    bool defined;
    arg_val value;
};

struct _parameters {
    argument interface;
    argument resource;
    argument server;
    argument timeout;
    argument concatenate;
    argument fragmentation;
    argument help;
};

extern unsigned int global_forks;
extern std::vector <statistic *> global_statistics;
extern std::vector <tcp_fragment *> global_fragments;
extern connection global_syslog_connection;
extern parameters global_parameters;

/* statistic procedures */
void add_to_statistics(rr_answer *record);
void remove_tcp_fragment(std::string id);

/* sender procedures */
int init_sender(const char *addr_str);
int close_socket();
int syslog_send(std::string data_to_send);

/* stats */
std::string parse_stats(rr_answer* record);
std::string generate_syslog_header();


#endif //ISA_SHARED_H
