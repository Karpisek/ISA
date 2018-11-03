//
// Created by Miroslav Karpíšek on 25/10/2018.
//

#ifndef ISA_SHARED_H
#define ISA_SHARED_H

#include <iostream>
#include <vector>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <cstdio>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "records.h"
#include "error.h"

typedef struct _connection {
    bool enstablished;
    int connection;
} connection;

typedef struct _statistic {
    std::string text;
    int count;
} statistic;

extern unsigned int global_sending_timeout;
extern std::vector <statistic *> global_statistics;
extern connection global_syslog_connection;

/* statistic procedures */
void add_to_statistics(rr_answer *record);

/* sender procedures */
int init_sender(const char *addr_str);
int close_connection();
int syslog_send(std::string data_to_send);

/* stats */
std::string parse_stats(rr_answer* record);


#endif //ISA_SHARED_H
