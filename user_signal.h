//
// Created by Miroslav Karpíšek on 25/10/2018.
//

#ifndef ISA_USER_SIGNAL_H
#define ISA_USER_SIGNAL_H

#define FACILITY_LOCAL_0 16
#define SEVERITY_INFORMATIONAL 6
#define SYSLOG_VERSION 1

#define TIME_STR_BUFFER_SIZE 80
#define HOSTNAME_STR_BUFFER_SIZE 80
#define NIL_VALUE "-"
#define APP_NAME "dns-export"

#include <signal.h>
#include <cstdio>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include <time.h>

#include "shared.h"
#include "error.h"

void send_statistics(int signum);
void print_statistics(int signum);
std::string parse_stats(rr_answer* record);
std::string generate_syslog_header();
void loop_and_print();


#endif //ISA_USER_SIGNAL_H
