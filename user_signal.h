//
// Created by Miroslav Karpíšek on 25/10/2018.
//

#ifndef ISA_USER_SIGNAL_H
#define ISA_USER_SIGNAL_H

#include <signal.h>
#include <cstdio>
#include <stdlib.h>
#include <unistd.h>
#include <iostream>
#include <time.h>

#include "shared.h"
#include "error.h"

void send_statistics();
void print_statistics(int signum);
void timeout_signal(int signum);

#endif //ISA_USER_SIGNAL_H
