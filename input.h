//
// Created by Miroslav Karpíšek on 06/10/2018.
//

#ifndef ISA_INPUT_H
#define ISA_INPUT_H

#define DEFAULT_TIMEOUT 60

#define ERR_UNDEFINED_PARAM 3
#define STR_ERR_UNDEFINED_PARAM "Unsupported argument, see man page for more information"

#include <iostream>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>

#include "error.h"

union arg_val {
    int i;
    char *str;
};

struct argument {
    bool defined;
    arg_val value;
};

void parse_input(int argc, char **argv, argument *interface, argument *resource, argument *server, argument *timeout);

void debug_print_args(argument interface, argument resource, argument server, argument timeout);
void check_collisions(argument interface, argument resource, argument timeout);

#endif //ISA_INPUT_H
