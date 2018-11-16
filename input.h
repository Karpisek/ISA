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
#include "shared.h"

void parse_input(int argc, char **argv);

void debug_print_args();
void check_collisions();

#endif //ISA_INPUT_H
