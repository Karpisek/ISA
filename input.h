//
// Created by Miroslav Karpíšek on 06/10/2018.
//

#ifndef ISA_INPUT_H
#define ISA_INPUT_H

#define DEFAULT_TIMEOUT 60

#include <iostream>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>

#include "error.h"
#include "shared.h"

void parse_input(int argc, char **argv);

void check_collisions();

#endif //ISA_INPUT_H
