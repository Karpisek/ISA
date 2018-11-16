//
// Created by Miroslav Karpíšek on 06/10/2018.
//

#include "input.h"

void parse_input(int argc, char **argv) {

    opterr = 0;
    int c;

    while ((c = getopt (argc, argv, "cr:i:s:t:")) != -1) {
        switch (c) {
            case 'r':
                global_parameters.resource.defined = true;
                global_parameters.resource.value.str = optarg;
                break;

            case 'i':
                global_parameters.interface.defined = true;
                global_parameters.interface.value.str = optarg;
                break;

            case 's':
                global_parameters.server.defined = true;
                global_parameters.server.value.str = optarg;
                break;

            case 't':
                global_parameters.timeout.defined = true;
                global_parameters.timeout.value.i = atoi(optarg); // NOLINT(cert-err34-c)
                break;

            case 'c':
                global_parameters.concatenate.defined = true;
                break;

            case '?':
                raise(ERR_UNDEFINED_PARAM, STR_ERR_UNDEFINED_PARAM);

            default:
                abort();
        }
    }
}

void debug_print_args() {
    if(global_parameters.resource.defined)
        std::cout << "r: " << global_parameters.resource.value.str << std::endl;

    if(global_parameters.interface.defined)
        std::cout << "i: " << global_parameters.interface.value.str << std::endl;

    if(global_parameters.server.defined)
        std::cout << "s: " << global_parameters.server.value.str << std::endl;

    if(global_parameters.timeout.defined)
        std::cout << "t: " << global_parameters.timeout.value.i << std::endl;
}

void check_collisions() {

    // -r and -i cannot be defined together
    if(global_parameters.resource.defined && global_parameters.interface.defined) {
        std::cerr << "argument -r and -i cannot be defined together" << std::endl;
        exit(EXIT_FAILURE);
    }

    // -r and -t cannot be defined together
    if(global_parameters.resource.defined && global_parameters.timeout.defined) {
        std::cerr << "argument -r and -t cannot be defined together" << std::endl;
        exit(EXIT_FAILURE);
    }

    // -t and not -s defined
    if(global_parameters.timeout.defined && !global_parameters.server.defined) {
        exit(0);
    }
}


