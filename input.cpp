//
// Created by Miroslav Karpíšek on 06/10/2018.
//

#include "input.h"

void parse_input(int argc, char **argv, argument *interface, argument *resource, argument *server, argument *timeout) {

    opterr = 0;
    int c;

    while ((c = getopt (argc, argv, "r:i:s:t:")) != -1) {
        switch (c) {
            case 'r':
                resource->defined = true;
                resource->value.str = optarg;
                break;

            case 'i':
                interface->defined = true;
                interface->value.str = optarg;
                break;

            case 's':
                server->defined = true;
                server->value.str = optarg;
                break;

            case 't':
                timeout->defined = true;
                timeout->value.i = atoi(optarg); // NOLINT(cert-err34-c)
                break;

            case '?':
                raise(ERR_UNDEFINED_PARAM, STR_ERR_UNDEFINED_PARAM);

            default:
                abort();
        }
    }
}

void debug_print_args(argument interface, argument resource, argument server, argument timeout) {
    if(resource.defined)
        std::cout << "r: " << resource.value.str << std::endl;

    if(interface.defined)
        std::cout << "i: " << interface.value.str << std::endl;

    if(server.defined)
        std::cout << "s: " << server.value.str << std::endl;

    if(timeout.defined)
        std::cout << "t: " << timeout.value.i << std::endl;
}

void check_collisions(argument interface, argument resource, argument server, argument timeout) {

    // -r and -i cannot be defined together
    if(resource.defined && interface.defined) {
        std::cerr << "argument -r and -i cannot be defined together" << std::endl;
        exit(EXIT_FAILURE);
    }

    // -r and -t cannot be defined together
    if(resource.defined && timeout.defined) {
        std::cerr << "argument -r and -t cannot be defined together" << std::endl;
        exit(EXIT_FAILURE);
    }

    // -t and not -s defined
    if(timeout.defined && !server.defined) {
        exit(0);
    }
}


