//
// Created by Miroslav Karpíšek on 06/10/2018.
//

#include "input.h"

void parse_input(int argc, char **argv) {

    opterr = 0;
    int c;

    while ((c = getopt (argc, argv, "hfcr:i:s:t:")) != -1) {
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

            case 'f':
                global_parameters.fragmentation.defined = true;
                break;

            case 'h':
                global_parameters.help.defined = true;
                break;

            case '?':
                raise(EX_USAGE, ERR_UNDEFINED_ARG);

            default:
                raise(EX_USAGE, ERR_UNDEFINED_ARG);
        }
    }
}

void check_collisions() {

    // -r and -i cannot be defined together
    if(global_parameters.resource.defined && global_parameters.interface.defined) {
        raise(EX_USAGE, ERR_ARG_COLLISION);
    }

    // -r and -t cannot be defined together
    if(global_parameters.resource.defined && global_parameters.timeout.defined) {
        raise(EX_USAGE, ERR_ARG_COLLISION);
    }

    // -t and not -s defined
    if(global_parameters.timeout.defined && !global_parameters.server.defined) {
        raise(EX_USAGE, ERR_ARG_COLLISION);
    }

    // -c and not -s defined
    if(global_parameters.timeout.defined && !global_parameters.server.defined) {
        raise(EX_USAGE, ERR_ARG_COLLISION);
    }

    if(global_parameters.timeout.defined) {
        if(global_parameters.timeout.value.i < 1) {
            raise(EX_USAGE, ERR_TIMEOUT);
        }
    }
}


