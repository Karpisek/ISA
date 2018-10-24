//
// Created by Miroslav Karpíšek on 06/10/2018.
//

#include "main.h"

int main(int argc, char **argv) {
    b32 ip

    argument interface = {false, 0};
    argument resource = {false, 0};
    argument timeout = {false, 0};
    argument server = {false, 0};

    /* parses given arguments and checks for collisions */
    parse_input(argc, argv, &interface, &resource, &server, &timeout);
    check_collisions(interface, resource, timeout);

    if(not timeout.defined) {
        timeout.defined = true;
        timeout.value.i = DEFAULT_TIMEOUT;
    }

    debug_print_args(interface, resource, server, timeout);

    /* starts sniffing on targeted device */
    if(interface.defined) {
        sniff(interface.value.str, timeout.value.i);
    }

    if(interface.defined) {

    }




    return 0;
}