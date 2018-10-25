//
// Created by Miroslav Karpíšek on 06/10/2018.
//

#include "main.h"

int main(int argc, char **argv) {

    /* user signal registration */
    signal(SIGUSR1, send_statistics);

    sniff_handler *handler;

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

    if(server.defined) {
        init_sender(server.value.str);
    }

    /* starts sniffing on targeted device */
    if(interface.defined) {
        handler = init_interface(interface.value.str);
    } else if(resource.defined) {
        handler = init_file(resource.value.str);
    } else {
        return 2222;
    }

    sniff(handler, timeout.value.i);


    return 0;
}