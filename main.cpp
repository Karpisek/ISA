//
// Created by Miroslav Karpíšek on 06/10/2018.
//

#include "main.h"

int main(int argc, char **argv) {

    /* user signal registration */
    signal(SIGUSR1, print_statistics);

    /* register alarm for sending to server */
    signal(SIGALRM, send_statistics);

    sniff_handler *handler = nullptr;

    argument interface = {false, 0};
    argument resource = {false, 0};
    argument timeout = {false, 0};
    argument server = {false, 0};

    /* parses given arguments and checks for collisions */
    parse_input(argc, argv, &interface, &resource, &server, &timeout);
    check_collisions(interface, resource, server, timeout);

    debug_print_args(interface, resource, server, timeout);

    /* timeout setting */
    if(!timeout.defined) {
        timeout.defined = true;
        timeout.value.i = DEFAULT_TIMEOUT;
    }

    global_sending_timeout = (unsigned int) timeout.value.i;

    /* setting up syslog server */
    if(server.defined) {
        init_sender(server.value.str);

        /* setting alarm to sending data to server */
        alarm(global_sending_timeout);
    }

    /* starts sniffing on targeted device */
    if(!interface.defined && !resource.defined) {
        return 0;
    }

    if(interface.defined) {
        handler = init_interface(interface.value.str);
    }

    if(resource.defined) {
        handler = init_file(resource.value.str);
    }

    if(handler != nullptr) {
        sniff(handler);
    }

    return 0;
}