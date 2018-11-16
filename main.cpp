//
// Created by Miroslav Karpíšek on 06/10/2018.
//

#include "main.h"

int main(int argc, char **argv) {

    /* user signal registration */
    signal(SIGUSR1, print_statistics);

    /* register alarm for sending to server */
    signal(SIGALRM, timeout_signal);

    sniff_handler *handler = nullptr;

    /* parses given arguments and checks for collisions */
    parse_input(argc, argv);
    check_collisions();

    debug_print_args();

    /* timeout setting */
    if(!global_parameters.timeout.defined) {
        global_parameters.timeout.defined = true;
        global_parameters.timeout.value.i = DEFAULT_TIMEOUT;
    }

    global_sending_timeout = (unsigned int) global_parameters.timeout.value.i;

    /* setting up syslog server */
    if(global_parameters.server.defined) {
        init_sender(global_parameters.server.value.str);

        /* setting alarm to sending data to server */
        alarm(global_sending_timeout);
    }

    /* starts sniffing on targeted device */
    if(!global_parameters.interface.defined && !global_parameters.resource.defined) {
        return 0;
    }

    if(global_parameters.interface.defined) {
        handler = init_interface(global_parameters.interface.value.str);
    }

    if(global_parameters.resource.defined) {
        handler = init_file(global_parameters.resource.value.str);
    }

    if(handler != nullptr) {
        sniff(handler);
    }

    return 0;
}