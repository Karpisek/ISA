//
// Created by Miroslav Karpíšek on 06/10/2018.
//

#include "main.h"

int main(int argc, char **argv) {

    sniff_handler *handler = nullptr;

    try {
        /* user signal registration */
        signal(SIGUSR1, print_statistics);

        /* register alarm for sending to server */
        signal(SIGALRM, timeout_signal);

        /* register alarm for sending to server */
        signal(SIGINT, close_signal);

        /* parses given arguments and checks for collisions */
        parse_input(argc, argv);
        check_collisions();

        if(global_parameters.help.defined) {
            std::cout << HELP_MESSAGE << std::endl;
            exit(0);
    }

        /* timeout setting */
        if(!global_parameters.timeout.defined) {
            global_parameters.timeout.defined = true;
            global_parameters.timeout.value.i = DEFAULT_TIMEOUT;
        }


        /* setting up syslog server */
        if(global_parameters.server.defined) {
            init_sender(global_parameters.server.value.str);

            /* setting alarm to sending data to server */
            alarm((unsigned) global_parameters.timeout.value.i);
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
    }

    catch (std::exception& e) {
        raise(EX_SOFTWARE, ERR_SETTING_UP);
    }


    if(handler != nullptr) {
        sniff(handler);
    }

    close_socket();
    return 0;
}