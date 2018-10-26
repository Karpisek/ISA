//
// Created by Miroslav Karpíšek on 25/10/2018.
//

#include "user_signal.h"

void send_statistics(int signum) {
    printf("Caught signal %d\n", signum);
    printf("Break loop");
    printf("Sanding packets");
    printf("continue");

    sleep(10);

    printf("\n\nEND");
}
