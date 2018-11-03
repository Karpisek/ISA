//
// Created by Miroslav Karpíšek on 25/10/2018.
//

#include <sys/time.h>
#include "user_signal.h"

void print_statistics(int signum) {

    int pid;
    pid = fork();

    if(pid == 0) {
        for(auto stat: global_statistics) {
            std::cout << stat->text << " " << std::to_string(stat->count) << std::endl;
        }

        std::cout << std::endl;
        exit(0);

    }

    /* ignoring signal */
    signal(SIGCHLD, SIG_IGN);
}

void send_statistics(int signum) {
    int pid;
    pid = fork();

    if(pid == 0) {
        for(auto stat: global_statistics) {
            syslog_send(generate_syslog_header() + stat->text + " " + std::to_string(stat->count));
        }

        exit(0);
    }

    /* ignoring signal */
    signal(SIGCHLD, SIG_IGN);

    /* setting up periodic alarm */
    alarm(global_sending_timeout);
}

std::string generate_syslog_header() {

    /* priority value */
    int facility = FACILITY_LOCAL_0;
    int severity = SEVERITY_INFORMATIONAL;
    int priority = facility * 8 + severity;
    std::string priority_str = "<" + std::to_string(priority) + ">";

    /* version */
    int version = SYSLOG_VERSION;
    std::string version_str = std::to_string(version);

    /* timestamp */
    char timestamp_str[TIME_STR_BUFFER_SIZE];
    time_t timestamp = time(nullptr);
    struct tm *local_timestamp = localtime(&timestamp);

    strftime(timestamp_str, TIME_STR_BUFFER_SIZE, "%FT%TZ", local_timestamp);

    /* hostname is global*/
    char hostname_str[HOSTNAME_STR_BUFFER_SIZE];
    gethostname(hostname_str, HOSTNAME_STR_BUFFER_SIZE);

    /* app_name is global */

    /* structured data is NILVALUE */
    std::string structured_data = NIL_VALUE;

    std::string return_string;
    return_string += priority_str;
    return_string += version_str;
    return_string += " ";
    return_string += timestamp_str;
    return_string += " ";
    return_string += hostname_str;
    return_string += " ";
    return_string += APP_NAME;
    return_string += " ";
    return_string += structured_data;
    return_string += " ";

    return return_string;
}
