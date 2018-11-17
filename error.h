//
// Created by Miroslav Karpíšek on 06/10/2018.
//

#ifndef ISA_ERROR_H
#define ISA_ERROR_H


#include <iostream>
#include <cstdlib>
#include <cstdio>
#include <string>
#include <sysexits.h>
#include <exception>

/* Below are macros for error handling and to inform user */

#define HELP_MESSAGE "use man -l dns-export.1 for more informations"

/* main errors */
#define ERR_UNDEFINED_ARG "Unsupported argument, see man page for more information"
#define ERR_ARG_COLLISION "This argument combination is not allowed, see man page for more information"
#define ERR_SETTING_UP "An error occured while setting up sniffer. Make you sure that you are using all params correctly"
#define ERR_TIMEOUT "Timeout cannot be lower then 1 second"

/* sniff errors */
#define ERR_NETMASK "Can't get netmask for device"
#define ERR_INTERFACE "Can't acces selected interface"
#define ERR_FILE "Problem with selected pcap file"
#define ERR_FILTER "Can't parse filter for campture"

#define ERR_SNIFFING "Something unexpected happend on defragmenting TCP packet, last statistics were send (without the last packet, where error ocurred)"
#define ERR_PROTOCOL "Unsupported protocol"
#define ERR_IP4 "Error in IPv4 header"
#define ERR_IP6 "Error in IPv6 header"

/* shared errors */
#define ERR_HOST "Host not found"
#define ERR_SOCKET "Socket fail"
#define ERR_CLOSE "Can't close socket"
#define ERR_SYSLOG "Trying to send to not existing server"

/* undefined */
#define ERR_UNDEF "Statistics couldn't be sended, sorry"

void raise(int code, std::string message);

#endif //ISA_ERROR_H
