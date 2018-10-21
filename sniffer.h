//
// Created by Miroslav Karpíšek on 06/10/2018.
//

#ifndef ISA_SNIFFER_H
#define ISA_SNIFFER_H

#define ERR_INTERFACE_OPEN 1            /* couldn't open device */

#define FILTER_EXPRESSION "port 53"      /* The filter expression */

#define ERR_ETHERNET_HEADERS 2          /* device doesn't provide Ethernet headers */
#define STR_ERR_ETHERNET_HEADERS "Selected device doesn't provide Ethernet headers - not supported"

#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <iostream>
#include <sstream>
#include <pcap.h>
#include <time.h>
#include <string>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#include "error.h"

/* Typedefs for better readability */
typedef unsigned int b32;
typedef unsigned short b16;
typedef unsigned char b8;

#define ETHERNET_HEADER_LEN 14
#define MAC_ADDR_LEN 6
#define IP4_ADDR_LEN 4
#define ETHER_TYPE_IP4 0x0800
#define ETHER_TYPE_IP6 0x86DD

/* Ethernet header
 *
 *  +-----------------------------------------------------------------------------------------------+
 *  |       0       |       1       |       2       |       3       |       4       |       5       |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                                              DST                                              |
 *  +-----------------------------------------------------------------------------------------------+
 *  |                                              SRC                                              |
 *  +-------------------------------+---------------------------------------------------------------+
 *  |          TYPE/LEN             |            DATA       ...    1500 octets
 *  +---------------+---------------+---------------------------------------------------------------+
 *                ...               |                              SUM                              |
 *  +-------------------------------+---------------------------------------------------------------+
 *
 *  DST -       destination mac address
 *  SRC -       source mac address
 *  TYPE/LEN -  if under 1500 its len, if more it determinate which protocol is used
 *  SUM -       checksum
 *  */
struct ethernet_protocol {
    b8 mac_dest[MAC_ADDR_LEN];     /* destination host address */
    b8 mac_host[MAC_ADDR_LEN];     /* source host address */
    b16 type;                      /* IP? ARP? RARP? 802.1Q... TODO */
};

/* IPv4 header
 *  +---------------------------------------------------------------+
 *  |       0       |       1       |       2       |       3       |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  VER  |  IHL  |      TYPE     |              LEN              |
 *  +-------------------------------+-----+-------------------------+
 *  |               ID              | FRA |       OFFSET            |
 *  +-------------------------------+-----+-------------------------+
 *  |      TTL      |      PRT      |             HSUM              |
 *  +---------------+---------------+-------------------------------+
 *  |                              SRC                              |
 *  +---------------------------------------------------------------+
 *  |                              DST                              |
 *  +---------------------------------------------------------------+
 *  |                   Byte 20 to ((IHL * 4) - 1))                 |   <-- extensions
 *  +---------------------------------------------------------------+
 *
 *  VER -    version
 *  IHL -    header length in half-byte
 *  TYPE -   QoS mechanisms
 *  LEN -    total length in bytes
 *  ID -     identification (in case of fragmentation)
 *  FRA -    fragment flags [3] (zero, don't fragment, more frags)
 *  OFFSET - fragment offset
 *  TTL -    time to live
 *  PRT -    protocol RFC 3232, protocol delegate -> IANA
 *  HSUM -   header checksum
 *  SRC -    IPv4 source address
 *  DST -    IPv4 destination address
 * */

#define IP_HEAD_LEN(ip)          (((ip)->ver_ihl) & 0b00001111) * 4 /* extract ip header length from IHL */
#define IP_VERSION(ip)           (((ip)->ver_ihl) >> 4)             /* extract ip version length from IHL */
#define PRT_UDP 17  /* UDP protocol decimal code for PRT according to RFC 1700 */
#define PRT_TCP 6   /* TCP protocol decimal code for PRT according to RFC 1700 */

struct ip4_protocol {
    b8 ver_ihl;
    b8 type;
    b8 len[2];
    b8 id[2];
    b8 fra_offset[2];
    b8 ttl;
    b8 prt;
    b8 hsum[2];
    b8 src[IP4_ADDR_LEN];
    b8 dst[IP4_ADDR_LEN];
};

/* UDP header
 *  +---------------------------------------------------------------+
 *  |       0       |       1       |       2       |       3       |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |              SRC              |              DST              |
 *  +-------------------------------+-------------------------------+
 *  |              LEN              |              SUM              |
 *  +-------------------------------+-------------------------------+
 *
 *  SRC - source port
 *  DST - destination port
 *  LEN - UDP length + UPD data length
 *  SUM - checksum of UDP header and UDP data, IPv4 optional (zeros when unused) IPv6 mandatory
 *
 */

struct udp_protocol{
    b8 src[2];
    b8 dst[2];
    b8 len[2];
    b8 sum[2];
};


int sniff(char* dev, int timeout);

/* L1 header processing */
int process_ether_header(const b8 *packet);

/* L2 header processing */
int process_ip4_header(const b8 *packet);
int process_ip6_header(const b8 *packet);

/* L3 header processing */
int process_ip4_header(const b8 *packet);
int process_ip6_header(const b8 *packet);

/* L4 header processing */


#endif //ISA_SNIFFER_H

