//
// Created by Miroslav Karpíšek on 06/10/2018.
//

#ifndef ISA_SNIFFER_H
#define ISA_SNIFFER_H

#define ERR_INTERFACE_OPEN 1            /* couldn't open device */
#define FILTER_EXPRESSION "port 53"     /* The filter expression port DNS */

#define ERR_ETHERNET_HEADERS 2          /* device doesn't provide Ethernet headers */
#define STR_ERR_ETHERNET_HEADERS "Selected device doesn't provide Ethernet headers - not supported"

#define DEBUG_PRINT(info, data)         (std::cout << "\t" << info << ": " << data << std::endl)
#define DEBUG_DATAGRAM_PRINT(header)    (std::cout << "---------------- " << header  << std::endl)

#include <unistd.h>
#include <signal.h>
#include <cstdio>
#include <iostream>
#include <sstream>
#include <pcap.h>
#include <ctime>
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

typedef struct ethernet_protocol {
    b8 mac_dest[MAC_ADDR_LEN];     /* destination host address */
    b8 mac_host[MAC_ADDR_LEN];     /* source host address */
    b16 type;                      /* IP? ARP? RARP? 802.1Q... TODO */
} ethernet_protocol;

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

#define IP_HEAD_LEN(ip)          ((((ip)->ver_ihl) & 0b00001111) * 4) /* extract ip header length from IHL */
#define IP_VERSION(ip)           (((ip)->ver_ihl) >> 4)             /* extract ip version length from IHL */
#define PRT_UDP 17  /* UDP protocol decimal code for PRT according to RFC 1700 */
#define PRT_TCP 6   /* TCP protocol decimal code for PRT according to RFC 1700 */

typedef struct ip4_protocol {
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
} ip4_protocol;

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
 *  LEN - UDP length + UDP data length
 *  SUM - checksum of UDP header and UDP data, IPv4 optional (zeros when unused) IPv6 mandatory
 *
 */

#define UDP_HEAD_LEN 8  /* length of udp header in octets */

struct udp_protocol{
    b16 src;
    b16 dst;
    b16 len;
    b16 sum;
};

/* DNS header
 *
 *  +-----------------------+-----------------------+-----------------------+-----------------------+
 *  |           0           |           1           |           2           |           3           |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |              ID                               |QR|  OP_CODE  |AA|TC|RD|RA|Z |AD|CD|  RT_CODE  |
 *  +-----------------------------------------------+--+-----------+--+--+--+--+--+--+--+-----------+
 *  |                     NUM_Q                     |                    NUM_ANSW                   |
 *  +-----------------------------------------------+-----------------------------------------------+
 *  |                    NUM_AUTH                   |                    NUM_ADDT                   |
 *  +-----------------------------------------------+-----------------------------------------------+
 *  |                                       QUESTIONS [...]                                         |
 *  +-----------------------------------------------------------------------------------------------+
 *  |                                        ANSWERS [...]                                          |
 *  +-----------------------------------------------------------------------------------------------+
 *  |                                       AUTHORITY [...]                                         |
 *  +-----------------------------------------------------------------------------------------------+
 *  |                                      ADDITIONAL [...]                                         |
 *  +-----------------------------------------------------------------------------------------------+
 *
 *  ID      - identification for matching request and response
 *  QR      - request/response
 *  OP_CODE - query type (0 = standart query, 1 = inverse query)
 *  AA      - authoritative answer (1 = authoritative)
 *  TC      - truncated (1 = truncated)
 *  RD      - recursion desired (1 = desired)
 *  RA      - recursion available (1 = available)
 *  Z       -
 *  AD      - authenticated data (1 = authenticated)
 *  CD      - checking disabled (1 = disabled)
 *  RT_CODE - return Code:
 *      0 = No error
 *      1 = Format error
 *      2 = Server failure
 *      3 = Name error
 *      4 = Not implemented
 *      5 = Refused
 *      ...
 *
 *  NUM_Q       - number of total questions
 *  NUM_ANSW    - number of total answers
 *  NUM_AUTH    - number of total authority
 *  NUM_ADDT    - number of total additional
 *  QUESTIONS [...]     - 0 or more Question structures
 *  ANSWERS [...]       - 0 or more Resource Record structures
 *  AUTHORITY [...]     - 0 or more Resource Record structures
 *  ADDITIONAL [...]    - 0 or more Resource Record structures
 *
 */

#define DNS_HEAD_LEN 12

typedef struct dns_header {
    b16 identification;
    b8 qr_opcode_aa_tc_rd;
    b8 ra_z_ad_cd_rtcode;
    b16 questions_number;
    b16 answers_number;
    b16 authorities_number;
    b16 additions_number;
} dns_header;

/*
 *  Question
 *
 *  +-----------------------+-----------------------+
 *  |           0           |           1           |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                                               |
 *  ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ QNAME ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~
 *  |                                               |
 *  +-----------------------------------------------+
 *  |                     TYPE                      |
 *  +-----------------------------------------------+
 *  |                     QCLASS                    |
 *  +-----------------------------------------------+
 *
 *  QNAME - sequence of labels each has Len in octets and followed in octets
 *  TYPE - type of DNS record
 *  QCLASS - class of DNS record
 *
 */

typedef struct rr_question {
    std::string qname;
    b16 type;
    b16 qclass;
} rr_question;

/*
 *  Resource Record
 *
 *  +-----------+-----------+-----------------------+
 *  |           0           |           1           |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  | 1| 1|            NAME_OFFSET                  |
 *  +-----------------------------------------------+
 *  |                     TYPE                      |
 *  +-----------------------------------------------+
 *  |                     CLASS                     |
 *  +-----------------------------------------------+
 *  |                      TTL                      |
 *  +   -   -   -   -   -   -   -   -   -   -   -   +
 *  |                      TTL                      |
 *  +-----------------------------------------------+
 *  |                      LEN                      |
 *  +-----------------------------------------------+
 *  |                     DATA                      |
 *  ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~
 *
 *  NAME_OFFSET   - points to first occurance of NAME in DNS datagram
 *  TYPE    - type of DNS record
 *  CLASS   - class of DNS record
 *  TTL     - time to live
 *  LEN     - length of data
 *  DATA    - received record data
 *
 */

#define RESOURCE_RECORD_NAME_OFFSET 2

#define DNS_CLASS_IN    1

#define DNS_TYPE_A      1
#define DNS_TYPE_AAAA   28
#define DNS_TYPE_CNAME  5
#define DNS_TYPE_MX     15
// #define DNS_TYPE_MS
#define DNS_TYPE_SOA    6
#define DNS_TYPE_TXT    16
// #define DNS_TYPE_SPF


typedef struct rr_record {
    std::string qname;
    b16 type;
    b16 qclass;
    b32 ttl;
    b16 len;
} rr_record;

int sniff(char* dev, int timeout);
void process_packet(const b8 *packet);

/* L1 header processing */
int process_ether_header(const b8 **packet);

/* L2 header processing */
int process_ip4_header(const b8 **packet);
int process_ip6_header(const b8 **packet);

/* L3 header processing */
int process_upd_header(const b8 **packet);
int process_tcp_header(const b8 **packet);

/* L4 header processing */
int process_dns_header(const b8 **packet);

rr_question* get_query_record(const b8 **packet);
rr_record* get_answers_record(const b8 **packet, const b8 *dns_datagram_start);

std::string get_name(const b8 **packet);

#endif //ISA_SNIFFER_H

