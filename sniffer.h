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

#include <signal.h>
#include <unistd.h>
#include <cstdio>
#include <iostream>
#include <pcap.h>
#include <ctime>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <string>
#include <sstream>

#include "error.h"
#include "shared.h"
#include "string.h"
#include "records.h"
#include "user_signal.h"

typedef struct _rr_question rr_question;
typedef struct _sniff_handler sniff_handler;

/* Typedefs for better readability */
typedef unsigned int b32;
typedef unsigned short b16;
typedef unsigned char b8;

#define ETHERNET_HEADER_LEN 14
#define MAC_ADDR_LEN 6
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

#define IP4_ADDR_LEN 4
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

/* IPv6 header
 *  +---------------------------------------------------------------+
 *  |       0       |       1       |       2       |       3       |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  VER  |     CLASS     |              FLOW                     |
 *  +---------------+---------------+---------------+---------------+
 *  |            PAYLOAD            |      NEXT     |      HOP      |
 *  +-------------------------------+---------------+---------------+
 *  |      TTL      |      PRT      |             HSUM              |
 *  +---------------+---------------+-------------------------------+
 *  |                              SRC                              |
 *  + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
 *  |                              SRC                              |
 *  + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
 *  |                              SRC                              |
 *  + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
 *  |                              SRC                              |
 *  +---------------------------------------------------------------+
 *  |                              DST                              |
 *  + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
 *  |                              DST                              |
 *  + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
 *  |                              DST                              |
 *  + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
 *  |                              DST                              |
 *  +---------------------------------------------------------------+
 *
 *  VER     - version (constant 0110)
 *  CLASS   - traffic class
 *  FLOW    - hint for routers
 *  PAYLOAD - length of payload
 *  NEXT    - type of next header (may be extension)
 *  HOP     - hop limit (like TTL in ip4)
 *  SRC     - 128bit source address
 *  DST     - 128bit destination address
 */

#define IP6_HEAD_LEN 40
#define IP6_ADDR_LEN 16

typedef struct ip6_protocol {
    b32 ver_class_flow;
    b16 payload;
    b8  next;
    b8  hop;
    b8  src[IP6_ADDR_LEN];
    b8  dst[IP6_ADDR_LEN];
} ip6_protocol;

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

typedef struct udp_protocol{
    b16 src;
    b16 dst;
    b16 len;
    b16 sum;
} udp_protocol;

/* TCP header
 *  +---------------------------------------------------------------+
 *  |       0       |       1       |       2       |       3       |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |              SRC              |              DST              |
 *  +-------------------------------+-------------------------------+
 *  |                            SEQ_NUM                            |
 *  +-------------------------------+-------------------------------+
 *  |                            ACK_NUM                            |
 *  +---------------+---------------+-------------------------------+
 *  | OFSET |0|0|0|N|C|E|U|A|P|R|S|F|           WIN_SIZE            |
 *  +---------------+---------------+-------------------------------+
 *  |           CHECKSUM            |            URGENT             |
 *  +---------------+---------------+-------------------------------+
 *  |                          OPTIONS [...]                        |
 *  +---------------------------------------------------------------+
 *  SRC - source port
 *  DST - destination port
 *  SEQ_NUM - Sequence number
 *  ACK_NUM - Acknowledgment number
 *  OFSET   - Data offset in 32-bit words
 *  WIN_SIZE - window size
 */

#define TCP_HEAD_LEN(offset_n)    ((offset_n >> 4) * 4)

typedef struct tcp_protocol{
    b16 src;
    b16 dst;
    b32 seq;
    b32 ack;
    b8 offset_n;
    b8 flags;
    b16 window;
    b16 checksum;
    b16 urgent;
} tcp_protocol;

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

#define DNS_HEAD_LEN(tcp_flag)      (tcp_flag ? 14 : 12)

typedef struct raw_dns_header {
    b16 identification;
    b8 qr_opcode_aa_tc_rd;
    b8 ra_z_ad_cd_rtcode;
    b16 questions_number;
    b16 answers_number;
    b16 authorities_number;
    b16 additions_number;
}raw_dns_header;

typedef struct dns_header {
    raw_dns_header* raw_header;
    int identification;
    int questions_number;
    int answers_number;
    int authorities_number;
    int additions_number;
    int length;     /* undefined on UDP, works only with tcp*/
} dns_header;

typedef struct dns_body {
    rr_question** questions;
    rr_answer** answers;
} dns_body;

typedef struct dns_protocol {
    dns_header* header;
    dns_body* body;
} dns_protocol;

/*
 *  Question
 *
 *  +-----------------------+-----------------------+
 *  |           0           |           1           |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ QNAME ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~
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

struct _rr_question {
    std::string qname;
    int type;
    int qclass;
};

struct _sniff_handler {
    pcap_t *session;
    b32 ip_address;
    b32 netmask;
    char *dev;
};

sniff_handler *init_interface(char *dev);
sniff_handler *init_file(char *filename);

int sniff(sniff_handler *handler);
void process_packet(u_char *args, const struct pcap_pkthdr *header, const b8 *packet);

/* L2 header processing */
ethernet_protocol* process_ether_header(const b8 **packet);

/* L3 header processing */
ip4_protocol* process_ip4_header(const b8 *packet);
ip6_protocol* process_ip6_header(const b8 *packet);

/* L4 header processing */
udp_protocol* process_upd_header(const b8 *packet);
tcp_protocol* process_tcp_header(const b8 *packet);

/* L5 header processing */
dns_protocol* process_dns(const b8 *packet, bool tcp_flag);
dns_header* get_dns_header(const b8 *packet, bool tcp_flag);
dns_body* get_dns_body(const b8 **packet, dns_header *header);

rr_question* get_query_record(const b8 **packet, raw_dns_header *header);
rr_answer* get_answers_record(const b8 **packet, raw_dns_header *header);

std::string get_name(const b8 **packet, raw_dns_header *header, int *length);

/* records parsers */
rr_data get_a_record(const b8 *packet);
rr_data get_aaaa_record(const b8 *packet);
rr_data get_cname_record(const b8 *packet, raw_dns_header *header);
rr_data get_mx_record(const b8 *packet, raw_dns_header *header);
rr_data get_ns_record(const b8 *packet, raw_dns_header *header);
rr_data get_soa_record(const b8 *packet, raw_dns_header *header);
rr_data get_txt_record(const b8 *packet);
rr_data get_dnskey_record(const b8 *packet, const rr_answer *answer);
rr_data get_rsig_record(const b8 *packet, const rr_answer *answer);

#endif //ISA_SNIFFER_H

