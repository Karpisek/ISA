//
// Created by Miroslav Karpíšek on 01/11/2018.
//

#ifndef ISA_RECORDS_H
#define ISA_RECORDS_H

#include <string>

typedef struct _a_record a_record;
typedef struct _aaaa_record aaaa_record;
typedef struct _cname_record cname_record;
typedef struct _mx_record mx_record;
typedef struct _ns_record ns_record;
typedef struct _soa_record soa_record;
typedef struct _txt_record txt_record;
typedef struct _dnskey_record dnskey_record;
typedef struct _rsig_record rsig_record;
typedef struct _nsec_record nsec_record;
typedef struct _ds_record ds_record;

typedef union _rr_data rr_data;
typedef struct _rr_answer rr_answer;

/*
 * A RDATA
 *
 *  +---------------------------------------------------------------+
 *  |       0       |       1       |       2       |       3       |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                            ADDRESS                            |
 *  +-------------------------------+-------------------------------+
 *
 *  ADDRESS - 32 bit Internet IPv4 address
 *
 */
#define DNS_TYPE_A      1

struct _a_record{
    std::string ip4;
};

/*
 * AAAA RDATA
 *
 *  +---------------------------------------------------------------+
 *  |                            0 ... 18                           |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                            ADDRESS                            |
 *  +-------------------------------+-------------------------------+
 *
 *  ADDRESS - 128 bit Internet IPv6 address
 *
 */
#define DNS_TYPE_AAAA   28

struct _aaaa_record{
    std::string ip6;
};

/*
 * CNAME RDATA
 *
 *  +---------------------------------------------------------------+
 *  |                               ~                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                             CNAME                             |
 *  +-------------------------------+-------------------------------+
 *
 *  CNAME - again name in labels
 *
 */
#define DNS_TYPE_CNAME  5

struct _cname_record{
    std::string cname;
};

/*
 * MX RDATA
 *
 *  +-------------------------------+
 *  |       0       |       1       |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |              PREF             |
 *  +-------------------------------+
 *  ~ ~ ~ ~ ~ ~ ~EXCHANGE ~ ~ ~ ~ ~ ~
 *  +-------------------------------+
 *
 *  PREFERENCE  - integer specifies the preference in compare to other RR. Lowest value is higher
 *  EXCHANGE    - labels specifies a host willing to act as a mail exchange for the owner
 *
 */
#define DNS_TYPE_MX     15

struct _mx_record{
    int preference;
    std::string exchange;
};

/*
 * NSNAME RDATA
 *
 *  +---------------------------------------------------------------+
 *  |                               ~                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                             NSNAME                            |
 *  +-------------------------------+-------------------------------+
 *
 *  NSNAME - name in labels specifies a host which should be authoritative
 *
 */
#define DNS_TYPE_NS     2

struct _ns_record{
    std::string nsname;
};

/*
 * SOA RDATA
 *
 *  +---------------------------------------------------------------+
 *  |       0       |       1       |       2       |       3       |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ MNNAME~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~
 *  +---------------------------------------------------------------+
 *  ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ RNAME ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~
 *  +---------------------------------------------------------------+
 *  |                             SERIAL                            |
 *  +---------------+---------------+---------------+---------------+
 *  |                            REFRESH                            |
 *  +---------------+---------------+---------------+---------------+
 *  |                             RETRY                             |
 *  +---------------+---------------+---------------+---------------+
 *  |                             EXPIRE                            |
 *  +---------------+---------------+---------------+---------------+
 *  |                            MINIMUM                            |
 *  +---------------+---------------+---------------+---------------+
 *
 *  MNNAME  - domain name of the name server that was the original or primary source of data for this zone.
 *  RNAME   - domain name which specifies the mailbox of the person responsible for this zone.
 *  SERIAL  - version number of the original copy of the zone
 *  REFRESH - time interval before the zone should be refreshed.
 *  RETRY   - time interval that should elapse before a failed refresh should be retried.
 *  EXPIRE  - time value that specifies the upper limit on
 *            the time interval that can elapse before the zone is no
 *            longer authoritative.
 *  MINIMUM - minimum TTL field that should be exported with any RR from this zone.
 *
 */
#define DNS_TYPE_SOA    6

struct _soa_record{
    std::string mnname;
    std::string rname;
    unsigned int serial;
    unsigned int refresh;
    unsigned int retry;
    unsigned int expire;
    unsigned int minimum;
};

/*
 * TXT RDATA
 *
 *  +---------------------------------------------------------------+
 *  |       0       |                ~                              |
 *  +---------------+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |      LEN      |              TXT                              |
 *  +---------------+---------------+---------------+---------------+
 *
 *  LEN - length of the TXT
 *  TXT - characters
 *
 */
#define DNS_TYPE_TXT    16

struct _txt_record{
    int length;
    std::string text;
};

/*
 * DNSKEY RDATA
 *
 *  +---------------------------------------------------------------+
 *  |       0       |       1       |       2       |       3       |
 *  +---------------+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |             FLAGS             |    PROTOCOL   |      ALG      |
 *  +---------------+---------------+---------------+---------------+
 *  ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~PUBLIC_KEY ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~
 *  +---------------------------------------------------------------+
 *
 *  FLAGS       - flags
 *  PROTOCOL    - must be 3
 *  ALG         - used algorithm
 *      0 = RESERVED
 *      1 = RSAMD5
 *      2 = DH
 *      3 = DSA
 *      4 = ECC
 *      5 = RSASHA1
 *    252 = INDIRECT
 *    253 = PRIVATEDNS
 *    254 = PRIVATEOID
 *    255 = RESERVED
 *
 *  PUBLIC_KEY =
 */

#define DNS_TYPE_DNSKEY 48
#define DNSKEY_HASH_LEN(len)    (len - 4)

struct _dnskey_record {
    int flags;
    int protocol;
    int algorithm;
    std::string public_key;
};

/*
 * RSIG RDATA
 *
 *  +---------------------------------------------------------------+
 *  |       0       |       1       |       2       |       3       |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Type Covered           |  Algorithm    |     Labels    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                         Original TTL                          |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                      Signature Expiration                     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                      Signature Inception                      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |            Key Tag            |                               /
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         Signer's Name         /
 *  /                                                               /
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  /                                                               /
 *  /                            Signature                          /
 *  /                                                               /
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *
 */
#define DNS_TYPE_RRSIG 46
#define DNSRSIG_HASH_LEN(len, signers_name_len)     (len - signers_name_len - 18)

struct _rsig_record {
    int type;
    int algorithm;
    int labels;
    int ttl;
    std::string expiration;
    std::string inception;
    int key_tag;
    std::string signers_name;
    std::string signature;
};

/*
 *  NSEC RDATA
 *
 *                       1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  /                      Next Domain Name                         /
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  /                       Type Bit Maps                           /
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
#define DNS_TYPE_NSEC 47
#define NSEC_BITMAP_LEN(len, domain_len)        (len - domain_len)

struct _nsec_record {
    std::string next_domain_name;
    std::string bit_maps;
};

/*
 *  DS RDATA
 *                      1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |           Key Tag             |  Algorithm    |  Digest Type  |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  /                                                               /
 *  /                            Digest                             /
 *  /                                                               /
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
#define DNS_TYPE_DS 43
#define DS_DIGEST_LEN(len)     (len - 4)

struct _ds_record {
    int key_tag;
    int algorithm;
    int digest_type;
    std::string digest;
};



union _rr_data {
    a_record* A;
    aaaa_record* AAAA;
    cname_record* CNAME;
    mx_record* MX;
    ns_record* NS;
    soa_record* SOA;
    txt_record* TXT;
    dnskey_record* DNSKEY;
    rsig_record* RSIG;
    nsec_record* NSEC;
    ds_record* DS;
};

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
 *  ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ DATA~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~
 *  +-----------------------------------------------+
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

struct _rr_answer {
    std::string qname;
    int type;
    int qclass;
    int ttl;
    int len;
    rr_data record;
    int count;
};

bool operator ==(rr_answer answer1, rr_answer answer2);

#endif //ISA_RECORDS_H
