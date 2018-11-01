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
typedef struct _spf_record spf_record;

typedef union _rr_data rr_data;
typedef struct _rr_record rr_record;

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

struct _txt_record{
    int length;
    std::string text;
};

/*
 * SPF RDATA
 *
 *  +---------------------------------------------------------------+
 *  |       0       |                ~                              |
 *  +---------------+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |      LEN      |              TXT                              |
 *  +---------------+---------------+---------------+---------------+
 *
 *  TXT - single string of text
 */

// TODO SPF
struct _spf_record{
    std::string text;
};

union _rr_data {
    a_record* A;
    aaaa_record* AAAA;
    cname_record* CNAME;
    mx_record* MX;
    ns_record* NS;
    soa_record* SOA;
    txt_record* TXT;
    spf_record* SPF;
};

typedef enum _rr_tag {
    A,
    AAAA,
    CNAME,
    MX,
    NS,
    SOA,
    TXT,
    SPF,
} rr_tag;

struct _rr_record {
    rr_tag type;
    rr_data data;
};

#endif //ISA_RECORDS_H
