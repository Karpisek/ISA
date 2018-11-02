//
// Created by Miroslav Karpíšek on 01/11/2018.
//

#include "records.h"

bool operator==(rr_answer answer1, rr_answer answer2) {

    if(answer1.type != answer2.type) {
        return false;
    }

    if(answer1.qname != answer2.qname) {
        return false;
    }

    switch (answer1.type) {
        case DNS_TYPE_A:
            return answer1.record.A->ip4 == answer2.record.A->ip4;

        case DNS_TYPE_AAAA:
            return answer1.record.AAAA->ip6 == answer2.record.AAAA->ip6;

        case DNS_TYPE_CNAME:
            return answer1.record.CNAME->cname == answer2.record.CNAME->cname;

        case DNS_TYPE_MX:
            return
            answer1.record.MX->preference == answer2.record.MX->preference &&
            answer1.record.MX->exchange == answer2.record.MX->exchange;

        case DNS_TYPE_NS:
            return answer1.record.NS->nsname == answer2.record.NS->nsname;

        case DNS_TYPE_SOA:
            return
            answer1.record.SOA->mnname == answer2.record.SOA->mnname &&
            answer1.record.SOA->rname == answer2.record.SOA->rname &&
            answer1.record.SOA->minimum == answer2.record.SOA->minimum &&
            answer1.record.SOA->expire == answer2.record.SOA->expire &&
            answer1.record.SOA->retry == answer2.record.SOA->retry &&
            answer1.record.SOA->refresh == answer2.record.SOA->refresh &&
            answer1.record.SOA->serial == answer2.record.SOA->serial;

        case DNS_TYPE_TXT:
            return
            answer1.record.TXT->length == answer2.record.TXT->length &&
            answer1.record.TXT->text == answer2.record.TXT->text;

        default:
            break;
    }

    return false;
}