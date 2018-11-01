//
// Created by Miroslav Karpíšek on 01/11/2018.
//

#include "records.h"

bool operator==(rr_record record1, rr_record record2) {

    if(record1.type != record2.type) {
        return false;
    }

    switch (record1.type) {
        case A:
            return record1.data.A->ip4 == record2.data.A->ip4;

        case AAAA:
            return record1.data.AAAA->ip6 == record2.data.AAAA->ip6;

        case CNAME:
            return record1.data.CNAME->cname == record2.data.CNAME->cname;

        case MX:
            return record1.data.MX->preference == record2.data.MX->preference && record1.data.MX->exchange == record2.data.MX->exchange;

        case NS:
            return record1.data.NS->nsname == record2.data.NS->nsname;

        case SOA:
            return record1.data.SOA->mnname == record2.data.SOA->mnname;

        case TXT:

        default:
            break;
    }

    return false;
}