//
// Created by Miroslav Karpíšek on 25/10/2018.
//

#include "shared.h"

std::vector <rr_record *> global_statistics;

void add_to_statistics(rr_record *new_record) {
    for(auto record : global_statistics) {
        if(*record == *new_record) {
            /* increment counter found the same record */
            record->count++;
            return;
        }
    }

    /* no statistics so far found */
    global_statistics.push_back(new_record);
}