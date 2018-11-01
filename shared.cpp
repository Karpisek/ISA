//
// Created by Miroslav Karpíšek on 25/10/2018.
//

#include "shared.h"

std::vector <rr_record *> global_statistics;

void add_to_statistic(rr_record *record) {

    const rr_record *new_record;
    //std::find_if(global_statistics.begin(), global_statistics.end(), [new_record](const rr_record & record){ return record == new_record;});
}