//
// Created by Miroslav Karpíšek on 25/10/2018.
//

#ifndef ISA_SHARED_H
#define ISA_SHARED_H

#include <vector>
#include <string>
#include "records.h"

extern std::vector <rr_record *> global_statistics;

void add_to_statistics(rr_record *record);

#endif //ISA_SHARED_H
