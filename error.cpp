//
// Created by Miroslav Karpíšek on 06/10/2018.
//

#include "error.h"

void raise(int code, std::string message) {

    std::cerr << "ERROR " << code << " : " << message << std::endl;
    exit(code);
}
