//
// Created by Pietro Saccardi on 22/12/2020.
//

#ifndef APERTURAPORTA_MSG_H
#define APERTURAPORTA_MSG_H

#include <string>
#include "bits.hpp"

namespace pn532 {
    const char *to_string(bits::speed s);
    const char *to_string(bits::command c);
    const char *to_string(bits::test t);
    const char *to_string(bits::baudrate_modulation bm);
    const char *to_string(bits::target_type t);
    const char *to_string(bits::error e);
}

#endif //APERTURAPORTA_MSG_H
