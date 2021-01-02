//
// Created by Pietro Saccardi on 22/12/2020.
//

#ifndef PN532_MSG_HPP
#define PN532_MSG_HPP

#include <string>
#include "bits.hpp"

namespace pn532 {
    const char *to_string(bits::baudrate s);

    const char *to_string(bits::command c);

    const char *to_string(bits::test t);

    const char *to_string(bits::baudrate_modulation bm);

    const char *to_string(bits::target_type t);

    const char *to_string(bits::error e);
}

#endif //PN532_MSG_HPP
