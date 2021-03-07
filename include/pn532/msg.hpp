//
// Created by Pietro Saccardi on 22/12/2020.
//

#ifndef PN532_MSG_HPP
#define PN532_MSG_HPP

#include "bits.hpp"
#include <string>

namespace pn532 {
    [[nodiscard]] const char *to_string(bits::baudrate s);

    [[nodiscard]] const char *to_string(bits::command c);

    [[nodiscard]] const char *to_string(bits::test t);

    [[nodiscard]] const char *to_string(bits::baudrate_modulation bm);

    [[nodiscard]] const char *to_string(bits::target_type t);

    [[nodiscard]] const char *to_string(bits::error e);

}// namespace pn532

#endif//PN532_MSG_HPP
