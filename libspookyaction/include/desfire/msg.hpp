//
// Created by Pietro Saccardi on 03/01/2021.
//

#ifndef DESFIRE_MSG_HPP
#define DESFIRE_MSG_HPP

#include "bits.hpp"
#include "crypto.hpp"
#include "data.hpp"

namespace desfire {
    [[nodiscard]] const char *to_string(bits::cipher_mode comm);
    [[nodiscard]] const char *to_string(bits::status s);
    [[nodiscard]] const char *to_string(error e);
    [[nodiscard]] const char *to_string(cipher_type c);
    [[nodiscard]] const char *to_string(command_code c);
    [[nodiscard]] const char *to_string(file_type t);
    [[nodiscard]] const char *to_string(crypto_operation op);
    [[nodiscard]] const char *to_string(file_security);
}// namespace desfire

#endif//DESFIRE_MSG_HPP
