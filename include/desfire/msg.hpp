//
// Created by Pietro Saccardi on 03/01/2021.
//

#ifndef DESFIRE_MSG_HPP
#define DESFIRE_MSG_HPP

#include "bits.hpp"
#include "data.hpp"

namespace desfire {
    const char *to_string(bits::comm_mode comm);
    const char *to_string(bits::status s);
    const char *to_string(error e);
    const char *to_string(cipher_type c);
    const char *to_string(command_code c);
    const char *to_string(file_type t);
    const char *to_string(crypto_mode mode);
}

#endif //DESFIRE_MSG_HPP
