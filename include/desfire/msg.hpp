//
// Created by Pietro Saccardi on 03/01/2021.
//

#ifndef DESFIRE_MSG_HPP
#define DESFIRE_MSG_HPP

#include <string>
#include "cipher.hpp"
#include "data.hpp"

namespace desfire {
    const char *to_string(comm_mode comm);
    const char *to_string(status s);
    const char *to_string(error e);
    const char *to_string(cipher_type c);
}

#endif //DESFIRE_MSG_HPP
