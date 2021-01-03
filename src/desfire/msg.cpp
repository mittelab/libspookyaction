//
// Created by Pietro Saccardi on 03/01/2021.
//

#include "desfire/msg.hpp"

namespace desfire {
    const char * to_string(comm_mode comm) {
        switch (comm) {
            case comm_mode::plain:  return "plain";
            case comm_mode::mac:    return "(C)MAC";
            case comm_mode::cipher: return "ciphered";
            default:
                return "UNKNOWN";
        }
    }
}