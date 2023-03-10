//
// Created by Pietro Saccardi on 22/12/2020.
//

#ifndef PN532_MSG_HPP
#define PN532_MSG_HPP

#include <pn532/bits.hpp>
#include <string>

/**
 * @defgroup StringConversion String conversion functions
 * Human-readable description of the enumeration.
 * All the returned `const char *` are static strings.
 */

namespace pn532 {
    /**
     * @addtogroup StringConversion
     * @{
     */
    [[nodiscard]] const char *to_string(baudrate s);

    [[nodiscard]] const char *to_string(command_code c);

    [[nodiscard]] const char *to_string(bits::test t);

    [[nodiscard]] const char *to_string(baudrate_modulation bm);

    [[nodiscard]] const char *to_string(target_type t);

    [[nodiscard]] const char *to_string(internal_error_code e);
    /**
     * @}
     */
}// namespace pn532

#endif//PN532_MSG_HPP
