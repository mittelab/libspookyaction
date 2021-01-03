//
// Created by Pietro Saccardi on 02/01/2021.
//

#ifndef DESFIRE_BITS_HPP
#define DESFIRE_BITS_HPP

#include <cstdint>
#include <array>

namespace desfire {
    namespace bits {
        enum struct status : std::uint8_t {
            ok = 0x00,
            no_changes = 0x0c,
            out_of_eeprom = 0x0e,
            illegal_command = 0x1c,
            integrity_error = 0x1e,
            no_such_key = 0x40,
            length_error = 0x7e,
            permission_denied = 0x9d,
            parameter_error = 0x9e,
            app_not_found = 0xa0,
            app_integrity_error = 0xa1,
            authentication_error = 0xae,
            additional_frame = 0xaf,
            boundary_error = 0xbe,
            picc_integrity_error = 0xc1,
            command_aborted = 0xca,
            picc_disabled_error = 0xcd,
            count_error = 0xce,
            diplicate_error = 0xde,
            eeprom_error = 0xee,
            file_not_found = 0xf0,
            file_integrity_error = 0xf1
        };

    }
}

#endif //DESFIRE_BITS_HPP
