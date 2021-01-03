//
// Created by Pietro Saccardi on 03/01/2021.
//

#include "desfire/msg.hpp"

namespace desfire {
    const char *to_string(comm_mode comm) {
        switch (comm) {
            case comm_mode::plain:  return "plain";
            case comm_mode::mac:    return "(C)MAC";
            case comm_mode::cipher: return "ciphered";
            default:
                return "UNKNOWN";
        }
    }

    const char *to_string(bits::status s) {
        switch (s) {
            case bits::status::ok:                   return "successful operation";
            case bits::status::no_changes:           return "no changes done to backup files";
            case bits::status::out_of_eeprom:        return "insufficient NV memory to complete command";
            case bits::status::illegal_command:      return "command code not supported";
            case bits::status::integrity_error:      return "CRC or MAC does not match data";
            case bits::status::no_such_key:          return "invalid key number specified";
            case bits::status::length_error:         return "length of command string invalid";
            case bits::status::permission_denied:    return "current configuration/status does not allow command";
            case bits::status::parameter_error:      return "value of the parameter(s) invalid";
            case bits::status::app_not_found:        return "requested AID not present on PICC";
            case bits::status::app_integrity_error:  return "unrecoverable error within application";
            case bits::status::authentication_error: return "current authentication status does not allow the requested command";
            case bits::status::additional_frame:     return "additional data frame to be sent";
            case bits::status::boundary_error:       return "attempt to read/write beyond limits";
            case bits::status::picc_integrity_error: return "unrecoverable error within PICC";
            case bits::status::command_aborted:      return "previous command was not fully completed";
            case bits::status::picc_disabled_error:  return "PICC was disabled by unrecoverable error";
            case bits::status::count_error:          return "cannot create more than 28 apps";
            case bits::status::diplicate_error:      return "cannot create duplicate files or apps";
            case bits::status::eeprom_error:         return "could not complete NV-write operation";
            case bits::status::file_not_found:       return "specified file number does not exist";
            case bits::status::file_integrity_error: return "unrecoverable error within file";
            default:
                return "UNKNOWN";
        }
    }
}