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

    const char *to_string(status s) {
        switch (s) {
            case status::ok:                   return "successful operation";
            case status::no_changes:           return "no changes done to backup files";
            case status::out_of_eeprom:        return "insufficient NV memory to complete command";
            case status::illegal_command:      return "command code not supported";
            case status::integrity_error:      return "CRC or MAC does not match data";
            case status::no_such_key:          return "invalid key number specified";
            case status::length_error:         return "length of command string invalid";
            case status::permission_denied:    return "current configuration/status does not allow command";
            case status::parameter_error:      return "value of the parameter(s) invalid";
            case status::app_not_found:        return "requested AID not present on PICC";
            case status::app_integrity_error:  return "unrecoverable error within application";
            case status::authentication_error: return "current authentication status does not allow the requested command";
            case status::additional_frame:     return "additional data frame to be sent";
            case status::boundary_error:       return "attempt to read/write beyond limits";
            case status::picc_integrity_error: return "unrecoverable error within PICC";
            case status::command_aborted:      return "previous command was not fully completed";
            case status::picc_disabled_error:  return "PICC was disabled by unrecoverable error";
            case status::count_error:          return "cannot create more than 28 apps";
            case status::diplicate_error:      return "cannot create duplicate files or apps";
            case status::eeprom_error:         return "could not complete NV-write operation";
            case status::file_not_found:       return "specified file number does not exist";
            case status::file_integrity_error: return "unrecoverable error within file";
            default:
                return "UNKNOWN";
        }
    }

    const char *to_string(error e) {
        switch (e) {
            case error::controller_error: return "controller error";
            case error::malformed:        return "malformed frame";
            case error::crypto_error:     return "cryto error";
            default:
                return to_string(static_cast<status>(e));
        }
    }
}