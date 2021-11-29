//
// Created by Pietro Saccardi on 03/01/2021.
//

#include <desfire/msg.hpp>

namespace desfire {
    const char *to_string(file_security security) {
        switch (security) {
            case file_security::none:
                return "none";
            case file_security::authenticated:
                return "authenticated";
            case file_security::encrypted:
                return "encrypted";
        }
        return "UNKNOWN";
    }

    const char *to_string(cipher_mode mode) {
        switch (mode) {
            case cipher_mode::plain:
                return "plain";
            case cipher_mode::maced:
                return "maced";
            case cipher_mode::ciphered:
                return "ciphered";
            case cipher_mode::ciphered_no_crc:
                return "ciphered (no CRC)";
        }
        return "UNKNOWN";
    }

    const char *to_string(crypto_operation op) {
        switch (op) {
            case crypto_operation::encrypt:
                return "encrypt";
            case crypto_operation::decrypt:
                return "decrypt";
            case crypto_operation::mac:
                return "mac";
        }
        return "UNKNOWN";
    }

    const char *to_string(status s) {
        switch (s) {
            case status::ok:
                return "successful operation";
            case status::no_changes:
                return "no changes done to backup files";
            case status::out_of_eeprom:
                return "insufficient NV memory to complete command";
            case status::illegal_command:
                return "command code not supported";
            case status::integrity_error:
                return "CRC or MAC does not match data";
            case status::no_such_key:
                return "invalid key number specified";
            case status::length_error:
                return "length of command string invalid";
            case status::permission_denied:
                return "current configuration/status does not allow command";
            case status::parameter_error:
                return "value of the parameter(s) invalid";
            case status::app_not_found:
                return "requested AID not present on PICC";
            case status::app_integrity_error:
                return "unrecoverable error within application";
            case status::authentication_error:
                return "current authentication status does not allow the requested command";
            case status::additional_frame:
                return "additional data frame to be sent";
            case status::boundary_error:
                return "attempt to read/write beyond limits";
            case status::picc_integrity_error:
                return "unrecoverable error within PICC";
            case status::command_aborted:
                return "previous command was not fully completed";
            case status::picc_disabled_error:
                return "PICC was disabled by unrecoverable error";
            case status::count_error:
                return "cannot create more than 28 apps";
            case status::duplicate_error:
                return "cannot create duplicate files or apps";
            case status::eeprom_error:
                return "could not complete NV-write operation";
            case status::file_not_found:
                return "specified file number does not exist";
            case status::file_integrity_error:
                return "unrecoverable error within file";
        }
        return "UNKNOWN";
    }

    const char *to_string(error e) {
        switch (e) {
            case error::controller_error:
                return "controller error";
            case error::malformed:
                return "malformed frame";
            case error::crypto_error:
                return "crypto error";
            default:
                return to_string(static_cast<status>(e));
        }
    }

    const char *to_string(cipher_type c) {
        switch (c) {
            case cipher_type::none:
                return "none";
            case cipher_type::des:
                return "DES";
            case cipher_type::des3_2k:
                return "2K3DES";
            case cipher_type::des3_3k:
                return "3K3DES";
            case cipher_type::aes128:
                return "AES128";
        }
        return "UNKNOWN";
    }

    const char *to_string(file_type t) {
        switch (t) {
            case file_type::standard:
                return "standard data file";
            case file_type::backup:
                return "backup data file";
            case file_type::value:
                return "value file";
            case file_type::linear_record:
                return "linear record file";
            case file_type::cyclic_record:
                return "cyclic record file";
        }
        return "UNKNOWN";
    }

    const char *to_string(command_code c) {
        switch (c) {
            case command_code::authenticate_legacy:
                return "authenticate_legacy";
            case command_code::change_key_settings:
                return "change_key_settings";
            case command_code::get_key_settings:
                return "get_key_settings";
            case command_code::change_key:
                return "change_key";
            case command_code::get_key_version:
                return "get_key_version";
            case command_code::create_application:
                return "create_application";
            case command_code::delete_application:
                return "delete_application";
            case command_code::get_application_ids:
                return "get_application_ids";
            case command_code::select_application:
                return "select_application";
            case command_code::format_picc:
                return "format_picc";
            case command_code::get_version:
                return "get_version";
            case command_code::get_file_ids:
                return "get_file_ids";
            case command_code::get_file_settings:
                return "get_file_settings";
            case command_code::change_file_settings:
                return "change_file_settings";
            case command_code::create_std_data_file:
                return "create_std_data_file";
            case command_code::create_backup_data_file:
                return "create_backup_data_file";
            case command_code::create_value_file:
                return "create_value_file";
            case command_code::create_linear_record_file:
                return "create_linear_record_file";
            case command_code::create_cyclic_record_file:
                return "create_cyclic_record_file";
            case command_code::delete_file:
                return "delete_file";
            case command_code::read_data:
                return "read_data";
            case command_code::write_data:
                return "write_data";
            case command_code::get_value:
                return "get_value";
            case command_code::credit:
                return "credit";
            case command_code::debit:
                return "debit";
            case command_code::limited_credit:
                return "limited_credit";
            case command_code::write_record:
                return "write_record";
            case command_code::read_records:
                return "read_records";
            case command_code::clear_record_file:
                return "clear_record_file";
            case command_code::commit_transaction:
                return "commit_transaction";
            case command_code::abort_transaction:
                return "abort_transaction";
            case command_code::additional_frame:
                return "additional_frame";
            case command_code::authenticate_iso:
                return "authenticate_iso";
            case command_code::authenticate_aes:
                return "authenticate_aes";
            case command_code::free_mem:
                return "free_mem";
            case command_code::get_df_names:
                return "get_df_names";
            case command_code::get_card_uid:
                return "get_card_uid";
            case command_code::get_iso_file_ids:
                return "get_iso_file_ids";
            case command_code::set_configuration:
                return "set_configuration";
        }
        return "UNKNOWN";
    }
}// namespace desfire