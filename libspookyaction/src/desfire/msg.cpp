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

    const char *to_string(comm_mode mode) {
        switch (mode) {
            case comm_mode::plain:
                return "plain";
            case comm_mode::maced:
                return "maced";
            case comm_mode::ciphered:
                return "ciphered";
            case comm_mode::ciphered_no_crc:
                return "ciphered (no CRC)";
        }
        return "UNKNOWN";
    }

    const char *to_string(app_crypto crypto) {
        switch (crypto) {
            case app_crypto::aes_128:
                return "AES128";
            case app_crypto::iso_3k3des:
                return "3K3DES";
            case app_crypto::legacy_des_2k3des:
                return "DES/2K3DES";
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

    const char *to_string(bits::status s) {
        switch (s) {
            case bits::status::ok:
                return "successful operation";
            case bits::status::no_changes:
                return "no changes done to backup files";
            case bits::status::out_of_eeprom:
                return "insufficient NV memory to complete command";
            case bits::status::illegal_command:
                return "command code not supported";
            case bits::status::integrity_error:
                return "CRC or MAC does not match data";
            case bits::status::no_such_key:
                return "invalid key number specified";
            case bits::status::length_error:
                return "length of command string invalid";
            case bits::status::permission_denied:
                return "current configuration/status does not allow command";
            case bits::status::parameter_error:
                return "value of the parameter(s) invalid";
            case bits::status::app_not_found:
                return "requested AID not present on PICC";
            case bits::status::app_integrity_error:
                return "unrecoverable error within application";
            case bits::status::authentication_error:
                return "current authentication status does not allow the requested command";
            case bits::status::additional_frame:
                return "additional data frame to be sent";
            case bits::status::boundary_error:
                return "attempt to read/write beyond limits";
            case bits::status::picc_integrity_error:
                return "unrecoverable error within PICC";
            case bits::status::command_aborted:
                return "previous command was not fully completed";
            case bits::status::picc_disabled_error:
                return "PICC was disabled by unrecoverable error";
            case bits::status::count_error:
                return "cannot create more than 28 apps";
            case bits::status::duplicate_error:
                return "cannot create duplicate files or apps";
            case bits::status::eeprom_error:
                return "could not complete NV-write operation";
            case bits::status::file_not_found:
                return "specified file number does not exist";
            case bits::status::file_integrity_error:
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
                return to_string(static_cast<bits::status>(e));
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

    const char *to_string(bits::command_code c) {
        switch (c) {
            case bits::command_code::authenticate_legacy:
                return "authenticate_legacy";
            case bits::command_code::change_key_settings:
                return "change_key_settings";
            case bits::command_code::get_key_settings:
                return "get_key_settings";
            case bits::command_code::change_key:
                return "change_key";
            case bits::command_code::get_key_version:
                return "get_key_version";
            case bits::command_code::create_application:
                return "create_application";
            case bits::command_code::delete_application:
                return "delete_application";
            case bits::command_code::get_application_ids:
                return "get_application_ids";
            case bits::command_code::select_application:
                return "select_application";
            case bits::command_code::format_picc:
                return "format_picc";
            case bits::command_code::get_version:
                return "get_version";
            case bits::command_code::get_file_ids:
                return "get_file_ids";
            case bits::command_code::get_file_settings:
                return "get_file_settings";
            case bits::command_code::change_file_settings:
                return "change_file_settings";
            case bits::command_code::create_std_data_file:
                return "create_std_data_file";
            case bits::command_code::create_backup_data_file:
                return "create_backup_data_file";
            case bits::command_code::create_value_file:
                return "create_value_file";
            case bits::command_code::create_linear_record_file:
                return "create_linear_record_file";
            case bits::command_code::create_cyclic_record_file:
                return "create_cyclic_record_file";
            case bits::command_code::delete_file:
                return "delete_file";
            case bits::command_code::read_data:
                return "read_data";
            case bits::command_code::write_data:
                return "write_data";
            case bits::command_code::get_value:
                return "get_value";
            case bits::command_code::credit:
                return "credit";
            case bits::command_code::debit:
                return "debit";
            case bits::command_code::limited_credit:
                return "limited_credit";
            case bits::command_code::write_record:
                return "write_record";
            case bits::command_code::read_records:
                return "read_records";
            case bits::command_code::clear_record_file:
                return "clear_record_file";
            case bits::command_code::commit_transaction:
                return "commit_transaction";
            case bits::command_code::abort_transaction:
                return "abort_transaction";
            case bits::command_code::additional_frame:
                return "additional_frame";
            case bits::command_code::authenticate_iso:
                return "authenticate_iso";
            case bits::command_code::authenticate_aes:
                return "authenticate_aes";
            case bits::command_code::free_mem:
                return "free_mem";
            case bits::command_code::get_df_names:
                return "get_df_names";
            case bits::command_code::get_card_uid:
                return "get_card_uid";
            case bits::command_code::get_iso_file_ids:
                return "get_iso_file_ids";
            case bits::command_code::set_configuration:
                return "set_configuration";
        }
        return "UNKNOWN";
    }
}// namespace desfire