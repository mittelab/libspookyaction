//
// Created by Pietro Saccardi on 02/01/2021.
//

#ifndef DESFIRE_BITS_HPP
#define DESFIRE_BITS_HPP

#include <cstdint>
#include <array>

namespace desfire {
    namespace bits {

        enum struct comm_mode {
            plain,
            mac,
            cipher
        };

        enum struct command_code : std::uint8_t {
            authenticate_legacy = 0x0a,
            change_key_settings = 0x54,
            get_key_settings = 0x45,
            change_key = 0xc4,
            get_key_version = 0x64,
            create_application = 0xca,
            delete_application = 0xda,
            get_application_ids = 0x6a,
            select_application = 0x5a,
            format_picc = 0xfc,
            get_version = 0x60,
            get_file_ids = 0x6f,
            get_file_settings = 0xf5,
            change_file_settings = 0x5f,
            create_std_data_file = 0xcd,
            create_backup_data_file = 0xcb,
            create_value_file = 0xcc,
            create_linear_record_file = 0xc1,
            create_cyclic_record_file = 0xc0,
            delete_file = 0xdf,
            read_data = 0xbd,
            write_data = 0x3d,
            get_value = 0x6c,
            credit = 0x0c,
            debit = 0xdc,
            limited_credit = 0x1c,
            write_record = 0x3b,
            read_records = 0xbb,
            clear_record_file = 0xeb,
            commit_transaction = 0xc7,
            abort_transaction = 0xa7,
            additional_frame = 0xaf,
            authenticate_iso = 0x1a,
            authenticate_aes = 0xaa,
            free_mem = 0x6e,
            get_df_names = 0x6d,
            get_card_uid = 0x51,
            get_iso_file_ids = 0x61,
            set_configuration = 0x5c
        };

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

        static constexpr std::uint8_t max_keys_per_app = 14;
        static constexpr unsigned app_change_keys_right_shift = 4;
        static constexpr std::uint8_t app_change_keys_right_same_flag = 0x0e << app_change_keys_right_shift;
        static constexpr std::uint8_t app_change_keys_right_freeze_flag = 0x0f << app_change_keys_right_shift;
        static constexpr std::uint8_t app_change_config_allowed_flag = 1 << 3;
        static constexpr std::uint8_t app_create_delete_without_master_key_flag = 1 << 2;
        static constexpr std::uint8_t app_list_without_master_key_flag = 1 << 1;
        static constexpr std::uint8_t app_changeable_master_key_flag = 1 << 0;

        static constexpr unsigned app_id_length = 3;

        enum struct app_crypto : std::uint8_t {
            legacy_des_2k3des = 0x00,
            iso_3k3des = 0x40,
            aes_128 = 0x80
        };

        /**
         * @note The numeric assignment is only needed for CTTI (that is later used in ::mlab::any)
         */
        enum struct cipher_type : std::uint8_t {
            none = 0x0,
            des = 0x1,
            des3_2k = 0x2,
            des3_3k = 0x3,
            aes128 = 0x4
        };

        static constexpr std::uint8_t max_keys_mask = 0xf;

        static_assert((max_keys_per_app & max_keys_mask) == max_keys_per_app,
                "There's no spec for this max key mask, so let's make sure at least it works.");

        static constexpr std::uint8_t storage_size_approx_bit = 0b1;
        static constexpr unsigned storage_size_exponent_shift = 1;
    }
}

#endif //DESFIRE_BITS_HPP
