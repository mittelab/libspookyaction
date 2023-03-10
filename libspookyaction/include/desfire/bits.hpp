//
// Created by Pietro Saccardi on 02/01/2021.
//

#ifndef DESFIRE_BITS_HPP
#define DESFIRE_BITS_HPP

#include <array>
#include <cstdint>
#include <desfire/log.h>

/**
 * Structures related to Desfire cards.
 */
namespace desfire {

    /**
     * @brief Type of protection applied to transmitted data.
     * This describes how the command data and response data is transmitted to the card.
     * Different methods, ciphers and security settings imply different communication modes. For the vast majority
     * of the commands, this is already pre-determined.
     */
    enum struct comm_mode : std::uint8_t {
        plain = 0b00,   ///< Plain text: data is not encrypted and can be read by intercepting the communication.
        maced = 0b01,   ///< Authenticated: data has a MAC appended to it ensuring its authenticity, but can be intercepted.
        ciphered = 0b11,///< Full encryption: data is authenticated and encrypted and cannot be read if the communication is intercepted.
        ciphered_no_crc ///< Reserved for internal usage. This is a special mode used only within e.g. @ref tag::authenticate.
    };

    /**
     * Returns the most secure communication mode between @p l and @p r.
     * @param l Communication mode
     * @param r Communication mode
     * @return The most secure of the two, where @ref comm_mode::maced beats @ref comm_mode::plain and @ref comm_mode::ciphered beats
     *  @ref comm_mode::maced.
     */
    [[nodiscard]] constexpr comm_mode comm_mode_most_secure(comm_mode l, comm_mode r);

    /**
     * @brief Security level to apply to a file.
     * This affects how the file data is transmitted over the channel, and is a subset mapping of @ref desfire::comm_mode.
     * @see tag::create_file
     */
    enum struct file_security : std::uint8_t {
        none = static_cast<std::uint8_t>(comm_mode::plain),         ///< No security, corresponds to @ref comm_mode::plain
        authenticated = static_cast<std::uint8_t>(comm_mode::maced),///< MAC is appended to the data, corresponds to @ref comm_mode::maced
        encrypted = static_cast<std::uint8_t>(comm_mode::ciphered)  ///< Full encryption, corresponds to @ref comm_mode::ciphered.
    };

    /**
     * @brief An enumeration of the supported cipher types.
     * @note The numeric assignment is only needed for CTTI (that is later used in `mlab::any`).
     */
    enum struct cipher_type : std::uint8_t {
        none = 0x0,   ///< No cipher. This is a value only used to mark uninitialized values.
        des = 0x1,    ///< Classical DES, **insecure**.
        des3_2k = 0x2,///< 2TDEA (2K3DES), **insecure**.
        des3_3k = 0x3,///< Triple DES, **insecure**.
        aes128 = 0x4  ///< AES128. This is what you should be using.
    };

    /**
     * @brief Cryptographic settings used to encrypt app data.
     * This cannot be changed, an app must be created on one of those. This is a subset of @ref desfire::cipher_type, since DES and 2K3DES are aggregated
     * in the same mode.
     * @warning It's (at least) 2023, you should really only be using @ref aes_128. However, since the default app keys are always DES,
     *  we support this whole circus.
     * @see tag::create_app
     */
    enum struct app_crypto : std::uint8_t {
        legacy_des_2k3des = 0x00,///< Classical DES and 2K3DES (2TDEA). **Insecure, do not use in new applications.**
        iso_3k3des = 0x40,       ///< Triple DES, (3DES). **Insecure, do not use in new applications.**
        aes_128 = 0x80           ///< AES128 encryption. This is what you should be using.
    };

    /**
     * @brief Converts the @ref cipher_type into its corresponding @ref app_crypto value.
     * @param c Cipher type
     * @return Basically simply collapses 2K3DES, DES and `none` ciphers into @ref app_crypto::legacy_des_2k3des.
     */
    [[nodiscard]] constexpr app_crypto app_crypto_from_cipher(cipher_type c);

    /**
     * @brief Types of files supported by the Desfire card.
     * @see tag::create_file
     */
    enum struct file_type : std::uint8_t {
        standard = 0x00,     ///< A regular, fixed-length, binary data file.
        backup = 0x01,       ///< Same as @ref standard, but requires a @ref tag::commit_transaction call to permanently save the data
        value = 0x02,        ///< A value file, i.e. a single 32-bit integer, to which @ref tag::credit and @ref tag::debit can apply.
        linear_record = 0x03,///< A set of fixed-length binary records, where adding a record always appends at the end.
        cyclic_record = 0x04 ///< A constant sized set of fixed-length binary records, where appending past the tail overwrites the first record written.
    };

#ifndef DOXYGEN_SHOULD_SKIP_THIS
    namespace bits {

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

        [[nodiscard]] constexpr command_code auth_command(cipher_type t);

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
            duplicate_error = 0xde,
            eeprom_error = 0xee,
            file_not_found = 0xf0,
            file_integrity_error = 0xf1
        };

        static constexpr std::size_t max_packet_length = 60;

        static constexpr std::uint8_t max_keys_per_app = 14;
        static constexpr unsigned app_change_keys_right_shift = 4;
        static constexpr std::uint8_t app_change_keys_right_same = 0x0e;
        static constexpr std::uint8_t app_change_keys_right_none = 0x0f;
        static constexpr std::uint8_t app_change_config_allowed_flag = 1 << 3;
        static constexpr std::uint8_t app_create_delete_without_master_key_flag = 1 << 2;
        static constexpr std::uint8_t app_list_without_master_key_flag = 1 << 1;
        static constexpr std::uint8_t app_changeable_master_key_flag = 1 << 0;

        static constexpr unsigned app_id_length = 3;

        static constexpr std::uint8_t max_keys_mask = 0xf;

        static_assert((max_keys_per_app & max_keys_mask) == max_keys_per_app,
                      "There's no spec for this max key mask, so let's make sure at least it works.");

        static constexpr std::uint8_t storage_size_approx_bit = 0b1;
        static constexpr unsigned storage_size_exponent_shift = 1;

        static constexpr unsigned file_access_rights_change_shift = 0;
        static constexpr unsigned file_access_rights_read_write_shift = 4;
        static constexpr unsigned file_access_rights_write_shift = 8;
        static constexpr unsigned file_access_rights_read_shift = 12;

        static constexpr std::uint8_t max_standard_data_file_id = 0xf;
        static constexpr std::uint8_t max_backup_data_file_id = 0x7;
        static constexpr std::uint8_t max_value_file_id = 0x7;
        static constexpr std::uint8_t max_record_file_id = 0x7;

        static constexpr std::uint8_t config_flag_enable_random_uid = 0x02;
        static constexpr std::uint8_t config_flag_disable_format = 0x01;

        static constexpr std::uint8_t crypto_cmac_xor_byte_3k3des = 0x1b;
        static constexpr std::uint8_t crypto_cmac_xor_byte_2k3des = 0x1b;
        static constexpr std::uint8_t crypto_cmac_xor_byte_des = 0x1b;
        static constexpr std::uint8_t crypto_cmac_xor_byte_aes = 0x87;

        static constexpr std::array<std::uint8_t, 1> kdf_aes_const = {0x01};
        static constexpr std::array<std::uint8_t, 3> kdf_3k3des_const = {0x31, 0x32, 0x33};
        static constexpr std::array<std::uint8_t, 2> kdf_2k3des_const = {0x21, 0x22};
        static constexpr std::array<std::uint8_t, 1> kdf_des_const = {0x11};
    }// namespace bits
#endif

}// namespace desfire

namespace desfire {
    constexpr comm_mode comm_mode_most_secure(comm_mode l, comm_mode r) {
        if (l == comm_mode::ciphered or r == comm_mode::ciphered) {
            return comm_mode::ciphered;
        } else if (l == comm_mode::ciphered_no_crc or r == comm_mode::ciphered_no_crc) {
            return comm_mode::ciphered_no_crc;
        } else if (l == comm_mode::maced or r == comm_mode::maced) {
            return comm_mode::maced;
        } else {
            return comm_mode::plain;
        }
    }

    constexpr app_crypto app_crypto_from_cipher(cipher_type c) {
        switch (c) {
            case cipher_type::none:
                DESFIRE_LOGE("cipher_type::none cannot be converted to app_crypto!.");
                return app_crypto::legacy_des_2k3des;
            case cipher_type::des:
                [[fallthrough]];
            case cipher_type::des3_2k:
                return app_crypto::legacy_des_2k3des;
            case cipher_type::des3_3k:
                return app_crypto::iso_3k3des;
            case cipher_type::aes128:
                return app_crypto::aes_128;
        }
        return app_crypto::legacy_des_2k3des;
    }

    namespace bits {
        constexpr command_code auth_command(cipher_type t) {
            switch (t) {
                case cipher_type::des3_2k:
                    return command_code::authenticate_legacy;
                case cipher_type::des3_3k:
                    return command_code::authenticate_iso;
                case cipher_type::des:
                    return command_code::authenticate_legacy;
                case cipher_type::aes128:
                    return command_code::authenticate_aes;
                default:
                    DESFIRE_LOGE("Requesting authentication command for no cipher!");
                    return command_code::additional_frame;
            }
        }
    }// namespace bits
}// namespace desfire

#endif//DESFIRE_BITS_HPP
