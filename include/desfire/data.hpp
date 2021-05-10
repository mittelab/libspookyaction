//
// Created by Pietro Saccardi on 03/01/2021.
//

#ifndef DESFIRE_DATA_HPP
#define DESFIRE_DATA_HPP

#include "bits.hpp"
#include "crypto_algo.hpp"
#include "key_actor.hpp"
#include <memory>
#include <mlab/any_of.hpp>
#include <mlab/bin_data.hpp>

namespace desfire {
    namespace {
        using mlab::bin_data;
        using mlab::bin_stream;
    }// namespace

    using bits::all_records;
    using bits::app_crypto;
    using bits::cipher_mode;
    using bits::cipher_type;
    using bits::command_code;
    using bits::file_security;
    using bits::file_type;
    using bits::status;

    [[nodiscard]] inline cipher_mode cipher_mode_most_secure(cipher_mode l, cipher_mode r);

    using app_id = std::array<std::uint8_t, bits::app_id_length>;
    using file_id = std::uint8_t;

    static constexpr app_id root_app{0x0, 0x0, 0x0};

    [[nodiscard]] app_crypto app_crypto_from_cipher(cipher_type c);

    /**
     * @note Misses @ref status::ok, @ref status::no_changes, @ref status::additional_frame. The first two represent
     * success conditions, the latter has to be handled at communication level.
     */
    enum struct error : std::uint8_t {
        out_of_eeprom = static_cast<std::uint8_t>(status::out_of_eeprom),
        illegal_command = static_cast<std::uint8_t>(status::illegal_command),
        integrity_error = static_cast<std::uint8_t>(status::integrity_error),
        no_such_key = static_cast<std::uint8_t>(status::no_such_key),
        length_error = static_cast<std::uint8_t>(status::length_error),
        permission_denied = static_cast<std::uint8_t>(status::permission_denied),
        parameter_error = static_cast<std::uint8_t>(status::parameter_error),
        app_not_found = static_cast<std::uint8_t>(status::app_not_found),
        app_integrity_error = static_cast<std::uint8_t>(status::app_integrity_error),
        authentication_error = static_cast<std::uint8_t>(status::authentication_error),
        boundary_error = static_cast<std::uint8_t>(status::boundary_error),
        picc_integrity_error = static_cast<std::uint8_t>(status::picc_integrity_error),
        command_aborted = static_cast<std::uint8_t>(status::command_aborted),
        picc_disabled_error = static_cast<std::uint8_t>(status::picc_disabled_error),
        count_error = static_cast<std::uint8_t>(status::count_error),
        duplicate_error = static_cast<std::uint8_t>(status::duplicate_error),
        eeprom_error = static_cast<std::uint8_t>(status::eeprom_error),
        file_not_found = static_cast<std::uint8_t>(status::file_not_found),
        file_integrity_error = static_cast<std::uint8_t>(status::file_integrity_error),
        controller_error,///< Specific for PCD error
        malformed,       ///< No data or incorrect data received when some specific format was expected
        crypto_error     /**< @brief Something went wrong with crypto (@ref cipher_mode)
                              * This could mean invalid MAC, CMAC, or CRC, or data length is not a multiple of block
                              * size when encrypted; this depends on the specified communication config.
                              */
    };

    [[nodiscard]] error error_from_status(status s);
    [[nodiscard]] command_code auth_command(cipher_type t);

    struct same_key_t {};
    static constexpr same_key_t same_key{};

    struct change_key_actor : public key_actor_base<std::uint8_t, bits::app_change_keys_right_shift, same_key_t, change_key_actor> {
        using base = key_actor_base<std::uint8_t, bits::app_change_keys_right_shift, same_key_t, change_key_actor>;
        using base::base;
        using base::get;
    };

    struct key_rights {
        change_key_actor allowed_to_change_keys;

        /**
         * Settings this to false freezes the master key.
         */
        bool master_key_changeable = true;

        /**
         * On an app level, it is possible to list file IDs, get their settings and the key settings.
         * On a PICC level, it is possible to list app IDs and key settings.
         */
        bool dir_access_without_auth = true;

        /**
         * On an app level, this means files can be created or deleted without authentication.
         * On a PICC level, applications can be created without authentication and deleted with their own master keys.
         */
        bool create_delete_without_auth = true;

        /**
         * Setting this to false freezes the configuration of the PICC or the app. Changing still requires to
         * authenticate with the appropriate master key.
         */
        bool config_changeable = true;
    };

    struct all_keys_t {};
    static constexpr all_keys_t all_keys{};

    enum struct file_access {
        change,
        read,
        write
    };

    /**
     * @todo Do not use a union
     */
    union access_rights {
        using change_actor = key_actor_mask<std::uint16_t, bits::file_access_rights_change_shift, all_keys_t>;
        using rw_actor = key_actor_mask<std::uint16_t, bits::file_access_rights_read_write_shift, all_keys_t>;
        using w_actor = key_actor_mask<std::uint16_t, bits::file_access_rights_write_shift, all_keys_t>;
        using r_actor = key_actor_mask<std::uint16_t, bits::file_access_rights_read_shift, all_keys_t>;

        /**
         * @todo use std::array<std::uint8_t, 2>
         */
        std::uint16_t value;

        change_actor change;
        rw_actor read_write;
        w_actor write;
        r_actor read;

        inline constexpr access_rights();
        inline constexpr access_rights(no_key_t);
        inline constexpr access_rights(all_keys_t);
        inline explicit access_rights(std::uint8_t single_key);
        inline access_rights(rw_actor rw, change_actor chg);
        inline access_rights(rw_actor rw, change_actor chg, r_actor r, w_actor w);

        [[nodiscard]] inline static access_rights from_mask(std::uint16_t mask);

        [[nodiscard]] bool is_free(file_access access, std::uint8_t active_key_num) const;
    };

    static_assert(sizeof(access_rights) == sizeof(std::uint16_t), "Must be able to pack 2 bytes structures.");

    struct generic_file_settings {
        file_security security = file_security::none;
        access_rights rights;

        generic_file_settings() = default;
        inline generic_file_settings(file_security security_, access_rights rights_);
    };

    struct data_file_settings {
        /**
         * @note This is actually a 24bit value, so the maximum value is 0xffffff. It will be clamped upon trasmission.
         */
        std::uint32_t size;
    };

    struct value_file_settings {
        std::int32_t lower_limit;
        std::int32_t upper_limit;
        /**
         * @note For @ref tag::get_file_settings, this includes the limited credit, if enabled.
         * For the method @ref tag::create_value_file, this is the initial value.
         */
        std::int32_t value;
        bool limited_credit_enabled;
    };

    struct record_file_settings {
        /**
         * @note This is actually a 24bit value, so the maximum value is 0xffffff. It will be clamped upon trasmission.
         */
        std::uint32_t record_size;

        /**
         * @note This is actually a 24bit value, so the maximum value is 0xffffff. It will be clamped upon trasmission.
         */
        std::uint32_t max_record_count;

        /**
         * @note This is actually a 24bit value, so the maximum value is 0xffffff. It will be clamped upon trasmission.
         */
        std::uint32_t record_count;
    };

    template <file_type Type>
    struct file_settings {};

    template <>
    struct file_settings<file_type::standard> : public generic_file_settings, public data_file_settings {
        using specific_file_settings = data_file_settings;
        inline file_settings() : generic_file_settings{}, data_file_settings{.size = 0} {}
        file_settings(generic_file_settings generic, data_file_settings specific) : generic_file_settings{generic}, data_file_settings{specific} {}
    };

    template <>
    struct file_settings<file_type::backup> : public generic_file_settings, public data_file_settings {
        using specific_file_settings = data_file_settings;
        inline file_settings() : generic_file_settings{}, data_file_settings{.size = 0} {}
        file_settings(generic_file_settings generic, data_file_settings specific) : generic_file_settings{generic}, data_file_settings{specific} {}
    };

    template <>
    struct file_settings<file_type::value> : public generic_file_settings, public value_file_settings {
        using specific_file_settings = value_file_settings;
        inline file_settings() : generic_file_settings{},
                                 value_file_settings{.lower_limit = 0, .upper_limit = 0, .value = 0, .limited_credit_enabled = false} {}

        file_settings(generic_file_settings generic, value_file_settings specific) : generic_file_settings{generic}, value_file_settings{specific} {}
    };

    template <>
    struct file_settings<file_type::linear_record> : public generic_file_settings, public record_file_settings {
        using specific_file_settings = record_file_settings;
        inline file_settings() : generic_file_settings{},
                                 record_file_settings{.record_size = 0, .max_record_count = 0, .record_count = 0} {}

        file_settings(generic_file_settings generic, record_file_settings specific) : generic_file_settings{generic}, record_file_settings{specific} {}
    };

    template <>
    struct file_settings<file_type::cyclic_record> : public generic_file_settings, public record_file_settings {
        using specific_file_settings = record_file_settings;
        inline file_settings() : generic_file_settings{},
                                 record_file_settings{.record_size = 0, .max_record_count = 0, .record_count = 0} {}

        file_settings(generic_file_settings generic, record_file_settings specific) : generic_file_settings{generic}, record_file_settings{specific} {}
    };


    class any_file_settings : public mlab::any_of<file_type, file_settings, file_type::standard> {
    public:
        using mlab::any_of<file_type, file_settings, file_type::standard>::any_of;

        [[nodiscard]] generic_file_settings const &generic_settings() const;
        [[nodiscard]] generic_file_settings &generic_settings();
        [[nodiscard]] data_file_settings const &data_settings() const;
        [[nodiscard]] data_file_settings &data_settings();
        [[nodiscard]] record_file_settings const &record_settings() const;
        [[nodiscard]] record_file_settings &record_settings();
        [[nodiscard]] value_file_settings const &value_settings() const;
        [[nodiscard]] value_file_settings &value_settings();
    };

    struct app_settings {
        key_rights rights;
        std::uint8_t max_num_keys;
        app_crypto crypto;

        inline explicit app_settings(app_crypto crypto_ = app_crypto::legacy_des_2k3des,
                                     key_rights rights_ = key_rights{},
                                     std::uint8_t max_num_keys_ = bits::max_keys_per_app);

        inline explicit app_settings(cipher_type cipher,
                                     key_rights rights_ = key_rights{},
                                     std::uint8_t max_num_keys_ = bits::max_keys_per_app);
    };

    class storage_size {
        std::uint8_t _flag;

        [[nodiscard]] inline unsigned exponent() const;
        [[nodiscard]] inline bool approx() const;

    public:
        explicit storage_size(std::size_t nbytes = 0);

        [[nodiscard]] inline std::size_t bytes_lower_bound() const;
        [[nodiscard]] inline std::size_t bytes_upper_bound() const;

        mlab::bin_stream &operator>>(mlab::bin_stream &s);
        mlab::bin_data &operator<<(mlab::bin_data &s) const;
    };

    struct ware_info {
        std::uint8_t vendor_id = 0;
        std::uint8_t type = 0;
        std::uint8_t subtype = 0;
        std::uint8_t version_major = 0;
        std::uint8_t version_minor = 0;
        storage_size size;
        std::uint8_t comm_protocol_type = 0;
    };

    struct manufacturing_info {
        ware_info hardware;
        ware_info software;
        std::array<std::uint8_t, 7> serial_no{};
        std::array<std::uint8_t, 5> batch_no{};
        std::uint8_t production_week = 0;
        std::uint8_t production_year = 0;
    };


    template <cipher_type>
    struct key {
    };

    class any_key : public mlab::any_of<cipher_type, key, cipher_type::none> {
    public:
        using mlab::any_of<cipher_type, key, cipher_type::none>::any_of;

        any_key(any_key const &other);
        any_key &operator=(any_key const &other);

        [[nodiscard]] std::uint8_t key_number() const;
        [[nodiscard]] std::uint8_t version() const;

        /**
         * Size in bytes of the key. Does not account for the fact that DES key in Desfire cards are stored as 16 bytes,
         * that is, will return 8 for a DES key.
         */
        [[nodiscard]] std::size_t size() const;

        [[nodiscard]] bool parity_bits_are_version() const;

        /**
         * Does not include version for keys that do not use @ref parity_bits_are_version.
         */
        [[nodiscard]] bin_data get_packed_key_body() const;

        /**
         * @note Assume that keys which do not use parity bits as version will dump the version byte last in a
         * @ref bin_data.
         */
        [[nodiscard]] bin_data xored_with(any_key const &key_to_xor_with) const;

        bin_data &operator<<(bin_data &bd) const;
    };


    template <std::size_t KeyLength, bool /* ParityBitsAreVersion */>
    struct key_storage {
        static constexpr std::size_t key_length = KeyLength;
        using key_t = std::array<std::uint8_t, key_length>;
        key_t k;
        std::uint8_t v;

        key_storage() : k{}, v{0} {
            std::fill_n(std::begin(k), key_length, 0);
        }
        explicit key_storage(key_t k_) : k{k_}, v{0} {}
        explicit key_storage(key_t k_, std::uint8_t v_) : k{k_}, v{v_} {}
        [[nodiscard]] inline std::uint8_t version() const { return v; }
        inline void set_version(std::uint8_t v_) { v = v_; }
    };

    template <std::size_t KeyLength>
    struct key_storage<KeyLength, true /* ParityBitsAreVersion */> {
        static constexpr std::size_t key_length = KeyLength;
        using key_t = std::array<std::uint8_t, key_length>;
        key_t k;

        key_storage() : k{} {
            std::fill_n(std::begin(k), key_length, 0);
        }
        explicit key_storage(key_t k_) : k{k_} {}
        explicit key_storage(key_t k_, std::uint8_t v_) : k{k_} {
            set_version(v_);
        }

        [[nodiscard]] inline std::uint8_t version() const { return get_key_version(k); }

        inline void set_version(std::uint8_t v) { set_key_version(k, v); }
    };


    template <std::size_t KeyLength, bool ParityBitsAreVersion>
    struct key_base : public key_storage<KeyLength, ParityBitsAreVersion> {
        using storage = key_storage<KeyLength, ParityBitsAreVersion>;
        static constexpr bool parity_bits_are_version = ParityBitsAreVersion;
        std::uint8_t key_number = 0;
        using typename storage::key_t;

        key_base();
        key_base(std::uint8_t key_no, key_t k_);
        key_base(std::uint8_t key_no, key_t k_, std::uint8_t v_);
    };

    template <>
    struct key<cipher_type::des> : public key_base<8, true> {
        using key_base<8, true>::key_base;
    };

    template <>
    struct key<cipher_type::des3_2k> : public key_base<16, true> {
        using key_base<16, true>::key_base;
    };

    template <>
    struct key<cipher_type::des3_3k> : public key_base<24, true> {
        using key_base<24, true>::key_base;
    };

    template <>
    struct key<cipher_type::aes128> : public key_base<16, false> {
        using key_base<16, false>::key_base;
    };

}// namespace desfire

namespace mlab {

    bin_stream &operator>>(bin_stream &s, desfire::key_rights &kr);
    bin_stream &operator>>(bin_stream &s, desfire::app_settings &ks);
    bin_stream &operator>>(bin_stream &s, std::vector<desfire::app_id> &ids);
    bin_stream &operator>>(bin_stream &s, desfire::ware_info &wi);
    bin_stream &operator>>(bin_stream &s, desfire::manufacturing_info &mi);

    bin_stream &operator>>(bin_stream &s, desfire::access_rights &ar);
    bin_stream &operator>>(bin_stream &s, desfire::generic_file_settings &fs);
    bin_stream &operator>>(bin_stream &s, desfire::data_file_settings &fs);
    bin_stream &operator>>(bin_stream &s, desfire::value_file_settings &fs);
    bin_stream &operator>>(bin_stream &s, desfire::record_file_settings &fs);
    bin_stream &operator>>(bin_stream &s, desfire::any_file_settings &fs);

    template <desfire::file_type Type>
    bin_stream &operator>>(bin_stream &s, desfire::file_settings<Type> &fs);

    bin_data &operator<<(bin_data &bd, desfire::key_rights const &kr);
    bin_data &operator<<(bin_data &bd, desfire::app_settings const &ks);
    bin_data &operator<<(bin_data &bd, desfire::any_key const &k);

    bin_data &operator<<(bin_data &bd, desfire::access_rights const &ar);
    bin_data &operator<<(bin_data &bd, desfire::generic_file_settings const &fs);
    bin_data &operator<<(bin_data &bd, desfire::data_file_settings const &fs);
    bin_data &operator<<(bin_data &bd, desfire::value_file_settings const &fs);
    bin_data &operator<<(bin_data &bd, desfire::record_file_settings const &fs);
    bin_data &operator<<(bin_data &bd, desfire::any_file_settings const &fs);

    template <desfire::file_type Type>
    bin_data &operator<<(bin_data &bd, desfire::file_settings<Type> const &fs);
}// namespace mlab

namespace desfire {

    template <std::size_t KeyLength, bool ParityBitsAreVersion>
    key_base<KeyLength, ParityBitsAreVersion>::key_base() : storage{}, key_number{0} {}

    template <std::size_t KeyLength, bool ParityBitsAreVersion>
    key_base<KeyLength, ParityBitsAreVersion>::key_base(std::uint8_t key_no, key_t k_) : storage{k_}, key_number{key_no} {}

    template <std::size_t KeyLength, bool ParityBitsAreVersion>
    key_base<KeyLength, ParityBitsAreVersion>::key_base(std::uint8_t key_no, key_t k_, std::uint8_t v_) : storage{k_, v_}, key_number{key_no} {}

    app_settings::app_settings(app_crypto crypto_, key_rights rights_, std::uint8_t max_num_keys_) : rights{rights_}, max_num_keys{max_num_keys_}, crypto{crypto_} {}

    app_settings::app_settings(cipher_type cipher, key_rights rights_, std::uint8_t max_num_keys_) : rights{rights_}, max_num_keys{max_num_keys_}, crypto{app_crypto_from_cipher(cipher)} {}

    unsigned storage_size::exponent() const {
        return _flag >> bits::storage_size_exponent_shift;
    }
    bool storage_size::approx() const {
        return 0 != (_flag & bits::storage_size_approx_bit);
    }
    std::size_t storage_size::bytes_lower_bound() const {
        return 1 << exponent();
    }
    std::size_t storage_size::bytes_upper_bound() const {
        return 1 << (approx() ? exponent() + 1 : exponent());
    }

    cipher_mode cipher_mode_most_secure(cipher_mode l, cipher_mode r) {
        if (l == cipher_mode::ciphered or r == cipher_mode::ciphered) {
            return cipher_mode::ciphered;
        } else if (l == cipher_mode::ciphered_no_crc or r == cipher_mode::ciphered_no_crc) {
            return cipher_mode::ciphered_no_crc;
        } else if (l == cipher_mode::maced or r == cipher_mode::maced) {
            return cipher_mode::maced;
        } else {
            return cipher_mode::plain;
        }
    }

    constexpr access_rights::access_rights() : value{0} {}

    access_rights::access_rights(std::uint8_t single_key) : access_rights{} {
        if (single_key > bits::max_keys_per_app) {
            DESFIRE_LOGE("Invalid key number (%d) for access rights, should be <= %d.", single_key, bits::max_keys_per_app);
        } else {
            read = single_key;
            write = single_key;
            read_write = single_key;
            change = single_key;
        }
    }
    constexpr access_rights::access_rights(no_key_t) : value{0xffff} {}
    constexpr access_rights::access_rights(all_keys_t) : value{0xeeee} {}
    access_rights::access_rights(rw_actor rw, change_actor chg) : access_rights{no_key} {
        read_write = rw;
        change = chg;
    }
    access_rights::access_rights(rw_actor rw, change_actor chg, r_actor r, w_actor w) : access_rights{no_key} {
        read_write = rw;
        change = chg;
        read = r;
        write = w;
    }

    access_rights access_rights::from_mask(std::uint16_t mask) {
        access_rights retval;
        retval.value = mask;
        return retval;
    }

    generic_file_settings::generic_file_settings(file_security security_, access_rights rights_) : security{security_}, rights{rights_} {}
}// namespace desfire

namespace mlab {

    template <desfire::file_type Type>
    bin_stream &operator>>(bin_stream &s, desfire::file_settings<Type> &fs) {
        if (not s.bad()) {
            s >> static_cast<desfire::generic_file_settings &>(fs);
        }
        if (not s.bad()) {
            s >> static_cast<typename desfire::file_settings<Type>::specific_file_settings &>(fs);
        }
        return s;
    }

    template <desfire::file_type Type>
    bin_data &operator<<(bin_data &bd, desfire::file_settings<Type> const &fs) {
        return bd
               << static_cast<desfire::generic_file_settings const &>(fs)
               << static_cast<typename desfire::file_settings<Type>::specific_file_settings const &>(fs);
    }
}// namespace mlab

#endif//DESFIRE_DATA_HPP
