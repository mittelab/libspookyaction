//
// Created by Pietro Saccardi on 03/01/2021.
//

#ifndef DESFIRE_DATA_HPP
#define DESFIRE_DATA_HPP

#include <memory>
#include "mlab/any.hpp"
#include "bits.hpp"
#include "cipher_impl.hpp"

namespace desfire {
    using mlab::any;
    using bits::status;
    using bits::command_code;
    using bits::app_crypto;

    using app_id = std::array<std::uint8_t, bits::app_id_length>;

    static constexpr app_id root_app{0x0, 0x0, 0x0};


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

    app_crypto app_crypto_from_cipher(cipher_type c);

    /**
     * @note Misses @ref status::ok, @ref status::no_changes, @ref status::additional_frame. The first two represent
     * success conditions, the latter has to be handled at communication level.
     */
    enum struct error : std::uint8_t {
        out_of_eeprom        = static_cast<std::uint8_t>(status::out_of_eeprom),
        illegal_command      = static_cast<std::uint8_t>(status::illegal_command),
        integrity_error      = static_cast<std::uint8_t>(status::integrity_error),
        no_such_key          = static_cast<std::uint8_t>(status::no_such_key),
        length_error         = static_cast<std::uint8_t>(status::length_error),
        permission_denied    = static_cast<std::uint8_t>(status::permission_denied),
        parameter_error      = static_cast<std::uint8_t>(status::parameter_error),
        app_not_found        = static_cast<std::uint8_t>(status::app_not_found),
        app_integrity_error  = static_cast<std::uint8_t>(status::app_integrity_error),
        authentication_error = static_cast<std::uint8_t>(status::authentication_error),
        boundary_error       = static_cast<std::uint8_t>(status::boundary_error),
        picc_integrity_error = static_cast<std::uint8_t>(status::picc_integrity_error),
        command_aborted      = static_cast<std::uint8_t>(status::command_aborted),
        picc_disabled_error  = static_cast<std::uint8_t>(status::picc_disabled_error),
        count_error          = static_cast<std::uint8_t>(status::count_error),
        diplicate_error      = static_cast<std::uint8_t>(status::diplicate_error),
        eeprom_error         = static_cast<std::uint8_t>(status::eeprom_error),
        file_not_found       = static_cast<std::uint8_t>(status::file_not_found),
        file_integrity_error = static_cast<std::uint8_t>(status::file_integrity_error),
        controller_error,    ///< Specific for PCD error
        malformed,           ///< No data received when some was expected
        crypto_error         /**< @brief Something went wrong with crypto (@ref cipher::config)
                              * This could mean invalid MAC, CMAC, or CRC, or data length is not a multiple of block
                              * size when encrypted; this depends on the specified communication config.
                              */
    };

    error error_from_status(status s);
    command_code auth_command(cipher_type t);

    struct same_key_t {};
    struct no_key_t{};

    static constexpr same_key_t same_key{};
    static constexpr no_key_t no_key{};

    class key_actor {
        std::uint8_t _repr;
    public:
        inline key_actor(std::uint8_t key_index = 0);
        inline key_actor(same_key_t);
        inline key_actor(no_key_t);

        inline key_actor &operator=(std::uint8_t key_index);
        inline key_actor &operator=(same_key_t);
        inline key_actor &operator=(no_key_t);

        inline bool operator==(key_actor const &other) const;
        inline bool operator!=(key_actor const &other) const;

        inline std::uint8_t bitflag() const;
    };

    struct key_rights {
        key_actor allowed_to_change_keys;

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


    struct key_settings {
        key_rights rights;
        std::uint8_t max_num_keys;
        app_crypto crypto;

        inline explicit key_settings(app_crypto crypto_ = app_crypto::legacy_des_2k3des,
                                     key_rights rights_ = key_rights{},
                                     std::uint8_t max_num_keys_ = bits::max_keys_per_app);

        inline explicit key_settings(cipher_type cipher,
                                     key_rights rights_ = key_rights{},
                                     std::uint8_t max_num_keys_ = bits::max_keys_per_app);
    };


    template <cipher_type>
    struct key {
        std::unique_ptr<cipher> make_cipher() const {
            return std::unique_ptr<cipher>(new cipher_dummy());
        }
    };

    class any_key {
        cipher_type _type;
        any _key;
    public:
        inline any_key();

        template <cipher_type Type>
        inline explicit any_key(key<Type> entry);

        inline cipher_type type() const;
        std::uint8_t key_number() const;
        bool is_legacy_scheme() const;
        std::unique_ptr<cipher> make_cipher() const;

        template <cipher_type Type>
        key<Type> const &get_key() const;

        template <cipher_type Type>
        any_key &operator=(key<Type> entry);
    };


    template <std::size_t KeyLength, class Cipher>
    struct key_base {
        static constexpr std::size_t key_length = KeyLength;

        using key_t = std::array<std::uint8_t, key_length>;
        std::uint8_t key_number;
        key_t k;

        key_base();
        key_base(std::uint8_t key_no, key_t k_);
        std::unique_ptr<cipher> make_cipher() const;
        void store_version(std::uint8_t v);
        std::uint8_t get_version() const;
    };

    template <>
    struct key<cipher_type::des> : public key_base<8, cipher_des> {
        key() = default;
        key(std::uint8_t key_no, key_t k, std::uint8_t version = 0x0) : key_base<8, cipher_des>{key_no, k} {
            store_version(version);
        }
    };

    template <>
    struct key<cipher_type::des3_2k> : public key_base<16, cipher_2k3des> {
        key() = default;
        key(std::uint8_t key_no, key_t k, std::uint8_t version = 0x0) : key_base<16, cipher_2k3des>{key_no, k} {
            store_version(version);
        }
    };

    template <>
    struct key<cipher_type::des3_3k> : public key_base<24, cipher_3k3des> {
        key() = default;
        key(std::uint8_t key_no, key_t k, std::uint8_t version = 0x0) : key_base<24, cipher_3k3des>{key_no, k} {
            store_version(version);
        }
    };

    template <>
    struct key<cipher_type::aes128> : private key_base<16, cipher_aes> {
        using base = key_base<16, cipher_aes>;
        // Omit store and get version, because versioning is not implemented as such in AES
        using base::k;
        using base::key_length;
        using base::key_number;
        using base::key_t;
        using base::make_cipher;

        key() = default;
        key(std::uint8_t key_no, key_t k) : key_base<16, cipher_aes>{key_no, k} {}
    };

}

namespace mlab {
    using desfire::cipher_type;

    namespace ctti {
        template <cipher_type Type>
        struct type_info<desfire::key<Type>> : public std::integral_constant<id_type, static_cast<id_type>(Type)> {
        };
    }

    bin_data &operator<<(bin_data &bd, desfire::key_rights const &kr);
    bin_data &operator<<(bin_data &bd, desfire::key_settings const &ks);
    bin_stream &operator>>(bin_stream &s, desfire::key_rights &kr);
    bin_stream &operator>>(bin_stream &s, desfire::key_settings &ks);
    bin_stream &operator>>(bin_stream &s, std::vector<desfire::app_id> &ids);
}

namespace desfire {


    template <std::size_t KeyLength, class Cipher>
    key_base<KeyLength, Cipher>::key_base() : key_number{0}, k{} {
        std::fill_n(std::begin(k), key_length, 0x00);
    }

    template <std::size_t KeyLength, class Cipher>
    key_base<KeyLength, Cipher>::key_base(std::uint8_t key_no, key_t k_) : key_number{key_no}, k{k_} {}

    template <std::size_t KeyLength, class Cipher>
    std::unique_ptr<cipher> key_base<KeyLength, Cipher>::make_cipher() const {
        return std::unique_ptr<Cipher>(new Cipher(k));
    }

    template <std::size_t KeyLength, class Cipher>
    void key_base<KeyLength, Cipher>::store_version(std::uint8_t v) {
        for (auto &b : k) {
            b = (b & 0b11111110) | (v >> 7);
            v <<= 1;
        }
    }

    template <std::size_t KeyLength, class Cipher>
    std::uint8_t key_base<KeyLength, Cipher>::get_version() const {
        std::uint8_t v = 0x0;
        for (std::size_t i = 0; i < std::min(key_length, 8u); ++i) {
            v = (v << 1) | (k[i] & 0b00000001);
        }
        return v;
    }


    any_key::any_key() : _type{cipher_type::none}, _key{} {}

    template <cipher_type Type>
    any_key::any_key(key<Type> entry) :
            _type{Type}, _key{std::move(entry)} {}

    template <cipher_type Type>
    any_key &any_key::operator=(key<Type> entry) {
        _type = Type;
        _key = std::move(entry);
        return *this;
    }

    cipher_type any_key::type() const {
        return _type;
    }


    template <cipher_type Type>
    key<Type> const &any_key::get_key() const {
        return _key.template get<key<Type>>();
    }

    key_actor::key_actor(std::uint8_t key_index) : _repr{} {
        *this = key_index;
    }
    key_actor::key_actor(same_key_t) : _repr{} {
        *this = same_key;
    }
    key_actor::key_actor(no_key_t) : _repr{} {
        *this = no_key;
    }

    key_actor &key_actor::operator=(std::uint8_t key_index) {
        if (key_index >= bits::max_keys_per_app) {
            DESFIRE_LOGE("Specified key index %u is not valid, master key (0) assumed.", key_index);
            key_index = 0;
        }
        _repr = key_index << bits::app_change_keys_right_shift;
        return *this;
    }
    key_actor &key_actor::operator=(same_key_t) {
        _repr = bits::app_change_keys_right_same_flag;
        return *this;
    }
    key_actor &key_actor::operator=(no_key_t) {
        _repr = bits::app_change_keys_right_freeze_flag;
        return *this;
    }

    bool key_actor::operator==(key_actor const &other) const {
        return bitflag() == other.bitflag();
    }
    bool key_actor::operator!=(key_actor const &other) const {
        return bitflag() != other.bitflag();
    }
    std::uint8_t key_actor::bitflag() const {
        return _repr;
    }

    key_settings::key_settings(app_crypto crypto_, key_rights rights_, std::uint8_t max_num_keys_) :
            rights{rights_}, max_num_keys{max_num_keys_}, crypto{crypto_} {}

    key_settings::key_settings(cipher_type cipher, key_rights rights_, std::uint8_t max_num_keys_) :
            rights{rights_}, max_num_keys{max_num_keys_}, crypto{app_crypto_from_cipher(cipher)} {}
}

#endif //DESFIRE_DATA_HPP
