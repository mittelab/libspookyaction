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
    using bits::cipher_type;
    using bits::command_code;
    using bits::app_crypto;

    using app_id = std::array<std::uint8_t, bits::app_id_length>;

    static constexpr app_id root_app{0x0, 0x0, 0x0};

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

    class storage_size {
        std::uint8_t _flag;

        inline unsigned exponent() const;
        inline bool approx() const;
    public:
        explicit storage_size(std::size_t nbytes = 0);

        inline std::size_t bytes_lower_bound() const;
        inline std::size_t bytes_upper_bound() const;

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
        std::unique_ptr<cipher> make_cipher() const {
            return std::unique_ptr<cipher>(new cipher_dummy());
        }
        inline bin_data &operator<<(bin_data &bd) const {
            DESFIRE_LOGE("Attempt at writing key of an invalid cipher type.");
            return bd;
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
        std::uint8_t key_version() const;
        std::unique_ptr<cipher> make_cipher() const;

        template <cipher_type Type>
        key<Type> const &get_key() const;
        template <cipher_type Type>
        key<Type> &get_key();

        template <cipher_type Type>
        any_key &operator=(key<Type> entry);

        bin_data get_packed_key_data() const;

        /**
         * @note DES keys will become 2K3DES keys because they must be Xored with, in principle, arbitrary 16 bytes of
         * payload. This is perfectly fine. Also, for all keys that use parity bits for versioning, the version will be
         * of course Xored too; for keys that do not use parity bits for versioning, the version is preserved. That is
         * in such a way that the 16 or 24 bits that make up the key can be consistently transmitted.
         */
        any_key copy_xored(any_key const &key_to_xor_with) const;
    };


    template <std::size_t KeyLength, class Cipher, bool ParityBitsAreVersion>
    struct key_base {
        static constexpr std::size_t key_length = KeyLength;

        using key_t = std::array<std::uint8_t, key_length>;
        std::uint8_t key_number;
        std::uint8_t version;
        key_t k;

        key_base();
        key_base(std::uint8_t key_no, key_t k_);
        key_base(std::uint8_t key_no, key_t k_, std::uint8_t version_);

        std::unique_ptr<cipher> make_cipher() const;
    };

    template <>
    struct key<cipher_type::des> : public key_base<8, cipher_des, true> {
        using key_base<8, cipher_des, true>::key_base;

        std::array<std::uint8_t, 16> get_packed_key_data() const {
            // Key must be copied twice in two identical parts because it's DES.
            std::array<std::uint8_t, 2 * key_length> payload{};
            std::copy_n(std::begin(k), key_length, std::begin(payload));
            std::copy_n(std::begin(k), key_length, std::begin(payload) + key_length);
            set_key_version(payload, version);
            return payload;
        }

        bin_data &operator<<(bin_data &bd) const { return bd << get_packed_key_data(); }
    };

    template <>
    struct key<cipher_type::des3_2k> : public key_base<16, cipher_2k3des, true> {
        using key_base<16, cipher_2k3des, true>::key_base;

        std::array<std::uint8_t, 16> get_packed_key_data() const {
            std::array<std::uint8_t, key_length> payload{};
            std::copy_n(std::begin(k), key_length, std::begin(payload));
            set_key_version(payload, version);
            return payload;
        }

        bin_data &operator<<(bin_data &bd) const { return bd << get_packed_key_data(); }
    };

    template <>
    struct key<cipher_type::des3_3k> : public key_base<24, cipher_3k3des, true> {
        using key_base<24, cipher_3k3des, true>::key_base;

        std::array<std::uint8_t, 24> get_packed_key_data() const {
            std::array<std::uint8_t, key_length> payload{};
            std::copy_n(std::begin(k), key_length, std::begin(payload));
            set_key_version(payload, version);
            return payload;
        }

        bin_data &operator<<(bin_data &bd) const { return bd << get_packed_key_data(); }
    };

    template <>
    struct key<cipher_type::aes128> : public key_base<16, cipher_aes, false> {
        using key_base<16, cipher_aes, false>::key_base;

        std::array<std::uint8_t, 16> const &get_packed_key_data() const {
            return k;
        }

        bin_data &operator<<(bin_data &bd) const {
            // The only sensible choice out of three ciphers.
            return bd << get_packed_key_data() << version;
        }
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
    bin_stream &operator>>(bin_stream &s, desfire::ware_info &wi);
    bin_stream &operator>>(bin_stream &s, desfire::manufacturing_info &mi);

    bin_data &operator<<(bin_data &bd, desfire::any_key const &k);
    template <cipher_type Type>
    bin_data &operator<<(bin_data &bd, desfire::key<Type> const &k);
}

namespace desfire {


    template <std::size_t KeyLength, class Cipher, bool ParityBitsAreVersion>
    key_base<KeyLength, Cipher, ParityBitsAreVersion>::key_base() : key_number{0}, version{0x00}, k{} {
        std::fill_n(std::begin(k), key_length, 0x00);
    }

    template <std::size_t KeyLength, class Cipher, bool ParityBitsAreVersion>
    key_base<KeyLength, Cipher, ParityBitsAreVersion>::key_base(std::uint8_t key_no, key_t k_) :
            key_number{key_no}, version{ParityBitsAreVersion ? get_key_version(k_) : std::uint8_t(0)}, k{k_}
    {
        if (ParityBitsAreVersion) {
            set_key_version(k, 0x00);
        }
    }

    template <std::size_t KeyLength, class Cipher, bool ParityBitsAreVersion>
    key_base<KeyLength, Cipher, ParityBitsAreVersion>::key_base(std::uint8_t key_no, key_t k_, std::uint8_t version_) :
        key_number{key_no}, version{version_}, k{k_}
    {
        if (ParityBitsAreVersion) {
            set_key_version(k, 0x00);
        }
    }

    template <std::size_t KeyLength, class Cipher, bool ParityBitsAreVersion>
    std::unique_ptr<cipher> key_base<KeyLength, Cipher, ParityBitsAreVersion>::make_cipher() const {
        return std::unique_ptr<Cipher>(new Cipher(k));
    }

    any_key::any_key() : _type{cipher_type::none}, _key{key<cipher_type::none>{}} {}

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

    template <cipher_type Type>
    key<Type> &any_key::get_key() {
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
}

namespace mlab {

    template <cipher_type Type>
    bin_data &operator<<(bin_data &bd, desfire::key<Type> const &k) {
        return k.operator<<(bd);
    }
}

#endif //DESFIRE_DATA_HPP
