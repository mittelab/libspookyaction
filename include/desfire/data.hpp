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

        bool parity_bits_are_version() const;

        /**
         * @note The returned payload will include the parity bits with the version encoded for all ciphers for which
         * @ref parity_bits_are_version is true (at the moment, all but AES), but will __not__ include the version byte
         * for all other ciphers. This method is used for CRCs and xoring, where the implementation requires the version
         * only for the first type of ciphers.
         */
        bin_data get_packed_key_data() const;

        /**
         * XOR the key with the other given key and return the payload as it would be transmitted.
         * @note This behaves in the same way as operator<< in terms of how the payload is formed, however, we have a
         * different behavior for ciphers where the parity bit is the version (@ref parity_bits_are_version):
         *   - Since version (parity) bits are part of the key payload, those get xored as well. This means that the
         *     final result is somewhat of a malformed key, because the version is mangled; also, a DES key, which has
         *     a 8 bytes key length, is represented as two identical consecutive copies, which means that xoring it with
         *     anything that has a nonzero version (or a 2K3DES key), yields a 2K3DES key. This is the reason why this
         *     method returns a blob and not a key.
         *   - In ciphers where the version is stored separately, the version itself is preserved and appended at the
         *     end of the blob.
         */
        bin_data xored_with(any_key const &key_to_xor_with) const;
    };


    template <std::size_t KeyLength, class Cipher, bool ParityBitsAreVersion, class Subclass>
    struct key_base {
        static constexpr std::size_t key_length = KeyLength;
        static constexpr bool parity_bits_are_version = ParityBitsAreVersion;

        using key_t = std::array<std::uint8_t, key_length>;
        std::uint8_t key_number;
        std::uint8_t version;
        key_t k;

        key_base();
        key_base(std::uint8_t key_no, key_t k_);
        key_base(std::uint8_t key_no, key_t k_, std::uint8_t version_);

        std::unique_ptr<cipher> make_cipher() const;

        bin_data &operator<<(bin_data &bd) const;
    };

    template <>
    struct key<cipher_type::des> : public key_base<8, cipher_des, true, key<cipher_type::des>> {
        using key_base<8, cipher_des, true, key<cipher_type::des>>::key_base;

        std::array<std::uint8_t, 16> get_packed_key_data() const {
            // Key must be copied twice in two identical parts because it's DES.
            std::array<std::uint8_t, 2 * key_length> payload{};
            std::copy_n(std::begin(k), key_length, std::begin(payload));
            std::copy_n(std::begin(k), key_length, std::begin(payload) + key_length);
            set_key_version(payload, version);
            return payload;
        }
    };

    template <>
    struct key<cipher_type::des3_2k> : public key_base<16, cipher_2k3des, true, key<cipher_type::des3_2k>> {
        using key_base<16, cipher_2k3des, true, key<cipher_type::des3_2k>>::key_base;

        std::array<std::uint8_t, 16> get_packed_key_data() const {
            std::array<std::uint8_t, key_length> payload{};
            std::copy_n(std::begin(k), key_length, std::begin(payload));
            set_key_version(payload, version);
            return payload;
        }
    };

    template <>
    struct key<cipher_type::des3_3k> : public key_base<24, cipher_3k3des, true, key<cipher_type::des3_3k>> {
        using key_base<24, cipher_3k3des, true, key<cipher_type::des3_3k>>::key_base;

        std::array<std::uint8_t, 24> get_packed_key_data() const {
            std::array<std::uint8_t, key_length> payload{};
            std::copy_n(std::begin(k), key_length, std::begin(payload));
            set_key_version(payload, version);
            return payload;
        }
    };

    template <>
    struct key<cipher_type::aes128> : public key_base<16, cipher_aes, false, key<cipher_type::aes128>> {
        using key_base<16, cipher_aes, false, key<cipher_type::aes128>>::key_base;

        std::array<std::uint8_t, 16> const &get_packed_key_data() const {
            return k;
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


    template <std::size_t KeyLength, class Cipher, bool ParityBitsAreVersion, class Subclass>
    key_base<KeyLength, Cipher, ParityBitsAreVersion, Subclass>::key_base() : key_number{0}, version{0x00}, k{} {
        std::fill_n(std::begin(k), key_length, 0x00);
    }

    template <std::size_t KeyLength, class Cipher, bool ParityBitsAreVersion, class Subclass>
    key_base<KeyLength, Cipher, ParityBitsAreVersion, Subclass>::key_base(std::uint8_t key_no, key_t k_) :
            key_number{key_no}, version{ParityBitsAreVersion ? get_key_version(k_) : std::uint8_t(0)}, k{k_}
    {
        if (ParityBitsAreVersion) {
            set_key_version(k, 0x00);
        }
    }

    template <std::size_t KeyLength, class Cipher, bool ParityBitsAreVersion, class Subclass>
    key_base<KeyLength, Cipher, ParityBitsAreVersion, Subclass>::key_base(std::uint8_t key_no, key_t k_, std::uint8_t version_) :
        key_number{key_no}, version{version_}, k{k_}
    {
        if (ParityBitsAreVersion) {
            set_key_version(k, 0x00);
        }
    }

    template <std::size_t KeyLength, class Cipher, bool ParityBitsAreVersion, class Subclass>
    std::unique_ptr<cipher> key_base<KeyLength, Cipher, ParityBitsAreVersion, Subclass>::make_cipher() const {
        return std::unique_ptr<Cipher>(new Cipher(k));
    }

    namespace impl {
        template <class>
        struct extract_size {};

        template <std::size_t Length>
        struct extract_size<std::array<std::uint8_t, Length>> {
            static constexpr std::size_t size = Length;
        };
    }

    template <std::size_t KeyLength, class Cipher, bool ParityBitsAreVersion, class Subclass>
    bin_data &key_base<KeyLength, Cipher, ParityBitsAreVersion, Subclass>::operator<<(bin_data &bd) const {
        using packed_data_t = typename std::remove_const<typename std::remove_reference<
                decltype(std::declval<Subclass const &>().get_packed_key_data())
        >::type>::type;
        static constexpr std::size_t packed_key_data_length = impl::extract_size<packed_data_t>::size;
        static constexpr std::size_t prealloc_size = packed_key_data_length + (ParityBitsAreVersion ? 0 : 1);
        bd << prealloc(prealloc_size);
        // Here we would like to dynamic cast, but on embedded that is disabled, so we do some juggling
        static_assert(std::is_base_of<key_base, Subclass>::value,
                "We use the curiously recurring template pattern here to do something that otherwise would require a "
                "virtual function. You must specify the subclass's own type as the Subclass template parameter.");
        bd << reinterpret_cast<Subclass const *>(this)->get_packed_key_data();
        if (not ParityBitsAreVersion) {
            bd << version;
        }
        return bd;
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
