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

    inline error error_from_status(status s);

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

    inline command_code auth_command(cipher_type t);

    namespace impl {
        template <std::size_t KeyLength, class Cipher>
        struct key_base {
            static constexpr std::size_t key_length = KeyLength;
            using key_t = std::array<std::uint8_t, key_length>;
            std::uint8_t key_number;
            key_t k;

            inline key_base() : key_number{0}, k{} {
                std::fill_n(std::begin(k), key_length, 0x00);
            }

            inline key_base(std::uint8_t key_no, key_t k_) : key_number{key_no}, k{k_} {}

            std::unique_ptr<cipher> make_cipher() const {
                return std::unique_ptr<Cipher>(new Cipher(k));
            }

            void store_version(std::uint8_t v) {
                for (auto &b : k) {
                    b = (b & 0b11111110) | (v >> 7);
                    v <<= 1;
                }
            }

            std::uint8_t get_version() const {
                std::uint8_t v = 0x0;
                for (std::size_t i = 0; i < std::min(key_length, 8u); ++i) {
                    v = (v << 1) | (k[i] & 0b00000001);
                }
                return v;
            }

        };

    }

    template <cipher_type>
    struct key {
        std::unique_ptr<cipher> make_cipher() const {
            return std::unique_ptr<cipher>(new cipher_dummy());
        }
    };

    template <>
    struct key<cipher_type::des> : public impl::key_base<8, cipher_des> {
        key() = default;
        key(std::uint8_t key_no, key_t k, std::uint8_t version = 0x0) :
            impl::key_base<8, cipher_des>{key_no, k}
        {
            store_version(version);
        }
    };

    template <>
    struct key<cipher_type::des3_2k> : public impl::key_base<16, cipher_2k3des> {
        key() = default;
        key(std::uint8_t key_no, key_t k, std::uint8_t version = 0x0) :
            impl::key_base<16, cipher_2k3des>{key_no, k}
        {
            store_version(version);
        }
    };

    template <>
    struct key<cipher_type::des3_3k> : public impl::key_base<24, cipher_3k3des> {
        key() = default;
        key(std::uint8_t key_no, key_t k, std::uint8_t version = 0x0) :
            impl::key_base<24, cipher_3k3des>{key_no, k}
        {
            store_version(version);
        }
    };

    template <>
    struct key<cipher_type::aes128> : private impl::key_base<16, cipher_aes> {
        using base = impl::key_base<16, cipher_aes>;
        // Omit store and get version, because versioning is not implemented as such in AES
        using base::k;
        using base::key_length;
        using base::key_number;
        using base::key_t;
        using base::make_cipher;

        key() = default;
        key(std::uint8_t key_no, key_t k) : impl::key_base<16, cipher_aes>{key_no, k} {}
    };


    class any_key {
        cipher_type _type;
        any _key;
    public:
        inline any_key();

        template <cipher_type Type>
        inline explicit any_key(key<Type> entry);

        inline cipher_type type() const;
        inline std::uint8_t key_number() const;
        inline bool is_legacy_scheme() const;

        inline std::unique_ptr<cipher> make_cipher() const;

        template <cipher_type Type>
        key<Type> const &get_key() const;

        template <cipher_type Type>
        any_key &operator=(key<Type> entry);
    };
}

namespace mlab {
    using desfire::cipher_type;

    namespace ctti {
        template <cipher_type Type>
        struct type_info<desfire::key<Type>> : public std::integral_constant<id_type, static_cast<id_type>(Type)> {
        };
    }
}

namespace desfire {

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

    std::uint8_t any_key::key_number() const {
        switch (type()) {
            case cipher_type::none:
                return std::numeric_limits<std::uint8_t>::max();
            case cipher_type::des:
                return get_key<cipher_type::des>().key_number;
            case cipher_type::des3_2k:
                return get_key<cipher_type::des3_2k>().key_number;
            case cipher_type::des3_3k:
                return get_key<cipher_type::des3_3k>().key_number;
            case cipher_type::aes128:
                return get_key<cipher_type::aes128>().key_number;
            default:
                DESFIRE_LOGE("Unhandled cipher type.");
                return std::numeric_limits<std::uint8_t>::max();
        }
    }

    bool any_key::is_legacy_scheme() const {
        switch (type()) {
            case cipher_type::des:
            case cipher_type::des3_2k:
                return true;
            case cipher_type::des3_3k:
            case cipher_type::aes128:
                return false;
            default:
                DESFIRE_LOGE("Requesting whether a cipher is legacy with no cipher!");
                return true;
        }
    }

    template <cipher_type Type>
    key<Type> const &any_key::get_key() const {
        return _key.template get<key<Type>>();
    }

    std::unique_ptr<cipher> any_key::make_cipher() const {
        switch (type()) {
            case cipher_type::none:
                return get_key<cipher_type::none>().make_cipher();
            case cipher_type::des:
                return get_key<cipher_type::des>().make_cipher();
            case cipher_type::des3_2k:
                return get_key<cipher_type::des3_2k>().make_cipher();
            case cipher_type::des3_3k:
                return get_key<cipher_type::des3_3k>().make_cipher();
            case cipher_type::aes128:
                return get_key<cipher_type::aes128>().make_cipher();
            default:
                DESFIRE_LOGE("Unhandled cipher type.");
                return nullptr;
        }
    }

    command_code auth_command(cipher_type t) {
        switch (t) {
            case cipher_type::des3_2k: return command_code::authenticate_legacy;
            case cipher_type::des3_3k: return command_code::authenticate_iso;
            case cipher_type::des:     return command_code::authenticate_legacy;
            case cipher_type::aes128:  return command_code::authenticate_aes;
            default:
                DESFIRE_LOGE("Requesting authentication command for no cipher!");
                return command_code::additional_frame;
        }
    }

    error error_from_status(status s) {
        if (s == status::ok or s == status::no_changes or s == status::additional_frame) {
            return error::malformed;
        }
        return static_cast<error>(s);
    }

}

#endif //DESFIRE_DATA_HPP
