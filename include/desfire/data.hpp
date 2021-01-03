//
// Created by Pietro Saccardi on 03/01/2021.
//

#ifndef DESFIRE_DATA_HPP
#define DESFIRE_DATA_HPP

#include "bits.hpp"
#include "cipher_impl.hpp"
#include <memory>
#include "mlab/any.hpp"

namespace desfire {
    using mlab::any;
    using bits::status;


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
        additional_frame     = static_cast<std::uint8_t>(status::additional_frame),
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

    namespace impl {
        template <std::size_t KeyLength, class Cipher>
        struct key_base {
            static constexpr std::size_t key_length = KeyLength;
            using key_t = std::array<std::uint8_t, key_length>;
            std::uint8_t key_number;
            key_t k;

            std::unique_ptr<cipher> make_cipher() const {
                return std::unique_ptr<Cipher>(new Cipher(k));
            }
        };

    }

    template <cipher_type>
    struct key {
        std::uint8_t key_number;
        std::unique_ptr<cipher> make_cipher() const { return nullptr; }
        explicit key(std::uint8_t key_no) : key_number{key_no} {}
    };

    template <>
    struct key<cipher_type::des> : public impl::key_base<8, cipher_des> {
        key() = default;
        key(std::uint8_t key_no, key_t k) : impl::key_base<8, cipher_des>{.key_number = key_no, .k = k} {}
    };

    template <>
    struct key<cipher_type::des3_2k> : public impl::key_base<16, cipher_2k3des> {
        key() = default;
        key(std::uint8_t key_no, key_t k) : impl::key_base<16, cipher_2k3des>{.key_number = key_no, .k = k} {}
    };

    template <>
    struct key<cipher_type::des3_3k> : public impl::key_base<24, cipher_3k3des> {
        key() = default;
        key(std::uint8_t key_no, key_t k) : impl::key_base<24, cipher_3k3des>{.key_number = key_no, .k = k} {}
    };

    template <>
    struct key<cipher_type::aes128> : public impl::key_base<16, cipher_aes> {
        key() = default;
        key(std::uint8_t key_no, key_t k) : impl::key_base<16, cipher_aes>{.key_number = key_no, .k = k} {}
    };


    class any_key {
        cipher_type _type;
        any _key;
    public:
        inline any_key();

        template <cipher_type Type>
        inline explicit any_key(key<Type> entry);

        inline cipher_type type() const;

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
        }
    }

}

#endif //DESFIRE_DATA_HPP
