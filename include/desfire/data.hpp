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
            key_t k;

            std::unique_ptr<cipher> make_cipher() const {
                return std::unique_ptr<Cipher>(new Cipher(k));
            }
        };

    }

    template <cipher_type>
    struct key {
        std::unique_ptr<cipher> make_cipher() const { return nullptr; }
    };

    template <>
    struct key<cipher_type::des> : public impl::key_base<8, cipher_des> {
        key() = default;
        explicit key(key_t k) : impl::key_base<8, cipher_des>{.k = k} {}
    };

    template <>
    struct key<cipher_type::des3_2k> : public impl::key_base<16, cipher_2k3des> {
        key() = default;
        explicit key(key_t k) : impl::key_base<16, cipher_2k3des>{.k = k} {}
    };

    template <>
    struct key<cipher_type::des3_3k> : public impl::key_base<24, cipher_3k3des> {
        key() = default;
        explicit key(key_t k) : impl::key_base<24, cipher_3k3des>{.k = k} {}
    };

    template <>
    struct key<cipher_type::aes128> : public impl::key_base<16, cipher_aes> {
        key() = default;
        explicit key(key_t k) : impl::key_base<16, cipher_aes>{.k = k} {}
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
