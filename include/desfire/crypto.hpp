//
// Created by spak on 5/6/21.
//

#ifndef DESFIRE_CRYPTO_HPP
#define DESFIRE_CRYPTO_HPP

#include <cstdint>
#include <desfire/bits.hpp>
#include <desfire/cmac_provider.hpp>
#include <mlab/bin_data.hpp>

namespace desfire {
    namespace {
        using mlab::bin_data;
        using mlab::range;
    }// namespace
    using bits::cipher_type;

    enum struct crypto_operation {
        encrypt,
        decrypt,
        mac
    };

    class crypto {
    public:
        [[nodiscard]] virtual desfire::cipher_type cipher_type() const = 0;
        virtual void setup_with_key(range<std::uint8_t const *> key) = 0;
        virtual void init_session(range<std::uint8_t const *> random_data) = 0;
        virtual void do_crypto(range<std::uint8_t *> data, range<std::uint8_t *> iv, crypto_operation op) = 0;
        virtual ~crypto() = default;
    };

    class crypto_with_cmac : public crypto {
        cmac_provider _cmac;

    protected:
        crypto_with_cmac(std::uint8_t block_size, std::uint8_t last_byte_xor);
        virtual void setup_primitives_with_key(range<std::uint8_t const *> key) = 0;

    public:
        using mac_t = std::array<std::uint8_t, 8>;
        virtual mac_t do_cmac(range<std::uint8_t const *> data, range<std::uint8_t *> iv);
        [[nodiscard]] std::size_t block_size() const;
        void setup_with_key(range<std::uint8_t const *> key) override;
    };

    class crypto_des_base : public crypto {
    public:
        [[nodiscard]] inline desfire::cipher_type cipher_type() const final;
        void init_session(range<std::uint8_t const *> random_data) final;
    };

    class crypto_2k3des_base : public crypto {
        bool _degenerate = false;

    public:
        [[nodiscard]] inline bool is_degenerate() const;
        [[nodiscard]] inline desfire::cipher_type cipher_type() const final;
        void setup_with_key(range<std::uint8_t const *> key) override;
        void init_session(range<std::uint8_t const *> random_data) final;
    };

    class crypto_3k3des_base : public crypto_with_cmac {
    public:
        crypto_3k3des_base();
        [[nodiscard]] inline desfire::cipher_type cipher_type() const final;
        void init_session(range<std::uint8_t const *> random_data) final;
    };

    class crypto_aes_base : public crypto_with_cmac {
    public:
        crypto_aes_base();
        [[nodiscard]] inline desfire::cipher_type cipher_type() const final;
        void init_session(range<std::uint8_t const *> random_data) final;
    };

}// namespace desfire

namespace desfire {
    bool crypto_2k3des_base::is_degenerate() const {
        return _degenerate;
    }

    desfire::cipher_type crypto_des_base::cipher_type() const {
        return cipher_type::des;
    }

    desfire::cipher_type crypto_2k3des_base::cipher_type() const {
        return cipher_type::des3_2k;
    }

    desfire::cipher_type crypto_3k3des_base::cipher_type() const {
        return cipher_type::des3_3k;
    }

    desfire::cipher_type crypto_aes_base::cipher_type() const {
        return cipher_type::aes128;
    }

}// namespace desfire

#endif//DESFIRE_CRYPTO_HPP
