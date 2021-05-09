//
// Created by spak on 5/6/21.
//

#ifndef DESFIRE_CRYPTO_CIPHERS_BASE_HPP
#define DESFIRE_CRYPTO_CIPHERS_BASE_HPP

#include <cstdint>
#include <mlab/bin_data.hpp>
#include <desfire/crypto_cmac.hpp>

namespace desfire {
    namespace {
        using mlab::bin_data;
        using mlab::range;
    }

    enum struct crypto_operation {
        encrypt,
        decrypt,
        mac
    };

    class crypto {
    public:
        [[nodiscard]] virtual bits::cipher_type cipher_type() const = 0;
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
        void setup_with_key(range<std::uint8_t const *> key) override;
    };

    class crypto_des_base : public crypto {
    public:
        [[nodiscard]] inline bits::cipher_type cipher_type() const final;
        void init_session(range<std::uint8_t const *> random_data) final;
    };

    class crypto_2k3des_base : public crypto {
        bool _degenerate = false;
    public:
        [[nodiscard]] inline bool is_degenerate() const;
        [[nodiscard]] inline bits::cipher_type cipher_type() const final;
        void setup_with_key(range<std::uint8_t const *> key) override;
        void init_session(range<std::uint8_t const *> random_data) final;
    };

    class crypto_3k3des_base : public crypto_with_cmac {
    public:
        crypto_3k3des_base();
        [[nodiscard]] inline bits::cipher_type cipher_type() const final;
        void init_session(range<std::uint8_t const *> random_data) final;
    };

    class crypto_aes_base : public crypto_with_cmac {
    public:
        crypto_aes_base();
        [[nodiscard]] inline bits::cipher_type cipher_type() const final;
        void init_session(range<std::uint8_t const *> random_data) final;
    };

}

namespace desfire {
    bool crypto_2k3des_base::is_degenerate() const {
        return _degenerate;
    }

    bits::cipher_type crypto_des_base::cipher_type() const {
        return bits::cipher_type::des;
    }

    bits::cipher_type crypto_2k3des_base::cipher_type() const {
        return bits::cipher_type::des3_2k;
    }

    bits::cipher_type crypto_3k3des_base::cipher_type() const {
        return bits::cipher_type::des3_3k;
    }

    bits::cipher_type crypto_aes_base::cipher_type() const {
        return bits::cipher_type::aes128;
    }

}

#endif//DESFIRE_CRYPTO_CIPHERS_BASE_HPP
