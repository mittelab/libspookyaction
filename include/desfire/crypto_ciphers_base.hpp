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
        virtual void setup_with_key(range<std::uint8_t const *> key) = 0;
        virtual void init_session(range<std::uint8_t const *> random_data) = 0;
        virtual cmac_provider *cmac() { return nullptr; };
        virtual void do_crypto(range<std::uint8_t *> data, range<std::uint8_t *> iv, crypto_operation op) = 0;
        virtual ~crypto() = default;
    };

    class crypto_des_base : public virtual crypto {
    public:
        void init_session(range<std::uint8_t const *> random_data) final;
    };

    class crypto_2k3des_base : public virtual crypto {
        bool _degenerate = false;
    public:
        [[nodiscard]] inline bool is_degenerate() const;
        void setup_with_key(range<std::uint8_t const *> key) override;
        void init_session(range<std::uint8_t const *> random_data) final;
    };

    class crypto_3k3des_base : public virtual crypto {
        cmac_provider _cmac;
    public:
        crypto_3k3des_base();
        [[nodiscard]] cmac_provider *cmac() final;
        void init_session(range<std::uint8_t const *> random_data) final;
        void setup_with_key(range<std::uint8_t const *> key) final;
    protected:
        virtual void setup_with_key_primitive(range<std::uint8_t const *> key) = 0;
    };

    class crypto_aes_base : public virtual crypto {
        cmac_provider _cmac;
    public:
        crypto_aes_base();
        [[nodiscard]] cmac_provider *cmac() final;
        void init_session(range<std::uint8_t const *> random_data) final;
        void setup_with_key(range<std::uint8_t const *> key) final;
    protected:
        virtual void setup_with_key_primitive(range<std::uint8_t const *> key) = 0;
    };

}

namespace desfire {
    bool crypto_2k3des_base::is_degenerate() const {
        return _degenerate;
    }
}

#endif//DESFIRE_CRYPTO_CIPHERS_BASE_HPP
