//
// Created by Pietro Saccardi on 02/01/2021.
//

#ifndef DESFIRE_CIPHER_IMPL_HPP
#define DESFIRE_CIPHER_IMPL_HPP

#include <mbedtls/des.h>
#include <mbedtls/aes.h>
#include "cipher_scheme_impl.hpp"

namespace desfire {

    class cipher_des final : public cipher_legacy_scheme {
        mbedtls_des_context _enc_context;
        mbedtls_des_context _dec_context;
    public:
        explicit cipher_des(std::array<std::uint8_t, 8> const &key);
        void reinit_with_session_key(bin_data const &rndab) override;
        ~cipher_des() override;

        void do_crypto(range<bin_data::iterator> data, bool encrypt, block_t &iv) override;
    };

    class cipher_2k3des final : public cipher_legacy_scheme {
        mbedtls_des3_context _enc_context;
        mbedtls_des3_context _dec_context;

    public:
        explicit cipher_2k3des(std::array<std::uint8_t, 16> const &key);
        void reinit_with_session_key(bin_data const &rndab) override;
        ~cipher_2k3des() override;

        void do_crypto(range<bin_data::iterator> data, bool encrypt, block_t &iv) override;
    };

    class cipher_3k3des final : public cipher_scheme<8, 0x1b> {
        mbedtls_des3_context _enc_context;
        mbedtls_des3_context _dec_context;

    public:
        explicit cipher_3k3des(std::array<std::uint8_t, 24> const &key);
        void reinit_with_session_key(bin_data const &rndab) override;
        ~cipher_3k3des() override;

        void do_crypto(range<bin_data::iterator> data, bool encrypt, block_t &iv) override;
    };

    class cipher_aes final : public cipher_scheme<16, 0x87> {
        mbedtls_aes_context _enc_context;
        mbedtls_aes_context _dec_context;

    public:
        explicit cipher_aes(std::array<std::uint8_t, 16> const &key);
        void reinit_with_session_key(bin_data const &rndab) override;
        ~cipher_aes() override;

        void do_crypto(range<bin_data::iterator> data, bool encrypt, block_t &iv) override;
    };

    class cipher_dummy final : public cipher {
    public:
        void prepare_tx(bin_data &, std::size_t, config const &cfg) override {
            if (cfg.mode != comm_mode::plain) {
                DESFIRE_LOGE("Dummy cipher supports only plain comm mode.");
            }
        }
        bool confirm_rx(bin_data &, config const &cfg) override {
            if (cfg.mode != comm_mode::plain) {
                DESFIRE_LOGE("Dummy cipher supports only plain comm mode.");
                return false;
            }
            return true;
        }

        void encrypt(bin_data &) override {}

        void decrypt(bin_data &) override {}

        void reinit_with_session_key(bin_data const &) override {}
    };
}

#endif //DESFIRE_CIPHER_IMPL_HPP
