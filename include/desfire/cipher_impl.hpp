//
// Created by Pietro Saccardi on 02/01/2021.
//

#ifndef DESFIRE_CIPHER_IMPL_HPP
#define DESFIRE_CIPHER_IMPL_HPP

/**
 * @note ''esp_config.h'' must be included before ''aes.h'' to enable hardware AES.
 * @{
 */
#include <mbedtls/esp_config.h>
/**
 * @}
 */

#include <mbedtls/aes.h>
#include <mbedtls/des.h>

#include "cipher_scheme.hpp"
#include "cipher_scheme_legacy.hpp"

namespace desfire {

    class cipher_des final : public cipher_scheme_legacy {
        mbedtls_des_context _enc_context;
        mbedtls_des_context _dec_context;
        mbedtls_des_context _mac_enc_context;

    public:
        explicit cipher_des(std::array<std::uint8_t, 8> const &key);
        void reinit_with_session_key(bin_data const &rndab) override;
        ~cipher_des() override;

        void do_crypto(range<bin_data::iterator> const &data, crypto_direction dir, block_t &iv) override;
    };

    class cipher_2k3des final : public cipher_scheme_legacy {
        mbedtls_des3_context _enc_context;
        mbedtls_des3_context _dec_context;
        mbedtls_des3_context _mac_enc_context;
        bool _degenerate;

    public:
        explicit cipher_2k3des(std::array<std::uint8_t, 16> const &key);
        void reinit_with_session_key(bin_data const &rndab) override;
        ~cipher_2k3des() override;

        void do_crypto(range<bin_data::iterator> const &data, crypto_direction dir, block_t &iv) override;
    };

    class cipher_3k3des final : public cipher_scheme<8, 0x1b> {
        mbedtls_des3_context _enc_context;
        mbedtls_des3_context _dec_context;

    public:
        explicit cipher_3k3des(std::array<std::uint8_t, 24> const &key);
        void reinit_with_session_key(bin_data const &rndab) override;
        ~cipher_3k3des() override;

        void do_crypto(range<bin_data::iterator> const &data, crypto_direction dir, block_t &iv) override;
    };

    class cipher_aes final : public cipher_scheme<16, 0x87> {
        mbedtls_aes_context _enc_context;
        mbedtls_aes_context _dec_context;

    public:
        explicit cipher_aes(std::array<std::uint8_t, 16> const &key);
        void reinit_with_session_key(bin_data const &rndab) override;
        ~cipher_aes() override;

        void do_crypto(range<bin_data::iterator> const &data, crypto_direction dir, block_t &iv) override;
    };

    /**
     * @todo Move
     */
    class cipher_dummy final : public cipher {
    public:
        void prepare_tx(bin_data &, std::size_t, cipher_mode mode) override {
            if (mode != cipher_mode::plain) {
                DESFIRE_LOGE("Dummy cipher supports only plain comm mode.");
            }
        }

        bool confirm_rx(bin_data &, cipher_mode mode) override {
            if (mode != cipher_mode::plain) {
                DESFIRE_LOGE("Dummy cipher supports only plain comm mode.");
                return false;
            }
            return true;
        }

        void reinit_with_session_key(bin_data const &) override {}
    };
}// namespace desfire

#endif//DESFIRE_CIPHER_IMPL_HPP
