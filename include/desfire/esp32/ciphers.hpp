//
// Created by spak on 5/4/21.
//

#ifndef DESFIRE_ESP32_CIPHERS_HPP
#define DESFIRE_ESP32_CIPHERS_HPP

#include <desfire/crypto_base.hpp>

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

namespace desfire::esp32 {

    class crypto_des final : public crypto_des_base {
        mbedtls_des_context _enc_context;
        mbedtls_des_context _dec_context;
        mbedtls_des_context _mac_enc_context;
    public:
        void setup_with_key(range<std::uint8_t const *> key) override;
        void do_crypto(range<std::uint8_t *> data, range<std::uint8_t *> iv, crypto_operation op) override;
        crypto_des();
        ~crypto_des() override;
    };

    class crypto_2k3des final : public crypto_2k3des_base {
        mbedtls_des3_context _enc_context;
        mbedtls_des3_context _dec_context;
        mbedtls_des3_context _mac_enc_context;
    public:
        void setup_with_key(range<std::uint8_t const *> key) override;
        void do_crypto(range<std::uint8_t *> data, range<std::uint8_t *> iv, crypto_operation op) override;
        crypto_2k3des();
        ~crypto_2k3des() override;
    };

    class crypto_3k3des final : public crypto_3k3des_base {
        mbedtls_des3_context _enc_context;
        mbedtls_des3_context _dec_context;
    public:
        void setup_with_key(range<std::uint8_t const *> key) override;
        void do_crypto(range<std::uint8_t *> data, range<std::uint8_t *> iv, crypto_operation op) override;
        crypto_3k3des();
        ~crypto_3k3des() override;
    };

    class crypto_aes final : public crypto_aes_base {
        mbedtls_aes_context _enc_context;
        mbedtls_aes_context _dec_context;
    public:
        void setup_with_key(range<std::uint8_t const *> key) override;
        void do_crypto(range<std::uint8_t *> data, range<std::uint8_t *> iv, crypto_operation op) override;
        crypto_aes();
        ~crypto_aes() override;
    };

}

#endif//DESFIRE_ESP32_CIPHERS_HPP
