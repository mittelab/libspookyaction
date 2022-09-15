//
// Created by spak on 5/4/21.
//

#ifndef DESFIRE_ESP32_CRYPTO_IMPL_HPP
#define DESFIRE_ESP32_CRYPTO_IMPL_HPP

#include <desfire/cipher_provider.hpp>
#include <desfire/crypto.hpp>

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

/**
 * Guard against missing the definition of CONFIG_MBEDTLS_DES_C.
 */
#ifndef MBEDTLS_DES_C
#error "libSpookyAction: config macro CONFIG_MBEDTLS_DES_C not found; make sure you have CONFIG_MBEDTLS_DES_C=y in your sdkconfig!"
#endif

namespace desfire::esp32 {

    class crypto_des final : public crypto_des_base {
        mbedtls_des_context _enc_context;
        mbedtls_des_context _dec_context;
        mbedtls_des_context _mac_enc_context;

    protected:
        void setup_primitives_with_key(range<std::uint8_t const *> key) override;

    public:
        void do_crypto(range<std::uint8_t *> data, range<std::uint8_t *> iv, crypto_operation op) override;
        crypto_des();
        ~crypto_des() override;
    };

    class crypto_2k3des final : public crypto_2k3des_base {
        mbedtls_des3_context _enc_context;
        mbedtls_des3_context _dec_context;
        mbedtls_des3_context _mac_enc_context;

    protected:
        void setup_primitives_with_key(range<std::uint8_t const *> key) override;

    public:
        void do_crypto(range<std::uint8_t *> data, range<std::uint8_t *> iv, crypto_operation op) override;
        crypto_2k3des();
        ~crypto_2k3des() override;
    };

    class crypto_3k3des final : public crypto_3k3des_base {
        mbedtls_des3_context _enc_context;
        mbedtls_des3_context _dec_context;

    public:
        void do_crypto(range<std::uint8_t *> data, range<std::uint8_t *> iv, crypto_operation op) override;
        crypto_3k3des();
        ~crypto_3k3des() override;

    protected:
        void setup_primitives_with_key(range<std::uint8_t const *> key) override;
    };

    class crypto_aes final : public crypto_aes_base {
        mbedtls_aes_context _enc_context;
        mbedtls_aes_context _dec_context;

    public:
        void do_crypto(range<std::uint8_t *> data, range<std::uint8_t *> iv, crypto_operation op) override;
        crypto_aes();
        ~crypto_aes() override;

    protected:
        void setup_primitives_with_key(range<std::uint8_t const *> key) override;
    };

    using default_cipher_provider = typed_cipher_provider<crypto_des, crypto_2k3des, crypto_3k3des, crypto_aes>;
}// namespace desfire::esp32

#endif//DESFIRE_ESP32_CRYPTO_IMPL_HPP
