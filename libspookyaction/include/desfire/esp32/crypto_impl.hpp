//
// Created by spak on 5/4/21.
//

#ifndef DESFIRE_ESP32_CRYPTO_IMPL_HPP
#define DESFIRE_ESP32_CRYPTO_IMPL_HPP

#include <desfire/cipher_provider.hpp>
#include <desfire/crypto.hpp>

#include <sdkconfig.h>

/**
 * Detect SSL library to use, either MbedTLS or WolfSSL.
 * This can be overridden by ''-DSPOOKY_USE_WOLFSSL'' or ''-DSPOOKY_USE_MBEDTLS''.
 * The library user is responsible to provide the necessary component.
 * @{
 */

#if defined(SPOOKY_USE_WOLFSSL) and defined(CONFIG_ESP_TLS_USING_MBEDTLS)
#warning "libSpookyAciton: you are forcing WolfSSL but ESP-IDF will use MbedTLS!"
#elif defined(SPOOKY_USE_MBEDTLS) and defined(CONFIG_ESP_TLS_USING_WOLFSSL)
#warning "libSpookyAciton: you are forcing MbedTLS but ESP-IDF will use WolfSSL!"
#elif not defined(SPOOKY_USE_MBEDTLS) and defined(CONFIG_ESP_TLS_USING_MBEDTLS)
#define SPOOKY_USE_MBEDTLS
#elif not defined(SPOOKY_USE_WOLFSSL) and defined(CONFIG_ESP_TLS_USING_WOLFSSL)
#define SPOOKY_USE_WOLFSSL
#endif

/**
 * @}
 */

#if defined(SPOOKY_USE_MBEDTLS)

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

#elif defined(SPOOKY_USE_WOLFSSL)

/**
 * @note ''user_settings.h'' must be included before any WolfSSL header to import the right constants.
 * @warning Here be hacks. Esp-wolfssl provides a ''user_settings.h'' file which removes 3DES. We check for the presence of this constant,
 * since we need 3DES. However, wolfssl searches for that header using quotes, so we include it with the quotes too. This presents us with
 * a hack opportunity: if we specify a ''-iquote'' compile flag, we can insert out custom ''user_settings.h'' in front of the one provided
 * by esp-wolfssl (because the path where it resides is included with ''-I'', and ''-iquote'' takes priority). This way we can include
 * esp-wolfssl as a submodule, leave the repo as-is, and replace the settings with our custom file.
 * @{
 */
#include "user_settings.h"
#ifdef NO_DES3
#error "libSpookyAction: NO_DES3 macro defined -- update your user_settings.h for WolfSSL and remove the definition. We need DES3 ciphers."
#endif
/**
 * @}
 */

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/des3.h>

/**
 * @note We need to fix the LOG_LOCAL_LEVEL override.
 * @{
 */
#undef LOG_LOCAL_LEVEL
#define LOG_LOCAL_LEVEL CONFIG_LOG_MAXIMUM_LEVEL
/**
  * @}
  */

#endif

namespace desfire::esp32 {

    class crypto_des final : public crypto_des_base {
#if defined(SPOOKY_USE_MBEDTLS)
        mbedtls_des_context _enc_context;
        mbedtls_des_context _dec_context;
#elif defined(SPOOKY_USE_WOLFSSL)
        Des _enc_context{};
        Des _dec_context{};
#endif

    public:
        void setup_with_key(range<std::uint8_t const *> key) override;
        void do_crypto(range<std::uint8_t *> data, range<std::uint8_t *> iv, crypto_operation op) override;
#ifdef SPOOKY_USE_MBEDTLS
        crypto_des();
        ~crypto_des() override;
#endif//SPOOKY_USE_MBEDTLS
    };

    class crypto_2k3des final : public crypto_2k3des_base {
#if defined(SPOOKY_USE_MBEDTLS)
        mbedtls_des3_context _enc_context;
        mbedtls_des3_context _dec_context;
#elif defined(SPOOKY_USE_WOLFSSL)
        Des3 _enc_context{};
        Des3 _dec_context{};
#endif
    protected:
        void setup_primitives_with_key(range<std::uint8_t const *> key) override;

    public:
        void do_crypto(range<std::uint8_t *> data, range<std::uint8_t *> iv, crypto_operation op) override;
#ifdef SPOOKY_USE_MBEDTLS
        crypto_2k3des();
        ~crypto_2k3des() override;
#endif//SPOOKY_USE_MBEDTLS
    };

    class crypto_3k3des final : public crypto_3k3des_base {
#if defined(SPOOKY_USE_MBEDTLS)
        mbedtls_des3_context _enc_context;
        mbedtls_des3_context _dec_context;
#elif defined(SPOOKY_USE_WOLFSSL)
        Des3 _enc_context{};
        Des3 _dec_context{};
#endif

    public:
        void do_crypto(range<std::uint8_t *> data, range<std::uint8_t *> iv, crypto_operation op) override;

#ifdef SPOOKY_USE_MBEDTLS
        crypto_3k3des();
        ~crypto_3k3des() override;
#endif//SPOOKY_USE_MBEDTLS

    protected:
        void setup_primitives_with_key(range<std::uint8_t const *> key) override;
    };

    class crypto_aes final : public crypto_aes_base {
#if defined(SPOOKY_USE_MBEDTLS)
        mbedtls_aes_context _enc_context;
        mbedtls_aes_context _dec_context;
#elif defined(SPOOKY_USE_WOLFSSL)
        Aes _enc_context{};
        Aes _dec_context{};
#endif

    public:
        void do_crypto(range<std::uint8_t *> data, range<std::uint8_t *> iv, crypto_operation op) override;

#ifdef SPOOKY_USE_MBEDTLS
        crypto_aes();
        ~crypto_aes() override;
#endif//SPOOKY_USE_MBEDTLS

    protected:
        void setup_primitives_with_key(range<std::uint8_t const *> key) override;
    };

    using default_cipher_provider = typed_cipher_provider<crypto_des, crypto_2k3des, crypto_3k3des, crypto_aes>;
}// namespace desfire::esp32

#endif//DESFIRE_ESP32_CRYPTO_IMPL_HPP
