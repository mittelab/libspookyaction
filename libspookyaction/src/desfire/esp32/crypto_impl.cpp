//
// Created by spak on 5/4/21.
//

#include <desfire/esp32/crypto_impl.hpp>
#include <desfire/msg.hpp>


namespace desfire::esp32 {

    namespace {
        [[nodiscard]] const char *input_tag(crypto_operation op) {
            if (op == crypto_operation::decrypt) {
                return DESFIRE_LOG_PREFIX " BLOB";
            } else {
                return DESFIRE_LOG_PREFIX " DATA";
            }
        }
        [[nodiscard]] const char *output_tag(crypto_operation op) {
            if (op == crypto_operation::decrypt) {
                return DESFIRE_LOG_PREFIX " DATA";
            } else {
                return DESFIRE_LOG_PREFIX " BLOB";
            }
        }

#ifdef SPOOKY_USE_WOLFSSL
        void copy_wolfssl_iv(const word32 reg[], range<std::uint8_t *> iv) {
            std::copy_n(reinterpret_cast<std::uint8_t const *>(reg), iv.size(), std::begin(iv));
        }
#endif
    }// namespace


    void crypto_des::setup_with_key(range<std::uint8_t const *> key) {
        if (key.size() != 8) {
            DESFIRE_LOGE("DES: invalid key size %d, expected 8 bytes.", key.size());
            return;
        }
#if defined(SPOOKY_USE_MBEDTLS)
        mbedtls_des_setkey_enc(&_enc_context, std::begin(key));
        mbedtls_des_setkey_dec(&_dec_context, std::begin(key));
#elif defined(SPOOKY_USE_WOLFSSL)
        wc_Des_SetKey(&_enc_context, std::begin(key), nullptr, DES_ENCRYPTION);
        wc_Des_SetKey(&_dec_context, std::begin(key), nullptr, DES_DECRYPTION);
#endif
    }

    void crypto_des::do_crypto(range<std::uint8_t *> data, range<std::uint8_t *> iv, crypto_operation op) {
        ESP_LOGD(DESFIRE_LOG_PREFIX " CRYPTO", "DES: %s %u bytes.", desfire::to_string(op), std::distance(std::begin(data), std::end(data)));
        ESP_LOG_BUFFER_HEX_LEVEL(input_tag(op), data.data(), data.size(), ESP_LOG_DEBUG);
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_LOG_PREFIX "IN IV", iv.data(), iv.size(), ESP_LOG_DEBUG);
        assert(data.size() % 8 == 0);
        /**
         * @note Using @ref _dec_context with encrypt operation is **deliberate**, see note on
         * @ref cipher_scheme_legacy.
         */
#if defined(SPOOKY_USE_MBEDTLS)
        switch (op) {
            case crypto_operation::encrypt:
                mbedtls_des_crypt_cbc(&_dec_context, MBEDTLS_DES_ENCRYPT, data.size(), iv.data(), data.data(), data.data());
                break;
            case crypto_operation::decrypt:
                mbedtls_des_crypt_cbc(&_dec_context, MBEDTLS_DES_DECRYPT, data.size(), iv.data(), data.data(), data.data());
                break;
            case crypto_operation::mac:
                mbedtls_des_crypt_cbc(&_enc_context, MBEDTLS_DES_ENCRYPT, data.size(), iv.data(), data.data(), data.data());
                break;
        }
#elif defined(SPOOKY_USE_WOLFSSL)
        switch (op) {
            case crypto_operation::encrypt:
                wc_Des_SetIV(&_dec_context, std::begin(iv));
                wc_Des_CbcEncrypt(&_dec_context, data.data(), data.data(), data.size());
                copy_wolfssl_iv(_dec_context.reg, iv);
                break;
            case crypto_operation::decrypt:
                wc_Des_SetIV(&_dec_context, std::begin(iv));
                wc_Des_CbcDecrypt(&_dec_context, data.data(), data.data(), data.size());
                copy_wolfssl_iv(_dec_context.reg, iv);
                break;
            case crypto_operation::mac:
                wc_Des_SetIV(&_enc_context, std::begin(iv));
                wc_Des_CbcEncrypt(&_enc_context, data.data(), data.data(), data.size());
                copy_wolfssl_iv(_enc_context.reg, iv);
                break;
        }
#endif
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_LOG_PREFIX "OUTIV", iv.data(), iv.size(), ESP_LOG_DEBUG);
        ESP_LOG_BUFFER_HEX_LEVEL(output_tag(op), data.data(), data.size(), ESP_LOG_DEBUG);
    }

    void crypto_2k3des::setup_primitives_with_key(range<std::uint8_t const *> key) {
        if (key.size() != 16) {
            DESFIRE_LOGE("2K3DES: invalid key size %d, expected 16 bytes.", key.size());
            return;
        }
#if defined(SPOOKY_USE_MBEDTLS)
        mbedtls_des3_set2key_enc(&_enc_context, std::begin(key));
        mbedtls_des3_set2key_dec(&_dec_context, std::begin(key));
#elif defined(SPOOKY_USE_WOLFSSL)
        // Expand the key to a 2TDEA key
        std::array<std::uint8_t, 24> des3_2k{};
        std::copy(std::begin(key), std::end(key), std::begin(des3_2k));
        std::copy_n(std::begin(key), 8, std::begin(des3_2k) + 16);
        // Now setup like a 3DES
        wc_Des3_SetKey(&_enc_context, std::begin(des3_2k), nullptr, DES_ENCRYPTION);
        wc_Des3_SetKey(&_dec_context, std::begin(des3_2k), nullptr, DES_DECRYPTION);
#endif
    }

    void crypto_2k3des::do_crypto(range<std::uint8_t *> data, range<std::uint8_t *> iv, crypto_operation op) {
        ESP_LOGD(DESFIRE_LOG_PREFIX " CRYPTO", "2K3DES: %s %u bytes.", to_string(op), std::distance(std::begin(data), std::end(data)));
        ESP_LOG_BUFFER_HEX_LEVEL(input_tag(op), data.data(), data.size(), ESP_LOG_DEBUG);
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_LOG_PREFIX "   IV", iv.data(), iv.size(), ESP_LOG_DEBUG);
        assert(data.size() % 8 == 0);
        /**
         * @note Using @ref _dec_context with encrypt operation is **deliberate**, see note on
         * @ref cipher_scheme_legacy.
         */
#if defined(SPOOKY_USE_MBEDTLS)
        switch (op) {
            case crypto_operation::encrypt:
                mbedtls_des3_crypt_cbc(&_dec_context, MBEDTLS_DES_ENCRYPT, data.size(), iv.data(), data.data(), data.data());
                break;
            case crypto_operation::decrypt:
                mbedtls_des3_crypt_cbc(&_dec_context, MBEDTLS_DES_DECRYPT, data.size(), iv.data(), data.data(), data.data());
                break;
            case crypto_operation::mac:
                mbedtls_des3_crypt_cbc(&_enc_context, MBEDTLS_DES_ENCRYPT, data.size(), iv.data(), data.data(), data.data());
                break;
        }
#elif defined(SPOOKY_USE_WOLFSSL)
        switch (op) {
            case crypto_operation::encrypt:
                wc_Des3_SetIV(&_dec_context, iv.data());
                wc_Des3_CbcEncrypt(&_dec_context, data.data(), data.data(), data.size());
                copy_wolfssl_iv(_dec_context.reg, iv);
                break;
            case crypto_operation::decrypt:
                wc_Des3_SetIV(&_dec_context, iv.data());
                wc_Des3_CbcDecrypt(&_dec_context, data.data(), data.data(), data.size());
                copy_wolfssl_iv(_dec_context.reg, iv);
                break;
            case crypto_operation::mac:
                wc_Des3_SetIV(&_enc_context, iv.data());
                wc_Des3_CbcEncrypt(&_enc_context, data.data(), data.data(), data.size());
                copy_wolfssl_iv(_enc_context.reg, iv);
                break;
        }
#endif
        ESP_LOG_BUFFER_HEX_LEVEL(output_tag(op), data.data(), data.size(), ESP_LOG_DEBUG);
    }

    void crypto_3k3des::setup_primitives_with_key(range<std::uint8_t const *> key) {
        if (key.size() != 24) {
            DESFIRE_LOGE("3K3DES: invalid key size %d, expected 24 bytes.", key.size());
            return;
        }
#if defined(SPOOKY_USE_MBEDTLS)
        mbedtls_des3_set3key_enc(&_enc_context, std::begin(key));
        mbedtls_des3_set3key_dec(&_dec_context, std::begin(key));
#elif defined(SPOOKY_USE_WOLFSSL)
        wc_Des3_SetKey(&_enc_context, key.data(), nullptr, DES_ENCRYPTION);
        wc_Des3_SetKey(&_dec_context, key.data(), nullptr, DES_DECRYPTION);
#endif
    }

    void crypto_3k3des::do_crypto(range<std::uint8_t *> data, range<std::uint8_t *> iv, crypto_operation op) {
        ESP_LOGD(DESFIRE_LOG_PREFIX " CRYPTO", "3K3DES: %s %u bytes.", to_string(op), std::distance(std::begin(data), std::end(data)));
        ESP_LOG_BUFFER_HEX_LEVEL(input_tag(op), data.data(), data.size(), ESP_LOG_DEBUG);
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_LOG_PREFIX "   IV", iv.data(), iv.size(), ESP_LOG_DEBUG);
        assert(data.size() % 8 == 0);
#if defined(SPOOKY_USE_MBEDTLS)
        switch (op) {
            case crypto_operation::mac:
                [[fallthrough]];
            case crypto_operation::encrypt:
                mbedtls_des3_crypt_cbc(&_enc_context, MBEDTLS_DES_ENCRYPT, data.size(), iv.data(), data.data(), data.data());
                break;
            case crypto_operation::decrypt:
                mbedtls_des3_crypt_cbc(&_dec_context, MBEDTLS_DES_DECRYPT, data.size(), iv.data(), data.data(), data.data());
                break;
        }
#elif defined(SPOOKY_USE_WOLFSSL)
        switch (op) {
            case crypto_operation::mac:
                [[fallthrough]];
            case crypto_operation::encrypt:
                wc_Des3_SetIV(&_enc_context, iv.data());
                wc_Des3_CbcEncrypt(&_enc_context, data.data(), data.data(), data.size());
                copy_wolfssl_iv(_enc_context.reg, iv);
                break;
            case crypto_operation::decrypt:
                wc_Des3_SetIV(&_dec_context, iv.data());
                wc_Des3_CbcDecrypt(&_dec_context, data.data(), data.data(), data.size());
                copy_wolfssl_iv(_dec_context.reg, iv);
                break;
        }
#endif
        ESP_LOG_BUFFER_HEX_LEVEL(output_tag(op), data.data(), data.size(), ESP_LOG_DEBUG);
    }

    void crypto_aes::setup_primitives_with_key(range<std::uint8_t const *> key) {
        if (key.size() != 16) {
            DESFIRE_LOGE("AES: invalid key size %d, expected 24 bytes.", key.size());
            return;
        }
#if defined(SPOOKY_USE_MBEDTLS)
        mbedtls_aes_setkey_enc(&_enc_context, std::begin(key), 8 * key.size());
        mbedtls_aes_setkey_dec(&_dec_context, std::begin(key), 8 * key.size());
#elif defined(SPOOKY_USE_WOLFSSL)
        wc_AesSetKey(&_enc_context, key.data(), key.size(), nullptr, AES_ENCRYPTION);
        wc_AesSetKey(&_dec_context, key.data(), key.size(), nullptr, AES_DECRYPTION);
#endif
    }

    void crypto_aes::do_crypto(range<std::uint8_t *> data, range<std::uint8_t *> iv, crypto_operation op) {
        ESP_LOGD(DESFIRE_LOG_PREFIX " CRYPTO", "AES128: %s %u bytes.", to_string(op), std::distance(std::begin(data), std::end(data)));
        ESP_LOG_BUFFER_HEX_LEVEL(input_tag(op), data.data(), data.size(), ESP_LOG_DEBUG);
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_LOG_PREFIX "   IV", iv.data(), iv.size(), ESP_LOG_DEBUG);
        assert(data.size() % 16 == 0);
#if defined(SPOOKY_USE_MBEDTLS)
        switch (op) {
            case crypto_operation::mac:
                [[fallthrough]];
            case crypto_operation::encrypt:
                mbedtls_aes_crypt_cbc(&_enc_context, MBEDTLS_AES_ENCRYPT, data.size(), iv.data(), data.data(), data.data());
                break;
            case crypto_operation::decrypt:
                mbedtls_aes_crypt_cbc(&_dec_context, MBEDTLS_AES_DECRYPT, data.size(), iv.data(), data.data(), data.data());
                break;
        }
#elif defined(SPOOKY_USE_WOLFSSL)
        switch (op) {
            case crypto_operation::mac:
                [[fallthrough]];
            case crypto_operation::encrypt:
                wc_AesSetIV(&_enc_context, iv.data());
                wc_AesCbcEncrypt(&_enc_context, data.data(), data.data(), data.size());
                copy_wolfssl_iv(_enc_context.reg, iv);
                break;
            case crypto_operation::decrypt:
                wc_AesSetIV(&_dec_context, iv.data());
                wc_AesCbcDecrypt(&_dec_context, data.data(), data.data(), data.size());
                copy_wolfssl_iv(_dec_context.reg, iv);
                break;
        }
#endif
        ESP_LOG_BUFFER_HEX_LEVEL(output_tag(op), data.data(), data.size(), ESP_LOG_DEBUG);
    }

#if defined(SPOOKY_USE_MBEDTLS)
    crypto_des::crypto_des() : _enc_context{}, _dec_context{} {
        mbedtls_des_init(&_enc_context);
        mbedtls_des_init(&_dec_context);
    }

    crypto_des::~crypto_des() {
        mbedtls_des_free(&_enc_context);
        mbedtls_des_free(&_dec_context);
    }

    crypto_2k3des::crypto_2k3des() : _enc_context{}, _dec_context{} {
        mbedtls_des3_init(&_enc_context);
        mbedtls_des3_init(&_dec_context);
    }

    crypto_2k3des::~crypto_2k3des() {
        mbedtls_des3_free(&_enc_context);
        mbedtls_des3_free(&_dec_context);
    }

    crypto_3k3des::crypto_3k3des() : _enc_context{}, _dec_context{} {
        mbedtls_des3_init(&_enc_context);
        mbedtls_des3_init(&_dec_context);
    }

    crypto_3k3des::~crypto_3k3des() {
        mbedtls_des3_free(&_enc_context);
        mbedtls_des3_free(&_dec_context);
    }

    crypto_aes::crypto_aes() : _enc_context{}, _dec_context{} {
        mbedtls_aes_init(&_enc_context);
        mbedtls_aes_init(&_dec_context);
    }

    crypto_aes::~crypto_aes() {
        mbedtls_aes_free(&_enc_context);
        mbedtls_aes_free(&_dec_context);
    }
#endif//SPOOKY_USE_MBEDTLS

}// namespace desfire::esp32
