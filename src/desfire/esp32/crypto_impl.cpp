//
// Created by spak on 5/4/21.
//

#include "desfire/esp32/crypto_impl.hpp"
#include "desfire/msg.hpp"

namespace desfire::esp32 {

    namespace {
        [[nodiscard]] const char *input_tag(crypto_operation op) {
            if (op == crypto_operation::decrypt) {
                return DESFIRE_TAG " BLOB";
            } else {
                return DESFIRE_TAG " DATA";
            }
        }
        [[nodiscard]] const char *output_tag(crypto_operation op) {
            if (op == crypto_operation::decrypt) {
                return DESFIRE_TAG " DATA";
            } else {
                return DESFIRE_TAG " BLOB";
            }
        }
    }// namespace


    void crypto_des::setup_with_key(range<std::uint8_t const *> key) {
        if (key.size() != 8) {
            DESFIRE_LOGE("DES: invalid key size %d, expected 8 bytes.", key.size());
            return;
        }
        /**
         * @note Using @ref mbedtls_des_setkey_dec on @ref _enc_context is **deliberate**, see note on
         * @ref cipher_scheme_legacy.
         */
        mbedtls_des_setkey_dec(&_enc_context, std::begin(key));
        mbedtls_des_setkey_dec(&_dec_context, std::begin(key));
        mbedtls_des_setkey_enc(&_mac_enc_context, std::begin(key));
    }

    crypto_des::crypto_des() : _enc_context{}, _dec_context{}, _mac_enc_context{} {
        mbedtls_des_init(&_enc_context);
        mbedtls_des_init(&_dec_context);
        mbedtls_des_init(&_mac_enc_context);
    }

    crypto_des::~crypto_des() {
        mbedtls_des_free(&_enc_context);
        mbedtls_des_free(&_dec_context);
        mbedtls_des_free(&_mac_enc_context);
    }

    void crypto_des::do_crypto(range<std::uint8_t *> data, range<std::uint8_t *> iv, crypto_operation op) {
        ESP_LOGD(DESFIRE_TAG " CRYPTO", "DES: %s %u bytes.", desfire::to_string(op), std::distance(std::begin(data), std::end(data)));
        ESP_LOG_BUFFER_HEX_LEVEL(input_tag(op), data.data(), data.size(), ESP_LOG_DEBUG);
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG "   IV", iv.data(), iv.size(), ESP_LOG_DEBUG);
        assert(data.size() % 8 == 0);
        switch (op) {
            case crypto_operation::encrypt:
                mbedtls_des_crypt_cbc(&_enc_context, MBEDTLS_DES_ENCRYPT, data.size(), iv.data(), data.data(), data.data());
                break;
            case crypto_operation::decrypt:
                mbedtls_des_crypt_cbc(&_dec_context, MBEDTLS_DES_DECRYPT, data.size(), iv.data(), data.data(), data.data());
                break;
            case crypto_operation::mac:
                mbedtls_des_crypt_cbc(&_mac_enc_context, MBEDTLS_DES_ENCRYPT, data.size(), iv.data(), data.data(), data.data());
                break;
                break;
        }
        ESP_LOG_BUFFER_HEX_LEVEL(output_tag(op), data.data(), data.size(), ESP_LOG_DEBUG);
    }

    void crypto_2k3des::setup_with_key(range<std::uint8_t const *> key) {
        if (key.size() != 16) {
            DESFIRE_LOGE("2K3DES: invalid key size %d, expected 16 bytes.", key.size());
            return;
        }
        /**
         * @note Using @ref mbedtls_des3_set2key_dec on @ref _enc_context is **deliberate**, see note on
         * @ref cipher_scheme_legacy.
         */
        mbedtls_des3_set2key_dec(&_enc_context, std::begin(key));
        mbedtls_des3_set2key_dec(&_dec_context, std::begin(key));
        mbedtls_des3_set3key_enc(&_mac_enc_context, std::begin(key));
    }

    crypto_2k3des::crypto_2k3des() : _enc_context{}, _dec_context{}, _mac_enc_context{} {
        mbedtls_des3_init(&_enc_context);
        mbedtls_des3_init(&_dec_context);
        mbedtls_des3_init(&_mac_enc_context);
    }

    crypto_2k3des::~crypto_2k3des() {
        mbedtls_des3_free(&_enc_context);
        mbedtls_des3_free(&_dec_context);
        mbedtls_des3_free(&_mac_enc_context);
    }

    void crypto_2k3des::do_crypto(range<std::uint8_t *> data, range<std::uint8_t *> iv, crypto_operation op) {
        ESP_LOGD(DESFIRE_TAG " CRYPTO", "2K3DES: %s %u bytes.", to_string(op), std::distance(std::begin(data), std::end(data)));
        ESP_LOG_BUFFER_HEX_LEVEL(input_tag(op), data.data(), data.size(), ESP_LOG_DEBUG);
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG "   IV", iv.data(), iv.size(), ESP_LOG_DEBUG);
        assert(data.size() % 8 == 0);
        switch (op) {
            case crypto_operation::encrypt:
                mbedtls_des3_crypt_cbc(&_enc_context, MBEDTLS_DES_ENCRYPT, data.size(), iv.data(), data.data(), data.data());
                break;
            case crypto_operation::decrypt:
                mbedtls_des3_crypt_cbc(&_dec_context, MBEDTLS_DES_DECRYPT, data.size(), iv.data(), data.data(), data.data());
                break;
            case crypto_operation::mac:
                mbedtls_des3_crypt_cbc(&_mac_enc_context, MBEDTLS_DES_ENCRYPT, data.size(), iv.data(), data.data(), data.data());
                break;
                break;
        }
        ESP_LOG_BUFFER_HEX_LEVEL(output_tag(op), data.data(), data.size(), ESP_LOG_DEBUG);
    }

    void crypto_3k3des::setup_primitives_with_key(range<std::uint8_t const *> key) {
        if (key.size() != 24) {
            DESFIRE_LOGE("3K3DES: invalid key size %d, expected 24 bytes.", key.size());
            return;
        }
        mbedtls_des3_set3key_enc(&_enc_context, std::begin(key));
        mbedtls_des3_set3key_dec(&_dec_context, std::begin(key));
    }

    crypto_3k3des::crypto_3k3des() : _enc_context{}, _dec_context{} {
        mbedtls_des3_init(&_enc_context);
        mbedtls_des3_init(&_dec_context);
    }

    crypto_3k3des::~crypto_3k3des() {
        mbedtls_des3_free(&_enc_context);
        mbedtls_des3_free(&_dec_context);
    }

    void crypto_3k3des::do_crypto(range<std::uint8_t *> data, range<std::uint8_t *> iv, crypto_operation op) {
        ESP_LOGD(DESFIRE_TAG " CRYPTO", "3K3DES: %s %u bytes.", to_string(op), std::distance(std::begin(data), std::end(data)));
        ESP_LOG_BUFFER_HEX_LEVEL(input_tag(op), data.data(), data.size(), ESP_LOG_DEBUG);
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG "   IV", iv.data(), iv.size(), ESP_LOG_DEBUG);
        assert(data.size() % 8 == 0);
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
        ESP_LOG_BUFFER_HEX_LEVEL(output_tag(op), data.data(), data.size(), ESP_LOG_DEBUG);
    }

    void crypto_aes::setup_primitives_with_key(range<std::uint8_t const *> key) {
        if (key.size() != 16) {
            DESFIRE_LOGE("AES: invalid key size %d, expected 24 bytes.", key.size());
            return;
        }
        mbedtls_aes_setkey_enc(&_enc_context, std::begin(key), 8 * key.size());
        mbedtls_aes_setkey_dec(&_dec_context, std::begin(key), 8 * key.size());
    }

    crypto_aes::crypto_aes() : _enc_context{}, _dec_context{} {
        mbedtls_aes_init(&_enc_context);
        mbedtls_aes_init(&_dec_context);
    }

    crypto_aes::~crypto_aes() {
        mbedtls_aes_free(&_enc_context);
        mbedtls_aes_free(&_dec_context);
    }

    void crypto_aes::do_crypto(range<std::uint8_t *> data, range<std::uint8_t *> iv, crypto_operation op) {
        ESP_LOGD(DESFIRE_TAG " CRYPTO", "AES128: %s %u bytes.", to_string(op), std::distance(std::begin(data), std::end(data)));
        ESP_LOG_BUFFER_HEX_LEVEL(input_tag(op), data.data(), data.size(), ESP_LOG_DEBUG);
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG "   IV", iv.data(), iv.size(), ESP_LOG_DEBUG);
        assert(data.size() % 16 == 0);
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
        ESP_LOG_BUFFER_HEX_LEVEL(output_tag(op), data.data(), data.size(), ESP_LOG_DEBUG);
    }
}// namespace desfire::esp32