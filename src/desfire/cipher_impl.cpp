//
// Created by Pietro Saccardi on 02/01/2021.
//

#include <cassert>
#include "desfire/cipher_impl.hpp"

namespace desfire {

    cipher_des::cipher_des(std::array<std::uint8_t, 8> const &key) : _enc_context{}, _dec_context{} {
        mbedtls_des_init(&_enc_context);
        mbedtls_des_init(&_dec_context);
        mbedtls_des_setkey_enc(&_enc_context, key.data());
        mbedtls_des_setkey_dec(&_dec_context, key.data());
        initialize();
    }

    void cipher_des::reinit_with_session_key(bin_data const &rndab) {
        if (rndab.size() != 16) {
            DESFIRE_LOGE("Unsupported RndA || RndB length: %u != 16.", rndab.size());
            return;
        }
        std::array<std::uint8_t, 8> new_key{};
        const auto bsrc = std::begin(rndab);
        const auto btrg = std::begin(new_key);
        std::copy_n(bsrc, 4, btrg);
        std::copy_n(bsrc + 8, 4, btrg + 4);
        mbedtls_des_free(&_enc_context);
        mbedtls_des_free(&_dec_context);
        mbedtls_des_init(&_enc_context);
        mbedtls_des_init(&_dec_context);
        mbedtls_des_setkey_enc(&_enc_context, new_key.data());
        mbedtls_des_setkey_dec(&_dec_context, new_key.data());
        initialize();
    }

    cipher_des::~cipher_des() {
        mbedtls_des_free(&_enc_context);
        mbedtls_des_free(&_dec_context);
    }

    void cipher_des::do_crypto(range<bin_data::iterator> data, bool encrypt, cipher_des::block_t &iv) {
        DESFIRE_LOGD("DES: %s %u bytes.", (encrypt ? "encrypting" : "decrypting"), std::distance(std::begin(data), std::end(data)));
        ESP_LOG_BUFFER_HEX_LEVEL((encrypt ? DESFIRE_TAG " DATA" : DESFIRE_TAG " BLOB"), data.data(), data.size(), ESP_LOG_VERBOSE);
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG "   IV", iv.data(), iv.size(), ESP_LOG_VERBOSE);
        assert(data.size() % block_size == 0);
        if (encrypt) {
            mbedtls_des_crypt_cbc(&_enc_context, MBEDTLS_DES_ENCRYPT, data.size(), iv.data(), data.data(), data.data());
        } else {
            mbedtls_des_crypt_cbc(&_dec_context, MBEDTLS_DES_DECRYPT, data.size(), iv.data(), data.data(), data.data());
        }
        ESP_LOG_BUFFER_HEX_LEVEL((encrypt ? DESFIRE_TAG " BLOB" : DESFIRE_TAG " DATA"), data.data(), data.size(), ESP_LOG_VERBOSE);
    }

    cipher_2k3des::cipher_2k3des(std::array<std::uint8_t, 16> const &key) : _enc_context{}, _dec_context{} {
        mbedtls_des3_init(&_enc_context);
        mbedtls_des3_init(&_dec_context);
        mbedtls_des3_set2key_enc(&_enc_context, key.data());
        mbedtls_des3_set2key_enc(&_dec_context, key.data());
        initialize();
    }

    void cipher_2k3des::reinit_with_session_key(bin_data const &rndab) {
        if (rndab.size() != 16) {
            DESFIRE_LOGE("Unsupported RndA || RndB length: %u != 16.", rndab.size());
            return;
        }
        std::array<std::uint8_t, 16> new_key{};
        const auto bsrc = std::begin(rndab);
        const auto btrg = std::begin(new_key);
        std::copy_n(bsrc, 4, btrg);
        std::copy_n(bsrc + 8,  4, btrg + 4);
        std::copy_n(bsrc + 4,  4, btrg + 8);
        std::copy_n(bsrc + 12, 4, btrg + 12);
        mbedtls_des3_free(&_enc_context);
        mbedtls_des3_free(&_dec_context);
        mbedtls_des3_init(&_enc_context);
        mbedtls_des3_init(&_dec_context);
        mbedtls_des3_set2key_enc(&_enc_context, new_key.data());
        mbedtls_des3_set2key_dec(&_dec_context, new_key.data());
        initialize();
    }

    cipher_2k3des::~cipher_2k3des() {
        mbedtls_des3_free(&_enc_context);
        mbedtls_des3_free(&_dec_context);
    }

    void cipher_2k3des::do_crypto(range <bin_data::iterator> data, bool encrypt, cipher_2k3des::block_t &iv) {
        DESFIRE_LOGD("2K3DES: %s %u bytes.", (encrypt ? "encrypting" : "decrypting"), std::distance(std::begin(data), std::end(data)));
        ESP_LOG_BUFFER_HEX_LEVEL((encrypt ? DESFIRE_TAG " DATA" : DESFIRE_TAG " BLOB"), data.data(), data.size(), ESP_LOG_VERBOSE);
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG "   IV", iv.data(), iv.size(), ESP_LOG_VERBOSE);
        assert(data.size() % block_size == 0);
        if (encrypt) {
            mbedtls_des3_crypt_cbc(&_enc_context, MBEDTLS_DES_ENCRYPT, data.size(), iv.data(), data.data(), data.data());
        } else {
            mbedtls_des3_crypt_cbc(&_dec_context, MBEDTLS_DES_DECRYPT, data.size(), iv.data(), data.data(), data.data());
        }
        ESP_LOG_BUFFER_HEX_LEVEL((encrypt ? DESFIRE_TAG " BLOB" : DESFIRE_TAG " DATA"), data.data(), data.size(), ESP_LOG_VERBOSE);
    }

    cipher_3k3des::cipher_3k3des(std::array<std::uint8_t, 24> const &key) : _enc_context{}, _dec_context{} {
        mbedtls_des3_init(&_enc_context);
        mbedtls_des3_init(&_dec_context);
        mbedtls_des3_set3key_enc(&_enc_context, key.data());
        mbedtls_des3_set3key_enc(&_dec_context, key.data());
        initialize();
    }

    void cipher_3k3des::reinit_with_session_key(bin_data const &rndab) {
        if (rndab.size() != 32) {
            DESFIRE_LOGE("Unsupported RndA || RndB length: %u != 32.", rndab.size());
            return;
        }
        std::array<std::uint8_t, 24> new_key{};
        const auto bsrc = std::begin(rndab);
        const auto btrg = std::begin(new_key);
        std::copy_n(bsrc, 4, btrg);
        std::copy_n(bsrc + 16, 4, btrg + 4);
        std::copy_n(bsrc + 6,  4, btrg + 8);
        std::copy_n(bsrc + 22, 4, btrg + 12);
        std::copy_n(bsrc + 12, 4, btrg + 16);
        std::copy_n(bsrc + 28, 4, btrg + 20);
        mbedtls_des3_free(&_enc_context);
        mbedtls_des3_free(&_dec_context);
        mbedtls_des3_init(&_enc_context);
        mbedtls_des3_init(&_dec_context);
        mbedtls_des3_set3key_enc(&_enc_context, new_key.data());
        mbedtls_des3_set3key_dec(&_dec_context, new_key.data());
        initialize();
    }

    cipher_3k3des::~cipher_3k3des() {
        mbedtls_des3_free(&_enc_context);
        mbedtls_des3_free(&_dec_context);
    }

    void cipher_3k3des::do_crypto(range <bin_data::iterator> data, bool encrypt, cipher_3k3des::block_t &iv) {
        DESFIRE_LOGD("3K3DES: %s %u bytes.", (encrypt ? "encrypting" : "decrypting"), std::distance(std::begin(data), std::end(data)));
        ESP_LOG_BUFFER_HEX_LEVEL((encrypt ? DESFIRE_TAG " DATA" : DESFIRE_TAG " BLOB"), data.data(), data.size(), ESP_LOG_VERBOSE);
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG "   IV", iv.data(), iv.size(), ESP_LOG_VERBOSE);
        assert(data.size() % block_size == 0);
        if (encrypt) {
            mbedtls_des3_crypt_cbc(&_enc_context, MBEDTLS_DES_ENCRYPT, data.size(), iv.data(), data.data(), data.data());
        } else {
            mbedtls_des3_crypt_cbc(&_dec_context, MBEDTLS_DES_DECRYPT, data.size(), iv.data(), data.data(), data.data());
        }
        ESP_LOG_BUFFER_HEX_LEVEL((encrypt ? DESFIRE_TAG " BLOB" : DESFIRE_TAG " DATA"), data.data(), data.size(), ESP_LOG_VERBOSE);
    }

    cipher_aes::cipher_aes(std::array<std::uint8_t, 16> const &key) : _enc_context{}, _dec_context{} {
        mbedtls_aes_init(&_enc_context);
        mbedtls_aes_init(&_dec_context);
        mbedtls_aes_setkey_enc(&_enc_context, key.data(), 8 * key.size());
        mbedtls_aes_setkey_enc(&_dec_context, key.data(), 8 * key.size());
        initialize();
    }

    void cipher_aes::reinit_with_session_key(bin_data const &rndab) {
        if (rndab.size() != 32) {
            DESFIRE_LOGE("Unsupported RndA || RndB length: %u != 32.", rndab.size());
            return;
        }
        std::array<std::uint8_t, 16> new_key{};
        const auto bsrc = std::begin(rndab);
        const auto btrg = std::begin(new_key);
        std::copy_n(bsrc, 4, btrg);
        std::copy_n(bsrc + 16, 4, btrg + 4);
        std::copy_n(bsrc + 12, 4, btrg + 8);
        std::copy_n(bsrc + 28, 4, btrg + 12);
        mbedtls_aes_free(&_enc_context);
        mbedtls_aes_free(&_dec_context);
        mbedtls_aes_init(&_enc_context);
        mbedtls_aes_init(&_dec_context);
        mbedtls_aes_setkey_enc(&_enc_context, new_key.data(), 8 * new_key.size());
        mbedtls_aes_setkey_dec(&_dec_context, new_key.data(), 8 * new_key.size());
        initialize();
    }

    cipher_aes::~cipher_aes() {
        mbedtls_aes_free(&_enc_context);
        mbedtls_aes_free(&_dec_context);
    }

    void cipher_aes::do_crypto(range <bin_data::iterator> data, bool encrypt, cipher_aes::block_t &iv) {
        DESFIRE_LOGD("AES128: %s %u bytes.", (encrypt ? "encrypting" : "decrypting"), std::distance(std::begin(data), std::end(data)));
        ESP_LOG_BUFFER_HEX_LEVEL((encrypt ? DESFIRE_TAG " DATA" : DESFIRE_TAG " BLOB"), data.data(), data.size(), ESP_LOG_VERBOSE);
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG "   IV", iv.data(), iv.size(), ESP_LOG_VERBOSE);
        assert(data.size() % block_size == 0);
        if (encrypt) {
            mbedtls_aes_crypt_cbc(&_enc_context, MBEDTLS_AES_ENCRYPT, data.size(), iv.data(), data.data(), data.data());
        } else {
            mbedtls_aes_crypt_cbc(&_dec_context, MBEDTLS_AES_DECRYPT, data.size(), iv.data(), data.data(), data.data());
        }
        ESP_LOG_BUFFER_HEX_LEVEL((encrypt ? DESFIRE_TAG " BLOB" : DESFIRE_TAG " DATA"), data.data(), data.size(), ESP_LOG_VERBOSE);
    }
}
