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
    }

    cipher_des::~cipher_des() {
        mbedtls_des_free(&_enc_context);
        mbedtls_des_free(&_dec_context);
    }

    cipher_des::block_t cipher_des::do_crypto(range<bin_data::iterator> data, bool encrypt) {
        assert(data.size() % block_size == 0);
        static block_t iv{};
        // In legacy authentication, the IV is reset every time
        iv = {0, 0, 0, 0, 0, 0, 0, 0};
        if (encrypt) {
            mbedtls_des_crypt_cbc(&_enc_context, MBEDTLS_DES_ENCRYPT, data.size(), iv.data(), data.data(), data.data());
        } else {
            mbedtls_des_crypt_cbc(&_dec_context, MBEDTLS_DES_DECRYPT, data.size(), iv.data(), data.data(), data.data());
        }
        return iv;
    }

    cipher_2k3des::cipher_2k3des(std::array<std::uint8_t, 16> const &key) : _enc_context{}, _dec_context{} {
        mbedtls_des3_init(&_enc_context);
        mbedtls_des3_init(&_dec_context);
        mbedtls_des3_set2key_enc(&_enc_context, key.data());
        mbedtls_des3_set2key_enc(&_dec_context, key.data());
    }

    cipher_2k3des::~cipher_2k3des() {
        mbedtls_des3_free(&_enc_context);
        mbedtls_des3_free(&_dec_context);
    }

    cipher_2k3des::block_t cipher_2k3des::do_crypto(range <bin_data::iterator> data, bool encrypt) {
        assert(data.size() % block_size == 0);
        static block_t iv{};
        // In legacy authentication, the IV is reset every time
        iv = {0, 0, 0, 0, 0, 0, 0, 0};
        if (encrypt) {
            mbedtls_des3_crypt_cbc(&_enc_context, MBEDTLS_DES_ENCRYPT, data.size(), iv.data(), data.data(),
                                   data.data());
        } else {
            mbedtls_des3_crypt_cbc(&_dec_context, MBEDTLS_DES_DECRYPT, data.size(), iv.data(), data.data(),
                                   data.data());
        }
        return iv;
    }

    cipher_3k3des::cipher_3k3des(std::array<std::uint8_t, 24> const &key) : _enc_context{}, _dec_context{} {
        mbedtls_des3_init(&_enc_context);
        mbedtls_des3_init(&_dec_context);
        mbedtls_des3_set3key_enc(&_enc_context, key.data());
        mbedtls_des3_set3key_enc(&_dec_context, key.data());
        generate_cmac_subkeys();
    }

    cipher_3k3des::~cipher_3k3des() {
        mbedtls_des3_free(&_enc_context);
        mbedtls_des3_free(&_dec_context);
    }

    void cipher_3k3des::do_crypto(range <bin_data::iterator> data, cipher_3k3des::block_t &iv, bool encrypt) {
        assert(data.size() % block_size == 0);
        if (encrypt) {
            mbedtls_des3_crypt_cbc(&_enc_context, MBEDTLS_DES_ENCRYPT, data.size(), iv.data(), data.data(),
                                   data.data());
        } else {
            mbedtls_des3_crypt_cbc(&_dec_context, MBEDTLS_DES_DECRYPT, data.size(), iv.data(), data.data(),
                                   data.data());
        }
    }

    cipher_aes::cipher_aes(std::array<std::uint8_t, 16> const &key) : _enc_context{}, _dec_context{} {
        mbedtls_aes_init(&_enc_context);
        mbedtls_aes_init(&_dec_context);
        mbedtls_aes_setkey_enc(&_enc_context, key.data(), 8 * key.size());
        mbedtls_aes_setkey_enc(&_dec_context, key.data(), 8 * key.size());
        generate_cmac_subkeys();
    }

    cipher_aes::~cipher_aes() {
        mbedtls_aes_free(&_enc_context);
        mbedtls_aes_free(&_dec_context);
    }

    void cipher_aes::do_crypto(range <bin_data::iterator> data, cipher_aes::block_t &iv, bool encrypt) {
        assert(data.size() % block_size == 0);
        if (encrypt) {
            mbedtls_aes_crypt_cbc(&_enc_context, MBEDTLS_AES_ENCRYPT, data.size(), iv.data(), data.data(), data.data());
        } else {
            mbedtls_aes_crypt_cbc(&_dec_context, MBEDTLS_AES_DECRYPT, data.size(), iv.data(), data.data(), data.data());
        }
    }
}
