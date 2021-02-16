//
// Created by Pietro Saccardi on 02/01/2021.
//

#include "desfire/cipher_impl.hpp"
#include "desfire/msg.hpp"
#include <cassert>

namespace desfire {

    namespace {
        const char *input_tag(crypto_direction dir) {
            switch (dir) {
                case crypto_direction::decrypt:
                    return DESFIRE_TAG " BLOB";
                case crypto_direction::encrypt:// [[fallthrough]];
                case crypto_direction::mac:    // [[ fallthrough]];
                default:
                    return DESFIRE_TAG " DATA";
            }
        }
        const char *output_tag(crypto_direction dir) {
            switch (dir) {
                case crypto_direction::decrypt:
                    return DESFIRE_TAG " DATA";
                case crypto_direction::encrypt:// [[fallthrough]];
                case crypto_direction::mac:    // [[ fallthrough]];
                default:
                    return DESFIRE_TAG " BLOB";
            }
        }
    }// namespace

    cipher_des::cipher_des(std::array<std::uint8_t, 8> const &key) : _enc_context{}, _dec_context{}, _mac_enc_context{} {
        mbedtls_des_init(&_enc_context);
        mbedtls_des_init(&_dec_context);
        mbedtls_des_init(&_mac_enc_context);
        /**
         * @note Using @ref mbedtls_des_setkey_dec on @ref _enc_context is **deliberate**, see note on
         * @ref cipher_scheme_legacy.
         */
        mbedtls_des_setkey_dec(&_enc_context, key.data());
        mbedtls_des_setkey_dec(&_dec_context, key.data());
        mbedtls_des_setkey_enc(&_mac_enc_context, key.data());
        initialize();
    }

    void cipher_des::reinit_with_session_key(bin_data const &rndab) {
        if (rndab.size() != 16) {
            DESFIRE_LOGE("Incorrect session data length %u != 16. Are you attempt to authenticate with the wrong key type?", rndab.size());
            return;
        }
        std::array<std::uint8_t, 8> new_key{};
        const auto bsrc = std::begin(rndab);
        const auto btrg = std::begin(new_key);
        std::copy_n(bsrc, 4, btrg);
        std::copy_n(bsrc + 8, 4, btrg + 4);
        mbedtls_des_free(&_enc_context);
        mbedtls_des_free(&_dec_context);
        mbedtls_des_free(&_mac_enc_context);
        mbedtls_des_init(&_enc_context);
        mbedtls_des_init(&_dec_context);
        mbedtls_des_init(&_mac_enc_context);
        set_key_version(new_key, 0x00);

        ESP_LOGD(DESFIRE_TAG " KEY", "Session key %s:", to_string(cipher_type::des));
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " KEY", new_key.data(), new_key.size(), ESP_LOG_DEBUG);

        /**
         * @note Using @ref mbedtls_des_setkey_dec on @ref _enc_context is **deliberate**, see note on
         * @ref cipher_scheme_legacy.
         */
        mbedtls_des_setkey_dec(&_enc_context, new_key.data());
        mbedtls_des_setkey_dec(&_dec_context, new_key.data());
        mbedtls_des_setkey_enc(&_mac_enc_context, new_key.data());
        initialize();
    }

    cipher_des::~cipher_des() {
        mbedtls_des_free(&_enc_context);
        mbedtls_des_free(&_dec_context);
        mbedtls_des_free(&_mac_enc_context);
    }

    void cipher_des::do_crypto(range<bin_data::iterator> const &data, crypto_direction dir, cipher_des::block_t &iv) {
        ESP_LOGD(DESFIRE_TAG " CRYPTO", "DES: %s %u bytes.", to_string(dir), std::distance(std::begin(data), std::end(data)));
        ESP_LOG_BUFFER_HEX_LEVEL(input_tag(dir), data.data(), data.size(), ESP_LOG_DEBUG);
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG "   IV", iv.data(), iv.size(), ESP_LOG_DEBUG);
        assert(data.size() % block_size == 0);
        switch (dir) {
            case crypto_direction::encrypt:
                mbedtls_des_crypt_cbc(&_enc_context, MBEDTLS_DES_ENCRYPT, data.size(), iv.data(), data.data(), data.data());
                break;
            case crypto_direction::decrypt:
                mbedtls_des_crypt_cbc(&_dec_context, MBEDTLS_DES_DECRYPT, data.size(), iv.data(), data.data(), data.data());
                break;
            case crypto_direction::mac:
                mbedtls_des_crypt_cbc(&_mac_enc_context, MBEDTLS_DES_ENCRYPT, data.size(), iv.data(), data.data(), data.data());
                break;
            default:
                DESFIRE_LOGE("Unknown crypto dir: %s", to_string(dir));
                break;
        }
        ESP_LOG_BUFFER_HEX_LEVEL(output_tag(dir), data.data(), data.size(), ESP_LOG_DEBUG);
    }

    cipher_2k3des::cipher_2k3des(std::array<std::uint8_t, 16> const &key) : _enc_context{}, _dec_context{},
                                                                            _mac_enc_context{}, _degenerate{false} {
        /**
         * @note Indentify whether the two halves of the key are the same, up to parity bit. This means that we are
         * actually doing a DES en/decipherement operation. When we reinit with a new session key, we need to be aware
         * that this property has to be preserved.
         */
        const auto eq_except_parity = [](std::uint8_t l, std::uint8_t r) -> bool {
            static constexpr std::uint8_t mask = 0b11111110;
            return (l & mask) == (r & mask);
        };
        const auto it_begin_2nd_half = std::begin(key) + block_size / 2;
        _degenerate = std::equal(std::begin(key), it_begin_2nd_half, it_begin_2nd_half, eq_except_parity);

        mbedtls_des3_init(&_enc_context);
        mbedtls_des3_init(&_dec_context);
        mbedtls_des3_init(&_mac_enc_context);
        /**
         * @note Using @ref mbedtls_des3_set2key_dec on @ref _enc_context is **deliberate**, see note on
         * @ref cipher_scheme_legacy.
         */
        mbedtls_des3_set2key_dec(&_enc_context, key.data());
        mbedtls_des3_set2key_dec(&_dec_context, key.data());
        mbedtls_des3_set3key_enc(&_mac_enc_context, key.data());
        initialize();
    }

    void cipher_2k3des::reinit_with_session_key(bin_data const &rndab) {
        if (rndab.size() != 16) {
            DESFIRE_LOGE("Incorrect session data length %u != 16. Are you attempt to authenticate with the wrong key type?", rndab.size());
            return;
        }
        std::array<std::uint8_t, 16> new_key{};
        const auto bsrc = std::begin(rndab);
        const auto btrg = std::begin(new_key);
        std::copy_n(bsrc, 4, btrg);
        std::copy_n(bsrc + 8, 4, btrg + 4);

        /**
         * @note When the key is actually a DES key, i.e. the two halves are the same, here we should be deriving a DES
         * session key, i.e. we should preserve the property.
         */
        if (_degenerate) {
            std::copy_n(btrg, 8, btrg + 8);
        } else {
            std::copy_n(bsrc + 4, 4, btrg + 8);
            std::copy_n(bsrc + 12, 4, btrg + 12);
        }
        mbedtls_des3_free(&_enc_context);
        mbedtls_des3_free(&_dec_context);
        mbedtls_des3_free(&_mac_enc_context);
        mbedtls_des3_init(&_enc_context);
        mbedtls_des3_init(&_dec_context);
        mbedtls_des3_init(&_mac_enc_context);
        set_key_version(new_key, 0x00);

        ESP_LOGD(DESFIRE_TAG " KEY", "Session key %s:", to_string(cipher_type::des3_2k));
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " KEY", new_key.data(), new_key.size(), ESP_LOG_DEBUG);

        /**
         * @note Using @ref mbedtls_des3_set2key_dec on @ref _enc_context is **deliberate**, see note on
         * @ref cipher_scheme_legacy.
         */
        mbedtls_des3_set2key_dec(&_enc_context, new_key.data());
        mbedtls_des3_set2key_dec(&_dec_context, new_key.data());
        mbedtls_des3_set2key_enc(&_mac_enc_context, new_key.data());
        initialize();
    }

    cipher_2k3des::~cipher_2k3des() {
        mbedtls_des3_free(&_enc_context);
        mbedtls_des3_free(&_dec_context);
        mbedtls_des3_free(&_mac_enc_context);
    }

    void cipher_2k3des::do_crypto(range<bin_data::iterator> const &data, crypto_direction dir, cipher_2k3des::block_t &iv) {
        ESP_LOGD(DESFIRE_TAG " CRYPTO", "2K3DES: %s %u bytes.", to_string(dir), std::distance(std::begin(data), std::end(data)));
        ESP_LOG_BUFFER_HEX_LEVEL(input_tag(dir), data.data(), data.size(), ESP_LOG_DEBUG);
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG "   IV", iv.data(), iv.size(), ESP_LOG_DEBUG);
        assert(data.size() % block_size == 0);
        switch (dir) {
            case crypto_direction::encrypt:
                mbedtls_des3_crypt_cbc(&_enc_context, MBEDTLS_DES_ENCRYPT, data.size(), iv.data(), data.data(), data.data());
                break;
            case crypto_direction::decrypt:
                mbedtls_des3_crypt_cbc(&_dec_context, MBEDTLS_DES_DECRYPT, data.size(), iv.data(), data.data(), data.data());
                break;
            case crypto_direction::mac:
                mbedtls_des3_crypt_cbc(&_mac_enc_context, MBEDTLS_DES_ENCRYPT, data.size(), iv.data(), data.data(), data.data());
                break;
            default:
                DESFIRE_LOGE("Unknown crypto dir: %s", to_string(dir));
                break;
        }
        ESP_LOG_BUFFER_HEX_LEVEL(output_tag(dir), data.data(), data.size(), ESP_LOG_DEBUG);
    }

    cipher_3k3des::cipher_3k3des(std::array<std::uint8_t, 24> const &key) : _enc_context{}, _dec_context{} {
        mbedtls_des3_init(&_enc_context);
        mbedtls_des3_init(&_dec_context);
        mbedtls_des3_set3key_enc(&_enc_context, key.data());
        mbedtls_des3_set3key_dec(&_dec_context, key.data());
        initialize();
    }

    void cipher_3k3des::reinit_with_session_key(bin_data const &rndab) {
        if (rndab.size() != 32) {
            DESFIRE_LOGE("Incorrect session data length %u != 32. Are you attempt to authenticate with the wrong key type?", rndab.size());
            return;
        }
        std::array<std::uint8_t, 24> new_key{};
        const auto bsrc = std::begin(rndab);
        const auto btrg = std::begin(new_key);
        std::copy_n(bsrc, 4, btrg);
        std::copy_n(bsrc + 16, 4, btrg + 4);
        std::copy_n(bsrc + 6, 4, btrg + 8);
        std::copy_n(bsrc + 22, 4, btrg + 12);
        std::copy_n(bsrc + 12, 4, btrg + 16);
        std::copy_n(bsrc + 28, 4, btrg + 20);
        mbedtls_des3_free(&_enc_context);
        mbedtls_des3_free(&_dec_context);
        mbedtls_des3_init(&_enc_context);
        mbedtls_des3_init(&_dec_context);
        set_key_version(new_key, 0x00);

        ESP_LOGD(DESFIRE_TAG " KEY", "Session key %s:", to_string(cipher_type::des3_3k));
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " KEY", new_key.data(), new_key.size(), ESP_LOG_DEBUG);

        mbedtls_des3_set3key_enc(&_enc_context, new_key.data());
        mbedtls_des3_set3key_dec(&_dec_context, new_key.data());
        initialize();
    }

    cipher_3k3des::~cipher_3k3des() {
        mbedtls_des3_free(&_enc_context);
        mbedtls_des3_free(&_dec_context);
    }

    void cipher_3k3des::do_crypto(range<bin_data::iterator> const &data, crypto_direction dir, cipher_3k3des::block_t &iv) {
        ESP_LOGD(DESFIRE_TAG " CRYPTO", "3K3DES: %s %u bytes.", to_string(dir), std::distance(std::begin(data), std::end(data)));
        ESP_LOG_BUFFER_HEX_LEVEL(input_tag(dir), data.data(), data.size(), ESP_LOG_DEBUG);
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG "   IV", iv.data(), iv.size(), ESP_LOG_DEBUG);
        assert(data.size() % block_size == 0);
        switch (dir) {
            case crypto_direction::mac:// [[fallthrough]];
            case crypto_direction::encrypt:
                mbedtls_des3_crypt_cbc(&_enc_context, MBEDTLS_DES_ENCRYPT, data.size(), iv.data(), data.data(), data.data());
                break;
            case crypto_direction::decrypt:
                mbedtls_des3_crypt_cbc(&_dec_context, MBEDTLS_DES_DECRYPT, data.size(), iv.data(), data.data(), data.data());
                break;
            default:
                DESFIRE_LOGE("Unknown crypto dir: %s", to_string(dir));
                break;
        }
        ESP_LOG_BUFFER_HEX_LEVEL(output_tag(dir), data.data(), data.size(), ESP_LOG_DEBUG);
    }

    cipher_aes::cipher_aes(std::array<std::uint8_t, 16> const &key) : _enc_context{}, _dec_context{} {
        mbedtls_aes_init(&_enc_context);
        mbedtls_aes_init(&_dec_context);
        mbedtls_aes_setkey_enc(&_enc_context, key.data(), 8 * key.size());
        mbedtls_aes_setkey_dec(&_dec_context, key.data(), 8 * key.size());
        initialize();
    }

    void cipher_aes::reinit_with_session_key(bin_data const &rndab) {
        if (rndab.size() != 32) {
            DESFIRE_LOGE("Incorrect session data length %u != 32. Are you attempt to authenticate with the wrong key type?", rndab.size());
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

        ESP_LOGD(DESFIRE_TAG " KEY", "Session key %s:", to_string(cipher_type::aes128));
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " KEY", new_key.data(), new_key.size(), ESP_LOG_DEBUG);

        initialize();
    }

    cipher_aes::~cipher_aes() {
        mbedtls_aes_free(&_enc_context);
        mbedtls_aes_free(&_dec_context);
    }

    void cipher_aes::do_crypto(range<bin_data::iterator> const &data, crypto_direction dir, cipher_aes::block_t &iv) {
        ESP_LOGD(DESFIRE_TAG " CRYPTO", "AES128: %s %u bytes.", to_string(dir), std::distance(std::begin(data), std::end(data)));
        ESP_LOG_BUFFER_HEX_LEVEL(input_tag(dir), data.data(), data.size(), ESP_LOG_DEBUG);
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG "   IV", iv.data(), iv.size(), ESP_LOG_DEBUG);
        assert(data.size() % block_size == 0);
        switch (dir) {
            case crypto_direction::mac:// [[fallthrough]];
            case crypto_direction::encrypt:
                mbedtls_aes_crypt_cbc(&_enc_context, MBEDTLS_AES_ENCRYPT, data.size(), iv.data(), data.data(), data.data());
                break;
            case crypto_direction::decrypt:
                mbedtls_aes_crypt_cbc(&_dec_context, MBEDTLS_AES_DECRYPT, data.size(), iv.data(), data.data(), data.data());
                break;
            default:
                DESFIRE_LOGE("Unknown crypto dir: %s", to_string(dir));
                break;
        }
        ESP_LOG_BUFFER_HEX_LEVEL(output_tag(dir), data.data(), data.size(), ESP_LOG_DEBUG);
    }
}// namespace desfire
