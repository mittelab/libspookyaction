//
// Created by spak on 5/6/21.
//

#include <desfire/crypto.hpp>
#include <desfire/crypto_algo.hpp>
#include <desfire/log.h>
#include <desfire/msg.hpp>

namespace desfire {

    namespace {
        using mlab::make_range;
    }

    void crypto_des_base::init_session(range<const std::uint8_t *> random_data) {
        if (random_data.size() != 16) {
            DESFIRE_LOGE("Incorrect session data length %u != 16. Are you attempt to authenticate with the wrong key type?", random_data.size());
            return;
        }
        std::array<std::uint8_t, 8> new_key{};
        const auto bsrc = std::begin(random_data);
        const auto btrg = std::begin(new_key);
        std::copy_n(bsrc, 4, btrg);
        std::copy_n(bsrc + 8, 4, btrg + 4);
        set_key_version(new_key, 0x00);

        ESP_LOGD(DESFIRE_TAG " KEY", "Session key %s:", to_string(cipher_type::des));
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " KEY", new_key.data(), new_key.size(), ESP_LOG_DEBUG);

        setup_with_key(make_range(new_key));
    }

    void crypto_2k3des_base::setup_with_key(range<const std::uint8_t *> key) {
        if (key.size() != 16) {
            DESFIRE_LOGE("2K3DES key size error: expected 16 bytes, got %d.", key.size());
            return;
        }

        /**
         * @note Indentify whether the two halves of the key are the same, up to parity bit. This means that we are
         * actually doing a DES en/decipherement operation. When we reinit with a new session key, we need to be aware
         * that this property has to be preserved.
         */
        const auto eq_except_parity = [](std::uint8_t l, std::uint8_t r) -> bool {
            static constexpr std::uint8_t mask = 0b11111110;
            return (l & mask) == (r & mask);
        };
        const auto it_begin_2nd_half = std::begin(key) + 8;
        _degenerate = std::equal(std::begin(key), it_begin_2nd_half, it_begin_2nd_half, eq_except_parity);

        setup_primitives_with_key(key);
    }

    void crypto_2k3des_base::init_session(range<const std::uint8_t *> random_data) {
        if (random_data.size() != 16) {
            DESFIRE_LOGE("Incorrect session data length %u != 16. Are you attempt to authenticate with the wrong key type?", random_data.size());
            return;
        }
        std::array<std::uint8_t, 16> new_key{};
        const auto bsrc = std::begin(random_data);
        const auto btrg = std::begin(new_key);
        std::copy_n(bsrc, 4, btrg);
        std::copy_n(bsrc + 8, 4, btrg + 4);

        /**
         * @note When the key is actually a DES key, i.e. the two halves are the same, here we should be deriving a DES
         * session key, i.e. we should preserve the property.
         */
        if (is_degenerate()) {
            std::copy_n(btrg, 8, btrg + 8);
        } else {
            std::copy_n(bsrc + 4, 4, btrg + 8);
            std::copy_n(bsrc + 12, 4, btrg + 12);
        }
        set_key_version(new_key, 0x00);

        ESP_LOGD(DESFIRE_TAG " KEY", "Session key %s:", to_string(cipher_type::des3_2k));
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " KEY", new_key.data(), new_key.size(), ESP_LOG_DEBUG);

        setup_with_key(make_range(new_key));
    }

    void crypto_3k3des_base::init_session(range<const std::uint8_t *> random_data) {
        if (random_data.size() != 32) {
            DESFIRE_LOGE("Incorrect session data length %u != 32. Are you attempt to authenticate with the wrong key type?", random_data.size());
            return;
        }
        std::array<std::uint8_t, 24> new_key{};
        const auto bsrc = std::begin(random_data);
        const auto btrg = std::begin(new_key);
        std::copy_n(bsrc, 4, btrg);
        std::copy_n(bsrc + 16, 4, btrg + 4);
        std::copy_n(bsrc + 6, 4, btrg + 8);
        std::copy_n(bsrc + 22, 4, btrg + 12);
        std::copy_n(bsrc + 12, 4, btrg + 16);
        std::copy_n(bsrc + 28, 4, btrg + 20);
        set_key_version(new_key, 0x00);

        ESP_LOGD(DESFIRE_TAG " KEY", "Session key %s:", to_string(cipher_type::des3_3k));
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " KEY", new_key.data(), new_key.size(), ESP_LOG_DEBUG);

        setup_with_key(make_range(new_key));
    }

    void crypto_aes_base::init_session(range<const std::uint8_t *> random_data) {
        if (random_data.size() != 32) {
            DESFIRE_LOGE("Incorrect session data length %u != 32. Are you attempt to authenticate with the wrong key type?", random_data.size());
            return;
        }
        std::array<std::uint8_t, 16> new_key{};
        const auto bsrc = std::begin(random_data);
        const auto btrg = std::begin(new_key);
        std::copy_n(bsrc, 4, btrg);
        std::copy_n(bsrc + 16, 4, btrg + 4);
        std::copy_n(bsrc + 12, 4, btrg + 8);
        std::copy_n(bsrc + 28, 4, btrg + 12);

        ESP_LOGD(DESFIRE_TAG " KEY", "Session key %s:", to_string(cipher_type::aes128));
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " KEY", new_key.data(), new_key.size(), ESP_LOG_DEBUG);

        setup_with_key(make_range(new_key));
    }

    crypto_3k3des_base::crypto_3k3des_base() : crypto_with_cmac{8, bits::crypto_cmac_xor_byte_3k3des} {
    }

    crypto_aes_base::crypto_aes_base() : crypto_with_cmac{16, bits::crypto_cmac_xor_byte_aes} {
    }


    void crypto_with_cmac::setup_with_key(range<const std::uint8_t *> key) {
        setup_primitives_with_key(key);
        _cmac.initialize_subkeys();
    }

    std::size_t crypto_with_cmac::block_size() const {
        return _cmac.block_size();
    }

    crypto_with_cmac::crypto_with_cmac(std::uint8_t block_size, std::uint8_t last_byte_xor)
        : _cmac{*this, block_size, last_byte_xor} {}

    crypto_with_cmac::mac_t crypto_with_cmac::do_cmac(range<std::uint8_t const *> data, range<std::uint8_t *> iv) {
        return _cmac.compute_cmac(iv, data);
    }

}// namespace desfire
