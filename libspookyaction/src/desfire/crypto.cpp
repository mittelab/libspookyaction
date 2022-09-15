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
        _key_version = get_key_version(key);

        setup_primitives_with_key(key);
        _diversification_keychain.initialize_subkeys(*this);
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
        set_key_version(new_key, _key_version);

        ESP_LOGD(DESFIRE_TAG " KEY", "Session key %s:", to_string(cipher_type::des3_2k));
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " KEY", new_key.data(), new_key.size(), ESP_LOG_DEBUG);

        setup_with_key(make_range(new_key));
    }

    crypto_2k3des_base::crypto_2k3des_base() : _degenerate{false}, _key_version{0x0},
                                               _diversification_keychain{8, bits::crypto_cmac_xor_byte_2k3des} {}

    std::array<std::uint8_t, 16> crypto_2k3des_base::diversify_key_an10922(mlab::bin_data &diversification_input) {
        // We use at most 15 bits of the diversification data
        if (diversification_input.size() > 15) {
            ESP_LOGW(DESFIRE_TAG, "Too long diversification input for 3K3DES, %d > 15 bytes.", diversification_input.size());
            diversification_input.resize(15);
        }
        // This will be the final key returned.
        std::array<std::uint8_t, 16> retval{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        // Will eventually use 16 bytes
        diversification_input.reserve(16);
        // We need to insert a different constant in front of the diversification data. For now, only zero
        diversification_input.insert(std::begin(diversification_input), 0);
        // This is the starting point for each piece of the final key. We need to save it and restore it
        const bin_data orig_div_input = diversification_input;
        for (std::size_t i = 0; i < 2; ++i) {
            if (i > 0) {
                // Restore the original input. Copy manually so that we do not cause reallocations
                diversification_input.resize(orig_div_input.size());
                std::copy(std::begin(orig_div_input), std::end(orig_div_input), std::begin(diversification_input));
            }
            // Set now the correct constant, pad and XOR
            diversification_input[0] = bits::kdf_2k3des_const[i];
            _diversification_keychain.prepare_cmac_data(diversification_input, 16);
            assert(diversification_input.size() == 16);
            // The new piece of the final key is now at zero, so we can use it as an IV and then copy over it
            const range<std::uint8_t *> iv{std::begin(retval) + i * 8, std::begin(retval) + i * 8 + 8};
            // Perform crypto in CMAC mode with a zero block IV.
            do_crypto(diversification_input.data_view(), iv, crypto_operation::mac);
            // Copy the piece of key back
            std::copy(std::begin(diversification_input) + 8, std::end(diversification_input), std::begin(retval) + i * 8);
        }
        // At this point, we need to restore the version bits
        set_key_version(retval, _key_version);
        return retval;
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
        set_key_version(new_key, _key_version);

        ESP_LOGD(DESFIRE_TAG " KEY", "Session key %s:", to_string(cipher_type::des3_3k));
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " KEY", new_key.data(), new_key.size(), ESP_LOG_DEBUG);

        setup_with_key(make_range(new_key));
    }

    void crypto_3k3des_base::setup_with_key(range<const std::uint8_t *> key) {
        crypto_with_cmac::setup_with_key(key);
        if (key.size() != 24) {
            DESFIRE_LOGE("Incorrect key size for 3K3DES: %u != 24", key.size());
        } else {
            _key_version = get_key_version(key);
        }
    }

    std::array<std::uint8_t, 24> crypto_3k3des_base::diversify_key_an10922(mlab::bin_data &diversification_input) {
        // We use at most 15 bits of the diversification data
        if (diversification_input.size() > 15) {
            ESP_LOGW(DESFIRE_TAG, "Too long diversification input for 3K3DES, %d > 15 bytes.", diversification_input.size());
            diversification_input.resize(15);
        }
        // This will be the final key returned.
        std::array<std::uint8_t, 24> retval{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        // Will eventually use 16 bytes
        diversification_input.reserve(16);
        // We need to insert a different constant in front of the diversification data. For now, only zero
        diversification_input.insert(std::begin(diversification_input), 0);
        // This is the starting point for each piece of the final key. We need to save it and restore it
        const bin_data orig_div_input = diversification_input;
        for (std::size_t i = 0; i < 3; ++i) {
            if (i > 0) {
                // Restore the original input. Copy manually so that we do not cause reallocations
                diversification_input.resize(orig_div_input.size());
                std::copy(std::begin(orig_div_input), std::end(orig_div_input), std::begin(diversification_input));
            }
            // Set now the correct constant, pad and XOR
            diversification_input[0] = bits::kdf_3k3des_const[i];
            prepare_cmac_data(diversification_input, 16);
            assert(diversification_input.size() == 16);
            // The new piece of the final key is now at zero, so we can use it as an IV and then copy over it
            const range<std::uint8_t *> iv{std::begin(retval) + i * 8, std::begin(retval) + i * 8 + 8};
            // Perform crypto in CMAC mode with a zero block IV.
            do_crypto(diversification_input.data_view(), iv, crypto_operation::mac);
            // Copy the piece of key back
            std::copy(std::begin(diversification_input) + 8, std::end(diversification_input), std::begin(retval) + i * 8);
        }
        // At this point, we need to restore the version bits
        set_key_version(retval, _key_version);
        return retval;
    }

    std::array<std::uint8_t, 16> crypto_aes_base::diversify_key_an10922(mlab::bin_data &diversification_input) {
        // We use at most 31 bits of the diversification data
        if (diversification_input.size() > 31) {
            ESP_LOGW(DESFIRE_TAG, "Too long diversification input for AES128, %d > 31 bytes.", diversification_input.size());
            diversification_input.resize(31);
        }
        // Will eventually use 32 bytes
        diversification_input.reserve(32);
        // We need to insert in front of it the constant 0x01
        diversification_input.insert(std::begin(diversification_input), bits::kdf_aes_const);
        // Now we pad to 32 bytes and xor with the appropriate key
        prepare_cmac_data(diversification_input, 32);
        assert(diversification_input.size() == 32);
        // Perform crypto in CMAC mode with a zero block
        std::array<std::uint8_t, 16> block{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        do_crypto(diversification_input.data_view(), make_range(block), crypto_operation::mac);
        // Use the block to return the last 16 bytes of the resulted encrypted data as differentiation input
        std::copy(std::begin(diversification_input) + 16, std::end(diversification_input), std::begin(block));
        return block;
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

    crypto_3k3des_base::crypto_3k3des_base() : crypto_with_cmac{8, bits::crypto_cmac_xor_byte_3k3des}, _key_version{0} {
    }

    crypto_aes_base::crypto_aes_base() : crypto_with_cmac{16, bits::crypto_cmac_xor_byte_aes} {
    }


    void crypto_with_cmac::setup_with_key(range<const std::uint8_t *> key) {
        setup_primitives_with_key(key);
        _cmac.initialize_subkeys(*this);
    }

    std::size_t crypto_with_cmac::block_size() const {
        return _cmac.keychain().block_size();
    }

    crypto_with_cmac::crypto_with_cmac(std::uint8_t block_size, std::uint8_t last_byte_xor)
        : _cmac{block_size, last_byte_xor} {}

    crypto_with_cmac::mac_t crypto_with_cmac::do_cmac(range<std::uint8_t const *> data, range<std::uint8_t *> iv) {
        return _cmac.compute_cmac(*this, iv, data);
    }

    void crypto_with_cmac::prepare_cmac_data(mlab::bin_data &data) const {
        _cmac.keychain().prepare_cmac_data(data);
    }

    void crypto_with_cmac::prepare_cmac_data(mlab::bin_data &data, std::size_t desired_padded_length) const {
        _cmac.keychain().prepare_cmac_data(data, desired_padded_length);
    }

}// namespace desfire
