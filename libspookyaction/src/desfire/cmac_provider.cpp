//
// Created by spak on 5/8/21.
//

#include <desfire/bits.hpp>
#include <desfire/cmac_provider.hpp>
#include <desfire/crypto.hpp>
#include <desfire/crypto_algo.hpp>

namespace desfire {

    void cmac_keychain::prepare_subkey(range<std::uint8_t *> subkey, std::uint8_t last_byte_xor) {
        const bool do_xor = (*std::begin(subkey) & 0x80) != 0;
        // Some app-specific magic: lshift by one
        lshift_sequence(std::begin(subkey), std::end(subkey), 1);
        // ...and xor with R if the MSB is one
        if (do_xor) {
            *std::prev(std::end(subkey)) ^= last_byte_xor;
        }
    }

    void cmac_provider::initialize_subkeys(crypto &crypto) {
        _keychain.initialize_subkeys(crypto);
    }

    void cmac_keychain::initialize_subkeys(crypto &crypto) {
        auto rg_key_nopad = key_nopad();
        auto rg_key_pad = key_pad();

        DESFIRE_LOGD("Deriving CMAC subkeys...");

        // Clear the keys to zero
        std::fill(std::begin(rg_key_pad), std::end(rg_key_pad), 0);
        std::fill(std::begin(rg_key_nopad), std::end(rg_key_nopad), 0);

        // Do the initial crypto_implementation. Should use a 0-filled IV. We use the padded key which we just reset.
        crypto.do_crypto(rg_key_pad, rg_key_nopad, crypto_operation::mac);

        // rg_key_nopad contains garbage now, process the nopad key first
        prepare_subkey(rg_key_pad, last_byte_xor());

        // Copy the nopad key to the pad key, and do it again
        std::copy(std::begin(rg_key_pad), std::end(rg_key_pad), std::begin(rg_key_nopad));
        prepare_subkey(rg_key_pad, last_byte_xor());

        ESP_LOGD(DESFIRE_TAG " KEY", "CMAC key for unpadded data:");
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " KEY", _subkey_nopad.get(), block_size(), ESP_LOG_DEBUG);
        ESP_LOGD(DESFIRE_TAG " KEY", "CMAC key for padded data:");
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " KEY", _subkey_pad.get(), block_size(), ESP_LOG_DEBUG);
    }


    void cmac_keychain::prepare_cmac_data(bin_data &data) const {
        prepare_cmac_data(data, data.size());
    }

    void cmac_keychain::prepare_cmac_data(bin_data &data, std::size_t desired_padded_length) const {
        // Ensure the padded length is a multiple of the block size
        desired_padded_length = padded_length(desired_padded_length, block_size());
        const auto old_size = data.size();
        data.resize(desired_padded_length);

        const auto last_block = data.view(data.size() - block_size());
        const auto xor_op = [](std::uint8_t l, std::uint8_t r) -> std::uint8_t { return l ^ r; };
        if (old_size == data.size()) {
            // Was not padded
            std::transform(std::begin(last_block), std::end(last_block), _subkey_nopad.get(),
                           std::begin(last_block), xor_op);
        } else {
            // Padding needs to begin with 0x80
            data[old_size] = 0x80;
            std::transform(std::begin(last_block), std::end(last_block), _subkey_pad.get(),
                           std::begin(last_block), xor_op);
        }
    }


    cmac_provider::mac_t cmac_provider::compute_cmac(crypto &crypto, range<std::uint8_t *> iv, range<std::uint8_t const *> data) {
        mac_t retval{0, 0, 0, 0, 0, 0, 0, 0};

        if (iv.size() < keychain().block_size()) {
            DESFIRE_LOGE("CMAC: got %d bytes for IV, need at least %d for CMAC.", iv.size(), keychain().block_size());
            return retval;
        }

        auto buffer = _buffer_pool->take();

        // Resize the buffer and copy data
        buffer->reserve(padded_length(data.size(), keychain().block_size()));
        buffer->resize(data.size());

        std::copy(std::begin(data), std::end(data), std::begin(*buffer));
        keychain().prepare_cmac_data(*buffer);

        // Return the first 8 bytes of the last block
        crypto.do_crypto(buffer->data_view(), iv, crypto_operation::mac);
        std::copy(std::begin(iv), std::begin(iv) + retval.size(), std::begin(retval));
        return retval;
    }
}// namespace desfire