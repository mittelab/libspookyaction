//
// Created by spak on 5/7/21.
//

#include "desfire/crypto_protocol.hpp"
#include "desfire/log.h"
#include "desfire/crypto_algo.hpp"

namespace desfire {
    namespace {
        using mlab::bin_stream;
        using mlab::make_range;
        using mlab::lsb16;
    }

    protocol_legacy::block_t &protocol_legacy::get_zeroed_iv() {
        // Reset every time
        std::fill_n(std::begin(_iv), block_size, 0x00);
        return _iv;
    }


    protocol_legacy::mac_t protocol_legacy::compute_mac(crypto &crypto, range<bin_data::const_iterator> data) {
        static bin_data buffer{};

        // Resize the buffer and copy data
        buffer.clear();
        buffer.resize(padded_length<block_size>(data.size()), 0x00);
        std::copy(std::begin(data), std::end(data), std::begin(buffer));

        // Return the first 4 bytes of the last block
        block_t &iv = get_zeroed_iv();
        crypto.do_crypto(buffer.data_view(), make_range(iv), crypto_operation::mac);
        return {iv[0], iv[1], iv[2], iv[3]};
    }

    bool protocol_legacy::drop_padding_verify_crc(bin_data &d) {
        static const auto crc_fn = [](bin_data::const_iterator b, bin_data::const_iterator e, std::uint16_t init) -> std::uint16_t {
          return compute_crc16(range<bin_data::const_iterator>{b, e}, init);
        };
        const auto [end_payload, did_verify] = find_crc_tail<block_size>(std::begin(d), std::end(d), crc_fn, crc16_init, true);
        if (did_verify) {
            const std::size_t payload_length = std::distance(std::begin(d), end_payload);
            // In case of error, make sure to not get any weird size/number
            d.resize(std::max(payload_length, crc_size) - crc_size);
            return true;
        }
        return false;
    }

    void protocol_legacy::prepare_tx(crypto &crypto, bin_data &data, std::size_t offset, cipher_mode mode) {
        if (offset >= data.size() or mode == cipher_mode::plain) {
            return;// Nothing to do
        }
        if (mode == cipher_mode::maced) {
            const auto mac = compute_mac(crypto, data.view(offset));
            ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " TX MAC", mac.data(), mac.size(), ESP_LOG_DEBUG);
            data << mac;
        } else {
            if (mode == cipher_mode::ciphered) {
                data.reserve(offset + padded_length<block_size>(data.size() + crc_size - offset));
                data << lsb16 << compute_crc16(data.view(offset));
            } else {
                data.reserve(offset + padded_length<block_size>(data.size() - offset));
            }
            data.resize(offset + padded_length<block_size>(data.size() - offset), 0x00);
            crypto.do_crypto(data.data_view(offset), make_range(get_zeroed_iv()), crypto_operation::encrypt);
        }
    }


    bool protocol_legacy::confirm_rx(crypto &crypto, bin_data &data, cipher_mode mode) {
        if (data.size() == 1 or mode == cipher_mode::plain) {
            // Just status byte, return as-is
            return true;
        }
        if (mode == cipher_mode::maced) {
            bin_stream s{data};
            // Data, followed by mac, followed by status
            const auto data_view = s.read(s.remaining() - mac_size - 1);
            // Compute mac on data
            const mac_t computed_mac = compute_mac(crypto, data_view);
            ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " RX MAC", computed_mac.data(), computed_mac.size(), ESP_LOG_DEBUG);
            // Extract the transmitted mac
            mac_t rxd_mac{};
            s >> rxd_mac;
            if (rxd_mac == computed_mac) {
                // Good, move status byte at the end and drop the mac
                data[data.size() - mac_size - 1] = data[data.size() - 1];
                data.resize(data.size() - mac_size);
                return true;
            }
            ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " != MAC", rxd_mac.data(), rxd_mac.size(), ESP_LOG_DEBUG);
            return false;
        } else {
            // Pop the status byte
            const std::uint8_t status = data.back();
            data.pop_back();
            // Decipher what's left
            if (data.size() % block_size != 0) {
                DESFIRE_LOGW("Received enciphered data of length %u, not a multiple of the block size %u.",
                             data.size(), block_size);
                ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG, data.data(), data.size(), ESP_LOG_WARN);
                return false;
            }
            crypto.do_crypto(data.data_view(), make_range(get_zeroed_iv()), crypto_operation::decrypt);
            if (mode == cipher_mode::ciphered) {
                // Truncate the padding and the crc
                const bool did_verify = drop_padding_verify_crc(data);
                // Reappend the status byte
                data << status;
                return did_verify;
            } else {
                // Reappend the status byte
                data << status;
                return true;
            }
        }
    }

    void cmac_provider::prepare_subkey(range<std::uint8_t *> subkey, std::uint8_t last_byte_xor) {
        const bool do_xor = (*std::begin(subkey) & 0x80) != 0;
        // Some app-specific magic: lshift by one
        lshift_sequence(std::begin(subkey), std::end(subkey), 1);
        // ...and xor with R if the MSB is one
        if (do_xor) {
            *std::prev(std::end(subkey)) ^= last_byte_xor;
        }
    }

    void cmac_provider::initialize_subkeys(crypto &crypto) {
        auto rg_key_nopad = key_nopad();
        auto rg_key_pad = key_pad();

        DESFIRE_LOGD("Deriving CMAC subkeys...");

        // Clear the keys to zero
        std::fill(std::begin(rg_key_pad), std::end(rg_key_pad), 0);
        std::fill(std::begin(rg_key_nopad), std::end(rg_key_nopad), 0);

        // Do the initial crypto. Should use a 0-filled IV. We use the padded key which we just reset.
        crypto.do_crypto(rg_key_nopad, rg_key_pad, crypto_operation::mac);

        // rg_key_pad contains garbage now, process the nopad key first
        prepare_subkey(rg_key_nopad, last_byte_xor());

        // Copy the nopad key to the pad key, and do it again
        std::copy(std::begin(rg_key_nopad), std::end(rg_key_nopad), std::begin(rg_key_pad));
        prepare_subkey(rg_key_nopad, last_byte_xor());

        ESP_LOGD(DESFIRE_TAG " KEY", "CMAC key for unpadded data:");
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " KEY", _subkey_nopad.get(), block_size_bytes(), ESP_LOG_DEBUG);
        ESP_LOGD(DESFIRE_TAG " KEY", "CMAC key for padded data:");
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " KEY", _subkey_pad.get(), block_size_bytes(), ESP_LOG_DEBUG);
    }


    cmac_provider::mac_t cmac_provider::compute_mac(crypto &crypto, range<std::uint8_t *> iv, range<bin_data::const_iterator> data) {
        mac_t retval{0, 0, 0, 0, 0, 0, 0, 0};

        if (iv.size() < block_size_bytes()) {
            DESFIRE_LOGE("CMAC: got %d bytes for IV, need at least %d for CMAC.", iv.size(), block_size_bytes());
            return retval;
        }

        static const auto xor_op = [](std::uint8_t l, std::uint8_t r) -> std::uint8_t { return l ^ r; };

        // Resize the buffer and copy data
        _cmac_buffer.clear();
        _cmac_buffer.resize([&]() -> std::size_t {
          switch (block_size()) {
              case cmac_block_size::_8:
                  return padded_length<8>(data.size());
              case cmac_block_size::_16:
                  return padded_length<16>(data.size());
          }
          return 0;
        }());

        std::copy(std::begin(data), std::end(data), std::begin(_cmac_buffer));

        // Spec requires XOR-ing the last block with the appropriate key.
        const auto last_block = _cmac_buffer.view(_cmac_buffer.size() - block_size_bytes());
        if (_cmac_buffer.size() == data.size()) {
            // Was not padded
            std::transform(std::begin(last_block), std::end(last_block), _subkey_nopad.get(),
                           std::begin(last_block), xor_op);
        } else {
            // Was padded, but spec wants to pad with 80 00 .. 00, so change one byte
            _cmac_buffer[data.size()] = 0x80;
            std::transform(std::begin(last_block), std::end(last_block), _subkey_pad.get(),
                           std::begin(last_block), xor_op);
        }

        // Return the first 8 bytes of the last block
        crypto.do_crypto(_cmac_buffer.data_view(), iv, crypto_operation::mac);
        std::copy(std::begin(iv), std::begin(iv) + retval.size(), std::begin(retval));
        return retval;
    }

    cmac_provider::cmac_provider(crypto_3k3des_base &crypto)
        : cmac_provider{cmac_block_size::_8, bits::crypto_cmac_xor_byte_3k3des} {
        initialize_subkeys(crypto);
    }

    cmac_provider::cmac_provider(crypto_aes_base &crypto)
        : cmac_provider{cmac_block_size::_16, bits::crypto_cmac_xor_byte_aes} {
        initialize_subkeys(crypto);
    }
}