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

}