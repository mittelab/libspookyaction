//
// Created by Pietro Saccardi on 02/01/2021.
//

#include <esp_log.h>
#include <rom/crc.h>
#include "desfire/log.h"
#include "desfire/crypto_algo.hpp"
#include "desfire/cipher_scheme.hpp"

namespace desfire {

    cipher_legacy_scheme::mac_t cipher_legacy_scheme::compute_mac(range <bin_data::const_iterator> data) {
        static bin_data buffer{};

        // Resize the buffer and copy data
        buffer.resize(padded_length<block_size>(data.size()), 0x00);
        std::copy(std::begin(data), std::end(data), std::begin(buffer));

        // Return the first 4 bytes of the last block
        block_t iv = get_null_iv();  // Copy locally the IV for local usage
        do_crypto(buffer.view(), true, iv);
        return {iv[0], iv[1], iv[2], iv[3]};
    }

    cipher_legacy_scheme::crc_t cipher_legacy_scheme::compute_crc(
            range <bin_data::const_iterator> data, std::uint16_t init) {
        /* @note This is correct, we need to negate the init value (0x6363, as per spec), negate the output value
         * (that is documented in ESP's CRC header), and remember to send LSB first.
         */
        const std::uint16_t word = ~crc16_le(~init, data.data(), data.size());
        return {std::uint8_t(word & 0xff), std::uint8_t(word >> 8)};
    }

    bool cipher_legacy_scheme::drop_padding_verify_crc(bin_data &d) {
        static const auto crc_fn = [](
                bin_data::const_iterator b, bin_data::const_iterator e, std::uint16_t init) -> std::uint16_t {
            return ~crc16_le(~init, &*b, std::distance(b, e));
        };
        const auto end_payload_did_verify = find_crc_tail<block_size>(std::begin(d), std::end(d), crc_fn, crc_init);
        if (end_payload_did_verify.second) {
            const std::size_t payload_length = std::distance(std::begin(d), end_payload_did_verify.first);
            // In case of error, make sure to not get any weird size/number
            d.resize(std::max(payload_length, crc_size) - crc_size);
            return true;
        }
        return false;
    }

    cipher_legacy_scheme::block_t &cipher_legacy_scheme::get_null_iv() {
        static block_t _iv{};
        // Legacy protocol always uses 0x0
        std::fill_n(std::begin(_iv), block_size, 0x00);
        return _iv;
    }

    void cipher_legacy_scheme::prepare_tx(bin_data &data, std::size_t offset, cipher::config const &cfg) {
        if (offset >= data.size()) {
            return;  // Nothing to do
        }
        switch (cfg.mode) {
            case comm_mode::plain:
                break;  // Nothing to do
            case comm_mode::mac:
                if (cfg.do_mac) {
                    // Apply mac overrides mode.
                    if (offset >= data.size() - 1) {
                        DESFIRE_LOGE("Specified offset leaves no data to mac.");
                        break;
                    }
                    data << compute_mac(data.view(offset));
                }
                break;
            case comm_mode::cipher:
                if (cfg.do_cipher) {
                    if (offset >= data.size() - 1) {
                        DESFIRE_LOGE("Specified offset leaves no data to encipher.");
                        break;
                    }
                    if (cfg.do_crc) {
                        data.reserve(offset + padded_length<block_size>(data.size() + crc_size - offset));
                        data << compute_crc(data.view(offset), crc_init);
                    } else {
                        data.reserve(offset + padded_length<block_size>(data.size() - offset));
                    }
                    data.resize(offset + padded_length<block_size>(data.size() - offset), 0x00);
                    // This is actually correct. The legacy mode of the Mifare does only encryption and not
                    // decryption, so we will have to decrypt before sending.
                    do_crypto(data.view(offset), false, get_null_iv());
                }
                break;
        }
    }

    void cipher_legacy_scheme::encrypt(bin_data &data) {
        data.resize(padded_length<block_size>(data.size()), 0x00);
        do_crypto(data.view(), true, get_null_iv());
    }

    void cipher_legacy_scheme::decrypt(bin_data &data) {
        data.resize(padded_length<block_size>(data.size()), 0x00);
        do_crypto(data.view(), false, get_null_iv());
    }


    bool cipher_legacy_scheme::confirm_rx(bin_data &data, cipher::config const &cfg) {
        if (data.size() == 1) {
            // Just status byte, return as-is
            return true;
        }
        switch (cfg.mode) {
            case comm_mode::plain:
                break;  // Nothing to do
            case comm_mode::mac:
                if (cfg.do_mac) {
                    bin_stream s{data};
                    // Data, followed by mac, followed by status
                    const auto data_view = s.read(s.remaining() - mac_size - 1);
                    // Compute mac on data
                    const mac_t computed_mac = compute_mac(data_view);
                    // Extract the transmitted mac
                    mac_t rxd_mac{};
                    s >> rxd_mac;
                    if (rxd_mac == computed_mac) {
                        // Good, move status byte at the end and drop the mac
                        data[data.size() - mac_size - 1] = data[data.size() - 1];
                        data.resize(data.size() - mac_size);
                        return true;
                    }
                    return false;
                }
                break;
            case comm_mode::cipher:
                if (cfg.do_cipher) {
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
                    do_crypto(data.view(), false, get_null_iv());
                    // Truncate the padding and the crc
                    const bool did_verify = drop_padding_verify_crc(data);
                    // Reappend the status byte
                    data << status;
                    return did_verify;
                }
                break;
        }
        return true;
    }


}