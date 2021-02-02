//
// Created by Pietro Saccardi on 02/01/2021.
//

#ifndef DESFIRE_CIPHER_SCHEME_IMPL_HPP
#define DESFIRE_CIPHER_SCHEME_IMPL_HPP

#include <esp_log.h>
#include "log.h"
#include "cipher_scheme.hpp"
#include "crypto_algo.hpp"

namespace desfire {

    const char *to_string(comm_mode);

    template <std::size_t BlockSize, std::uint8_t CMACSubkeyR>
    cipher_scheme<BlockSize, CMACSubkeyR>::cipher_scheme() : _cmac_subkey_pad{}, _cmac_subkey_nopad{}, _global_iv{} {
        set_iv_mode(cipher_iv::global);
    }

    template <std::size_t BlockSize, std::uint8_t CMACSubkeyR>
    void cipher_scheme<BlockSize, CMACSubkeyR>::initialize() {
        std::fill_n(std::begin(_cmac_subkey_pad), block_size, 0);
        std::fill_n(std::begin(_cmac_subkey_nopad), block_size, 0);
        std::fill_n(std::begin(_global_iv), block_size, 0);

        /// Perform key derivation
        DESFIRE_LOGD("Deriving CMAC subkeys...");

        static const auto prepare_subkey = [](cmac_subkey_t &subkey, bool xor_with_subkey_r) {
            // Some app-specific magic: lshift by one
            lshift_sequence(std::begin(subkey), std::end(subkey), 1);
            // ...and xor with R if the MSB is one
            if (xor_with_subkey_r) {
                subkey[block_size - 1] ^= cmac_subkey_r;
            }
        };

        const bin_data cmac_base_data = [&]() {
            iv_session session{*this, cipher_iv::zero};
            // Prepare subkey by ciphering
            bin_data block;
            block.resize(block_size, 0x00);
            do_crypto(block.view(), crypto_mode::mac, get_iv());
            return block;
        }();

        // Copy and prep
        std::copy(std::begin(cmac_base_data), std::end(cmac_base_data), std::begin(_cmac_subkey_nopad));
        prepare_subkey(_cmac_subkey_nopad, (cmac_base_data.front() & 0x80) != 0);

        // Do it again
        _cmac_subkey_pad = _cmac_subkey_nopad;
        prepare_subkey(_cmac_subkey_pad, (_cmac_subkey_nopad.front() & 0x80) != 0);
    }

    template <std::size_t BlockSize, std::uint8_t CMACSubkeyR>
    typename cipher_scheme<BlockSize, CMACSubkeyR>::mac_t cipher_scheme<BlockSize, CMACSubkeyR>::compute_mac(
            range <bin_data::const_iterator> const &data) {
        static const auto xor_op = [](std::uint8_t l, std::uint8_t r) -> std::uint8_t { return l ^ r; };
        static bin_data buffer{};

        // Resize the buffer and copy data
        buffer.clear();
        buffer.resize(padded_length<block_size>(data.size()), 0x00);
        std::copy(std::begin(data), std::end(data), std::begin(buffer));

        // Spec requires XOR-ing the last block with the appropriate key.
        const auto last_block = buffer.view(buffer.size() - block_size);
        if (buffer.size() == data.size()) {
            // Was not padded
            std::transform(std::begin(last_block), std::end(last_block), std::begin(_cmac_subkey_nopad),
                           std::begin(last_block), xor_op);
        } else {
            // Was padded, but spec wants to pad with 80 00 .. 00, so change one byte
            buffer[data.size()] = 0x80;
            std::transform(std::begin(last_block), std::end(last_block), std::begin(_cmac_subkey_pad),
                           std::begin(last_block), xor_op);
        }

        // Return the first 8 bytes of the last block
        block_t &iv = get_iv();
        do_crypto(buffer.view(), crypto_mode::mac, iv);
        return {iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6], iv[7]};
    }

    template <std::size_t BlockSize, std::uint8_t CMACSubkeyR>
    bool cipher_scheme<BlockSize, CMACSubkeyR>::drop_padding_verify_crc(bin_data &d, std::uint8_t status) {
        const auto crc_fn = [=](
                bin_data::const_iterator b, bin_data::const_iterator e, std::uint32_t init) -> std::uint32_t
        {
            const bin_data status_byte = bin_data::chain(status);
            // Simulate the presence of an extra status byte by doing an extra crc call
            const std::uint32_t crc_of_data = compute_crc32(range<bin_data::const_iterator>{b, e}, init);
            const std::uint32_t crc_of_data_and_status = compute_crc32(status_byte, crc_of_data);
            return crc_of_data_and_status;
        };
        const auto end_payload_did_verify = find_crc_tail<block_size>(std::begin(d), std::end(d), crc_fn, crc32_init);
        if (end_payload_did_verify.second) {
            const std::size_t payload_length = std::distance(std::begin(d), end_payload_did_verify.first);
            // In case of error, make sure to not get any weird size/number
            d.resize(std::max(payload_length, crc_size) - crc_size);
            return true;
        }
        return false;
    }

    template <std::size_t BlockSize, std::uint8_t CMACSubkeyR>
    void cipher_scheme<BlockSize, CMACSubkeyR>::prepare_tx(
            bin_data &data, std::size_t offset, cipher::config const &cfg) {
        if (cfg.mode != comm_mode::cipher) {
            // Plain and MAC may still require to pass data through CMAC, unless specified otherwise
            if (not cfg.do_mac) {
                return;
            }
            // CMAC has to be computed on the whole data
            const mac_t cmac = compute_mac(data.view());
            ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " TX MAC", cmac.data(), cmac.size(), ESP_LOG_DEBUG);
            if (cfg.mode == comm_mode::mac) {
                // Only MAC comm mode will actually append
                data << cmac;
            }
        } else if (cfg.do_cipher) {
            if (offset >= data.size()) {
                return;  // Nothing to do
            }
            if (cfg.do_crc) {
                data.reserve(offset + padded_length<block_size>(data.size() + crc_size - offset));
                // CRC has to be computed on the whole data
                data << lsb32 << compute_crc32(data);
            } else {
                data.reserve(offset + padded_length<block_size>(data.size() - offset));
            }
            data.resize(offset + padded_length<block_size>(data.size() - offset), 0x00);
            do_crypto(data.view(offset), crypto_mode::encrypt, get_iv());
        }
    }

    template <std::size_t BlockSize, std::uint8_t CMACSubkeyR>
    bool cipher_scheme<BlockSize, CMACSubkeyR>::confirm_rx(bin_data &data, cipher::config const &cfg) {
        if (data.size() == 1) {
            // Just status byte, return as-is
            return true;
        }
        switch (cfg.mode) {
            case comm_mode::plain:
                // Always pass data + status byte through CMAC, if required
                if (cfg.do_mac) {
                    // This will keep the IV in sync
                    const auto cmac = compute_mac(data.view());
                    ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " RX MAC", cmac.data(), cmac.size(), ESP_LOG_DEBUG);
                }
                break;
            case comm_mode::mac:
                if (cfg.do_mac) {
                    // [ data || mac || status ] -> [ data || status || mac ]; rotate mac_size + 1 bytes
                    std::rotate(data.rbegin(), data.rbegin() + 1, data.rbegin() + traits_base::mac_size + 1);
                    // This will keep the IV in sync
                    const mac_t computed_mac = compute_mac(data.view(0, data.size() - traits_base::mac_size));
                    ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " RX MAC", computed_mac.data(), computed_mac.size(), ESP_LOG_DEBUG);
                    // Extract the transmitted mac
                    bin_stream s{data};
                    s.seek(data.size() - traits_base::mac_size);
                    mac_t rxd_mac{};
                    s >> rxd_mac;
                    if (rxd_mac == computed_mac) {
                        // Good, drop the mac
                        data.resize(data.size() - traits_base::mac_size);
                        return true;
                    }
                    ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " != MAC", rxd_mac.data(), rxd_mac.size(), ESP_LOG_DEBUG);
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
                    do_crypto(data.view(), crypto_mode::decrypt, get_iv());
                    if (cfg.do_crc) {
                        // Truncate the padding and the crc
                        const bool did_verify = drop_padding_verify_crc(data, status);
                        // Reappend the status byte
                        data << status;
                        return did_verify;
                    } else {
                        // Reappend the status byte
                        data << status;
                        return true;
                    }
                }
                break;
        }
        return true;
    }

    template <std::size_t BlockSize, std::uint8_t CMACSubkeyR>
    typename cipher_scheme<BlockSize, CMACSubkeyR>::block_t &cipher_scheme<BlockSize, CMACSubkeyR>::get_iv() {
        static block_t _null_iv{};
        if (iv_mode() == cipher_iv::global) {
            return _global_iv;
        }
        // Reset every time
        std::fill_n(std::begin(_null_iv), block_size, 0x00);
        return _null_iv;
    }

}

#endif //DESFIRE_CIPHER_SCHEME_IMPL_HPP
