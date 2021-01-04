//
// Created by Pietro Saccardi on 02/01/2021.
//

#ifndef DESFIRE_CIPHER_SCHEME_IMPL_HPP
#define DESFIRE_CIPHER_SCHEME_IMPL_HPP

#include <esp_log.h>
#include <rom/crc.h>
#include "log.h"
#include "cipher_scheme.hpp"
#include "crypto_algo.hpp"

namespace desfire {

    const char *to_string(comm_mode);

    template <std::size_t BlockSize, std::uint8_t CMACSubkeyR>
    void cipher_scheme<BlockSize, CMACSubkeyR>::initialize() {
        std::fill_n(std::begin(_cmac_subkey_pad), block_size, 0);
        std::fill_n(std::begin(_cmac_subkey_nopad), block_size, 0);
        std::fill_n(std::begin(_global_iv), block_size, 0);

        static const auto prepare_subkey = [](cmac_subkey_t &subkey) {
            // Some app-specific magic: lshift by one
            lshift_sequence(std::begin(subkey), std::end(subkey), 1);
            // ...and xor with R if the MSB is one
            if ((subkey[0] & (1 << 7)) != 0) {
                subkey[block_size - 1] ^= cmac_subkey_r;
            }
        };

        static block_t iv{};
        static bin_data data{};
        // Initialize data and IV at zero
        std::fill_n(std::begin(iv), block_size, 0);
        data.clear();
        data.resize(block_size, 0x0);
        // Crypt on local IV
        do_crypto(data.view(), true, iv);

        // Copy and prep
        std::copy(std::begin(data), std::end(data), std::begin(_cmac_subkey_nopad));
        prepare_subkey(_cmac_subkey_nopad);

        // Do it again
        _cmac_subkey_pad = _cmac_subkey_nopad;
        prepare_subkey(_cmac_subkey_pad);
    }

    template <std::size_t BlockSize, std::uint8_t CMACSubkeyR>
    typename cipher_scheme<BlockSize, CMACSubkeyR>::mac_t cipher_scheme<BlockSize, CMACSubkeyR>::compute_mac(
            range <bin_data::const_iterator> data) {
        static const auto xor_op = [](std::uint8_t l, std::uint8_t r) -> std::uint8_t { return l ^ r; };
        static bin_data buffer{};

        // Resize the buffer and copy data
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
        do_crypto(buffer.view(), true, _global_iv);
        return {_global_iv[0], _global_iv[1], _global_iv[2], _global_iv[3], _global_iv[4], _global_iv[5],
                _global_iv[6], _global_iv[7]};
    }

    template <std::size_t BlockSize, std::uint8_t CMACSubkeyR>
    typename cipher_scheme<BlockSize, CMACSubkeyR>::crc_t cipher_scheme<BlockSize, CMACSubkeyR>::compute_crc(
            range <bin_data::const_iterator> data, std::uint32_t init) {
        const std::uint32_t dword = ~crc32_le(~init, data.data(), data.size());
        return {
                std::uint8_t(dword & 0xff),
                std::uint8_t((dword >> 8) & 0xff),
                std::uint8_t((dword >> 16) & 0xff),
                std::uint8_t((dword >> 24) & 0xff)
        };
    }

    template <std::size_t BlockSize, std::uint8_t CMACSubkeyR>
    bool cipher_scheme<BlockSize, CMACSubkeyR>::drop_padding_verify_crc(bin_data &d, std::uint8_t status) {
        const auto crc_fn = [=](
                bin_data::const_iterator b, bin_data::const_iterator e, std::uint32_t init) -> std::uint32_t {
            // Simulate the presence of an extra status byte by doing an extra crc call
            const std::uint32_t crc_of_data = ~crc32_le(~init, &*b, std::distance(b, e));
            const std::uint32_t crc_of_data_and_status = ~crc32_le(~crc_of_data, &status, 1);
            return crc_of_data_and_status;
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

    template <std::size_t BlockSize, std::uint8_t CMACSubkeyR>
    void cipher_scheme<BlockSize, CMACSubkeyR>::prepare_tx(
            bin_data &data, std::size_t offset, cipher::config const &cfg) {
        DESFIRE_LOGD("Modern protocol, preparing outgoing data with comm mode %s", to_string(cfg.mode));
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG, data.data(), data.size(), ESP_LOG_DEBUG);
        if (offset >= data.size()) {
            return;  // Nothing to do
        }
        if (cfg.mode != comm_mode::cipher) {
            // Plain and MAC may still require to pass data through CMAC, unless specified otherwise
            if (not cfg.do_mac) {
                return;
            }
            // CMAC has to be computed on the whole data
            const mac_t cmac = compute_mac(data.view());
            if (cfg.mode == comm_mode::mac) {
                // Only MAC comm mode will actually append
                data << cmac;
            }
        } else if (cfg.do_cipher) {
            if (cfg.do_crc) {
                data.reserve(offset + padded_length<block_size>(data.size() + crc_size - offset));
                // CRC has to be computed on the whole data
                data << compute_crc(data.view(), crc_init);
            } else {
                data.reserve(offset + padded_length<block_size>(data.size() - offset));
            }
            data.resize(offset + padded_length<block_size>(data.size() - offset), 0x00);
            do_crypto(data.view(offset), true, _global_iv);
        }
    }

    template <std::size_t BlockSize, std::uint8_t CMACSubkeyR>
    bool cipher_scheme<BlockSize, CMACSubkeyR>::confirm_rx(bin_data &data, cipher::config const &cfg) {
        DESFIRE_LOGD("Modern protocol, validating incoming data with comm mode %s", to_string(cfg.mode));
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG, data.data(), data.size(), ESP_LOG_DEBUG);
        if (data.size() == 1) {
            // Just status byte, return as-is
            return true;
        }
        switch (cfg.mode) {
            case comm_mode::plain:
                // Always pass data + status byte through CMAC, if required
                if (cfg.do_mac) {
                    // This will keep the IV in sync
                    compute_mac(data.view());
                }
                break;
            case comm_mode::mac:
                if (cfg.do_mac) {
                    // [ data || mac || status ] -> [ data || status || mac ]; rotate mac_size + 1 bytes
                    std::rotate(data.rend(), data.rend() + 1, data.rend() + traits_base::mac_size + 1);
                    // This will keep the IV in sync
                    const mac_t computed_mac = compute_mac(data.view(0, data.size() - traits_base::mac_size));
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
                    do_crypto(data.view(), false, _global_iv);
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
    void cipher_scheme<BlockSize, CMACSubkeyR>::encrypt(bin_data &data) {
        data.resize(padded_length<block_size>(data.size()), 0x00);
        do_crypto(data.view(), true, _global_iv);
    }

    template <std::size_t BlockSize, std::uint8_t CMACSubkeyR>
    void cipher_scheme<BlockSize, CMACSubkeyR>::decrypt(bin_data &data) {
        data.resize(padded_length<block_size>(data.size()), 0x00);
        do_crypto(data.view(), false, _global_iv);
    }


}

#endif //DESFIRE_CIPHER_SCHEME_IMPL_HPP
