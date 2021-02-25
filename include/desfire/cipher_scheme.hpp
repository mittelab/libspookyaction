//
// Created by Pietro Saccardi on 02/01/2021.
//

#ifndef DESFIRE_CIPHER_SCHEME_HPP
#define DESFIRE_CIPHER_SCHEME_HPP

#include "cipher.hpp"
#include "crypto_algo.hpp"
#include "log.h"
#include <cassert>

namespace desfire {

    namespace {
        using mlab::bin_stream;
        using mlab::lsb32;
    }// namespace

    template <std::size_t BlockSize, std::uint8_t CMACSubkeyR>
    class cipher_scheme : public virtual cipher, public cipher_traits<BlockSize, 8, 4> {
    public:
        using traits_base = cipher_traits<BlockSize, 8, 4>;
        using typename traits_base::block_t;
        using typename traits_base::crc_t;
        using typename traits_base::mac_t;

        using traits_base::block_size;
        using traits_base::crc_size;

    private:
        static constexpr std::uint8_t cmac_subkey_r = CMACSubkeyR;
        using cmac_subkey_t = std::array<std::uint8_t, block_size>;

        cmac_subkey_t _cmac_subkey_pad;
        cmac_subkey_t _cmac_subkey_nopad;
        block_t _global_iv;

        [[nodiscard]] block_t &get_iv();

    protected:
        cipher_scheme();

        /**
         * @note **Subclassing guide:** subclasses shall call this method as last in the constructor, and as last in
         * @ref reinit_with_session_Key. This method will derive CMAC keys, therefore all crypto primitives shall be
         * in place before performing this call.
         */
        void initialize();

    public:
        virtual void do_crypto(range<bin_data::iterator> const &data, crypto_direction dir, block_t &iv) = 0;

        mac_t compute_mac(range<bin_data::const_iterator> const &data);

        /**
         * @param status The CRC is always computed on ''data || status'', so we always need to update it for that
         */
        bool drop_padding_verify_crc(bin_data &d, std::uint8_t status);

        void prepare_tx(bin_data &data, std::size_t offset, cipher_mode mode) final;

        bool confirm_rx(bin_data &data, cipher_mode mode) final;
    };

}// namespace desfire

namespace desfire {

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
            do_crypto(block.view(), crypto_direction::mac, get_iv());
            return block;
        }();

        // Copy and prep
        std::copy(std::begin(cmac_base_data), std::end(cmac_base_data), std::begin(_cmac_subkey_nopad));
        prepare_subkey(_cmac_subkey_nopad, (cmac_base_data.front() & 0x80) != 0);

        // Do it again
        _cmac_subkey_pad = _cmac_subkey_nopad;
        prepare_subkey(_cmac_subkey_pad, (_cmac_subkey_nopad.front() & 0x80) != 0);

        ESP_LOGD(DESFIRE_TAG " KEY", "CMAC key for unpadded data:");
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " KEY", _cmac_subkey_nopad.data(), _cmac_subkey_nopad.size(), ESP_LOG_DEBUG);
        ESP_LOGD(DESFIRE_TAG " KEY", "CMAC key for padded data:");
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " KEY", _cmac_subkey_pad.data(), _cmac_subkey_pad.size(), ESP_LOG_DEBUG);
    }

    template <std::size_t BlockSize, std::uint8_t CMACSubkeyR>
    typename cipher_scheme<BlockSize, CMACSubkeyR>::mac_t cipher_scheme<BlockSize, CMACSubkeyR>::compute_mac(
            range<bin_data::const_iterator> const &data) {
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
        do_crypto(buffer.view(), crypto_direction::mac, iv);
        return {iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6], iv[7]};
    }

    template <std::size_t BlockSize, std::uint8_t CMACSubkeyR>
    bool cipher_scheme<BlockSize, CMACSubkeyR>::drop_padding_verify_crc(bin_data &d, std::uint8_t status) {
        const auto crc_fn = [=](bin_data::const_iterator b, bin_data::const_iterator e, std::uint32_t init) -> std::uint32_t {
            // Here we get a sequence [[ DATA || CRC ]]. But we need to compute the CRC on [[ DATA || STATUS || CRC ]].
            // So we split into two ranges, b..m and m..e, and chain the CRCs
            assert(std::distance(b, e) >= 0);
            const auto sequence_length = static_cast<decltype(traits_base::crc_size)>(std::distance(b, e));
            const auto m = b + (std::max(sequence_length, traits_base::crc_size) - traits_base::crc_size);
            assert(std::distance(b, m) >= 0);
            assert(std::distance(m, e) >= 0);
            // CRC of [[ DATA ]]
            const std::uint32_t crc_data = compute_crc32(range<bin_data::const_iterator>{b, m}, init);
            // CRC of [[ DATA || STATUS ]] = crc32({status}, crc32([[ DATA ]], init)
            const std::uint32_t crc_data_status = compute_crc32(status, crc_data);
            // CRC of [[ DATA || STATUS || CRC ]] (should be 0)
            const std::uint32_t crc_full = compute_crc32(range<bin_data::const_iterator>{m, e}, crc_data_status);
            return crc_full;
        };
        const auto [end_payload, did_verify] = find_crc_tail<block_size>(std::begin(d), std::end(d), crc_fn, crc32_init, false);
        if (did_verify) {
            const std::size_t payload_length = std::distance(std::begin(d), end_payload);
            // In case of error, make sure to not get any weird size/number
            d.resize(std::max(payload_length, crc_size) - crc_size);
            return true;
        }
        return false;
    }

    template <std::size_t BlockSize, std::uint8_t CMACSubkeyR>
    void cipher_scheme<BlockSize, CMACSubkeyR>::prepare_tx(
            bin_data &data, std::size_t offset, cipher_mode mode) {
        if (mode == cipher_mode::plain or mode == cipher_mode::maced) {
            // Plain and MAC may still require to pass data through CMAC, unless specified otherwise
            // CMAC has to be computed on the whole data
            const mac_t cmac = compute_mac(data.view());
            ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " TX MAC", cmac.data(), cmac.size(), ESP_LOG_DEBUG);
            if (mode == cipher_mode::maced) {
                // Only MAC comm mode will actually append
                data << cmac;
            }
        } else {
            if (offset >= data.size()) {
                return;// Nothing to do
            }
            if (mode == cipher_mode::ciphered) {
                data.reserve(offset + padded_length<block_size>(data.size() + crc_size - offset));
                // CRC has to be computed on the whole data
                data << lsb32 << compute_crc32(data);
            } else {
                data.reserve(offset + padded_length<block_size>(data.size() - offset));
            }
            data.resize(offset + padded_length<block_size>(data.size() - offset), 0x00);
            do_crypto(data.view(offset), crypto_direction::encrypt, get_iv());
        }
    }

    template <std::size_t BlockSize, std::uint8_t CMACSubkeyR>
    bool cipher_scheme<BlockSize, CMACSubkeyR>::confirm_rx(bin_data &data, cipher_mode mode) {
        if (data.size() == 1) {
            // Just status byte, return as-is
            return true;
        }
        if (mode == cipher_mode::plain) {
            // Always pass data + status byte through CMAC
            // This will keep the IV in sync
            const auto cmac = compute_mac(data.view());
            ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " RX MAC", cmac.data(), cmac.size(), ESP_LOG_DEBUG);
        } else if (mode == cipher_mode::maced) {
            // [ data || maced || status ] -> [ data || status || maced ]; rotate mac_size + 1 bytes
            std::rotate(data.rbegin(), data.rbegin() + 1, data.rbegin() + traits_base::mac_size + 1);
            // This will keep the IV in sync
            const mac_t computed_mac = compute_mac(data.view(0, data.size() - traits_base::mac_size));
            ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " RX MAC", computed_mac.data(), computed_mac.size(), ESP_LOG_DEBUG);
            // Extract the transmitted maced
            bin_stream s{data};
            s.seek(data.size() - traits_base::mac_size);
            mac_t rxd_mac{};
            s >> rxd_mac;
            if (rxd_mac == computed_mac) {
                // Good, drop the maced
                data.resize(data.size() - traits_base::mac_size);
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
            do_crypto(data.view(), crypto_direction::decrypt, get_iv());
            if (mode == cipher_mode::ciphered) {
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

}// namespace desfire

#endif//DESFIRE_CIPHER_SCHEME_HPP
