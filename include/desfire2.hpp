//
// Created by Pietro Saccardi on 29/12/2020.
//

#ifndef APERTURAPORTA_DESFIRE2_H
#define APERTURAPORTA_DESFIRE2_H

#include <array>

#include <mbedtls/des.h>
#include <rom/crc.h>
#include <cassert>
#include "bin_data.hpp"

namespace desfire {
    using pn532::bin_data;
    template <class It>
    using range = pn532::range<It>;


    class cipher {
    public:
        struct config;

        virtual void prepare_tx(bin_data &data, std::size_t enc_offset, config const &cfg) = 0;

        virtual ~cipher() = default;
    };

    enum struct comm_mode {
        plain,
        mac,
        cipher
    };

    struct cipher::config {
        comm_mode mode;
        bool do_mac;        // If required by protocol and comm_mode
        bool do_cipher;     // If required by protocol and comm_mode
        bool do_crc;        // If required by protocol and comm_mode
    };

    namespace crypto {
        template <std::size_t BlockSize, std::size_t MACSize, std::size_t CRCSize>
        struct cipher_traits {
            static constexpr std::size_t block_size = BlockSize;
            static constexpr std::size_t mac_size = MACSize;
            static constexpr std::size_t crc_size = CRCSize;

            using block_t = std::array<std::uint8_t, block_size>;
            using mac_t = std::array<std::uint8_t, mac_size>;
            using crc_t = std::array<std::uint8_t, crc_size>;

            static std::size_t padded_length(std::size_t size) {
                static_assert(BlockSize % 2 == 0, "This version works just with powers of two.");
                return (size + BlockSize - 1) & -BlockSize;
            }
        };
    }

    class cipher_legacy_protocol : public virtual cipher, public crypto::cipher_traits<8, 4, 2> {
    protected:
        /**
         * @param data Data to encipher, in-place. Must have a size that is a multiple of @ref block_size.
         * @return The IV after the encryption is completed
         */
        virtual block_t encipher(range<bin_data::iterator> data) = 0;

        /**
         * Returns the first @ref mac_length bytes of the IV after encrypting @p data.
         */
        virtual mac_t compute_mac(range<bin_data::const_iterator> data) {
            static bin_data buffer{};
            buffer.resize(padded_length(data.size()), 0x00);
            std::copy(std::begin(data), std::end(data), std::begin(buffer));
            const block_t iv = encipher(buffer.view());
            return {iv[0], iv[1], iv[2], iv[3]};
        }

        /**
         * Computes the CRC16 of @p data, using 0x6363 as the initial value, returns ''{LSB, MSB}''.
         */
        virtual crc_t compute_crc(range<bin_data::const_iterator> data) {
            /* @note This is correct, we need to negate the init value (0x6363, as per spec), negate the output value
             * (that is documented in ESP's CRC header), and remember to send LSB first.
             */
            const std::uint16_t word = ~crc16_le(~0x6363, data.data(), data.size());
            return {std::uint8_t(word & 0xff), std::uint8_t(word >> 8)};
        }

        void prepare_tx(bin_data &data, std::size_t enc_offset, config const &cfg) override {
            switch (cfg.mode) {
                case comm_mode::plain:
                    break;  // Nothing to do
                case comm_mode::mac:
                    if (cfg.do_mac) {
                        // Apply mac overrides mode.
                        data << compute_mac(data.view(enc_offset));
                    }
                    break;
                case comm_mode::cipher:
                    if (cfg.do_cipher) {
                        if (cfg.do_crc) {
                            data << compute_crc(data.view(enc_offset));
                        }
                        data.resize(enc_offset + padded_length(data.size() - enc_offset), 0x00);
                        encipher(data.view(enc_offset));
                    }
                    break;
            }
        }
    };



    class cipher_des final : public cipher_legacy_protocol {
        mbedtls_des_context _context;
    public:
        explicit cipher_des(std::array<std::uint8_t, 8> const &key) : _context{} {
            mbedtls_des_init(&_context);
            mbedtls_des_setkey_enc(&_context, key.data());
        }

        ~cipher_des() override {
            mbedtls_des_free(&_context);
        }

    protected:
        block_t encipher(range<bin_data::iterator> data) override {
            assert(data.size() % block_size == 0);
            static block_t iv{};
            // In legacy authentication, the IV is reset every time
            iv = {0, 0, 0, 0, 0, 0, 0, 0};
            mbedtls_des_crypt_cbc(&_context, MBEDTLS_DES_ENCRYPT, data.size(), iv.data(), data.data(), data.data());
            return iv;
        }
    };

    class cipher_2k3des final : public cipher_legacy_protocol {
        mbedtls_des3_context _context;

    public:
        explicit cipher_2k3des(std::array<std::uint8_t, 16> const &key) : _context{} {
            mbedtls_des3_init(&_context);
            mbedtls_des3_set2key_enc(&_context, key.data());
        }

        ~cipher_2k3des() override {
            mbedtls_des3_free(&_context);
        }

    protected:
        block_t encipher(range<bin_data::iterator> data) override {
            assert(data.size() % block_size == 0);
            static block_t iv{};
            // In legacy authentication, the IV is reset every time
            iv = {0, 0, 0, 0, 0, 0, 0, 0};
            mbedtls_des3_crypt_cbc(&_context, MBEDTLS_DES_ENCRYPT, data.size(), iv.data(), data.data(), data.data());
            return iv;
        }
    };

}

#endif //APERTURAPORTA_DESFIRE2_H
