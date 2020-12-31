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

    class cipher_legacy_scheme : public virtual cipher, public crypto::cipher_traits<8, 4, 2> {
    protected:
        /**
         * @param data Data to encipher, in-place. Must have a size that is a multiple of @ref block_size.
         * @return The IV after the encryption is completed
         */
        virtual block_t encipher(range<bin_data::iterator> data) = 0;
        /**
         * @param data Data to decipher, in-place. Must have a size that is a multiple of @ref block_size.
         * @return The IV after the encryption is completed
         */
        virtual block_t decipher(range<bin_data::iterator> data) = 0;

        /**
         * Returns the first @ref mac_length bytes of the IV after encrypting @p data.
         */
        virtual mac_t compute_mac(range<bin_data::const_iterator> data) {
            static bin_data buffer{};

            // Resize the buffer and copy data
            buffer.resize(padded_length(data.size()), 0x00);
            std::copy(std::begin(data), std::end(data), std::begin(buffer));

            // Return the first 4 bytes of the last block
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
                            data.reserve(enc_offset + padded_length(data.size() + crc_size - enc_offset));
                            data << compute_crc(data.view(enc_offset));
                        } else {
                            data.reserve(enc_offset + padded_length(data.size() - enc_offset));
                        }
                        data.resize(enc_offset + padded_length(data.size() - enc_offset), 0x00);
                        // This is actually correct. The legacy mode of the Mifare does only encryption and not
                        // decryption, so we will have to decrypt before sending.
                        decipher(data.view(enc_offset));
                    }
                    break;
            }
        }
    };

    template <std::size_t BlockSize>
    class cipher_scheme : public virtual cipher, public crypto::cipher_traits<BlockSize, 8, 4> {
    public:
        using traits_base = typename crypto::cipher_traits<BlockSize, 8, 4>;
        using typename traits_base::mac_t;
        using typename traits_base::crc_t;
        using typename traits_base::block_t;

        using traits_base::padded_length;
        using traits_base::crc_size;
        using traits_base::block_size;

    protected:
        static constexpr std::size_t cmac_subkey_length = 24;
        using cmac_subkey_t = std::array<std::uint8_t, cmac_subkey_length>;

        cmac_subkey_t _cmac_subkey_pad;
        cmac_subkey_t _cmac_subkey_nopad;


        virtual void encipher(range<bin_data::iterator> data) = 0;

        virtual mac_t compute_mac(range<bin_data::const_iterator> data) {
            static const auto xor_op = [](std::uint8_t l, std::uint8_t r) -> std::uint8_t { return l ^ r; };
            static bin_data buffer{};

            // Resize the buffer and copy data
            buffer.resize(traits_base::padded_length(data.size()), 0x00);
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
            const block_t iv = encipher(buffer.view());
            return {iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6], iv[7]};
        }

        /**
         * Computes the CRC32 of @p data, returns LSB first.
         */
        virtual crc_t compute_crc(range<bin_data::const_iterator> data) {
            const std::uint32_t dword = ~crc32_le(0x0, data.data(), data.size());
            return {
                    std::uint8_t(dword & 0xff),
                    std::uint8_t((dword >>  8) & 0xff),
                    std::uint8_t((dword >> 16) & 0xff),
                    std::uint8_t((dword >> 24) & 0xff)
            };
        }

        void prepare_tx(bin_data &data, std::size_t enc_offset, config const &cfg) override {
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
                    data.reserve(enc_offset + padded_length(data.size() + crc_size - enc_offset));
                    // CRC has to be computed on the whole data
                    data << compute_crc(data.view());
                } else {
                    data.reserve(enc_offset + padded_length(data.size() - enc_offset));
                }
                data.resize(enc_offset + padded_length(data.size() - enc_offset), 0x00);
                encipher(data.view(enc_offset));
            }
        }
    };



    class cipher_des final : public cipher_legacy_scheme {
        mbedtls_des_context _enc_context;
        mbedtls_des_context _dec_context;
    public:
        explicit cipher_des(std::array<std::uint8_t, 8> const &key) : _enc_context{}, _dec_context{} {
            mbedtls_des_init(&_enc_context);
            mbedtls_des_init(&_dec_context);
            mbedtls_des_setkey_enc(&_enc_context, key.data());
            mbedtls_des_setkey_dec(&_dec_context, key.data());
        }

        ~cipher_des() override {
            mbedtls_des_free(&_enc_context);
            mbedtls_des_free(&_dec_context);
        }

    private:
        block_t do_crypto(range<bin_data::iterator> data, bool encrypt) {
            assert(data.size() % block_size == 0);
            static block_t iv{};
            // In legacy authentication, the IV is reset every time
            iv = {0, 0, 0, 0, 0, 0, 0, 0};
            if (encrypt) {
                mbedtls_des_crypt_cbc(&_enc_context, MBEDTLS_DES_ENCRYPT, data.size(), iv.data(), data.data(), data.data());
            } else {
                mbedtls_des_crypt_cbc(&_dec_context, MBEDTLS_DES_DECRYPT, data.size(), iv.data(), data.data(), data.data());
            }
            return iv;
        }
    protected:
        block_t encipher(range<bin_data::iterator> data) override {
            return do_crypto(data, true);
        }
        block_t decipher(range<bin_data::iterator> data) override {
            return do_crypto(data, false);
        }
    };

    class cipher_2k3des final : public cipher_legacy_scheme {
        mbedtls_des3_context _enc_context;
        mbedtls_des3_context _dec_context;

    public:
        explicit cipher_2k3des(std::array<std::uint8_t, 16> const &key) : _enc_context{}, _dec_context{} {
            mbedtls_des3_init(&_enc_context);
            mbedtls_des3_init(&_dec_context);
            mbedtls_des3_set2key_enc(&_enc_context, key.data());
            mbedtls_des3_set2key_enc(&_dec_context, key.data());
        }

        ~cipher_2k3des() override {
            mbedtls_des3_free(&_enc_context);
            mbedtls_des3_free(&_dec_context);
        }

    private:
        block_t do_crypto(range<bin_data::iterator> data, bool encrypt) {
            assert(data.size() % block_size == 0);
            static block_t iv{};
            // In legacy authentication, the IV is reset every time
            iv = {0, 0, 0, 0, 0, 0, 0, 0};
            if (encrypt) {
                mbedtls_des3_crypt_cbc(&_enc_context, MBEDTLS_DES_ENCRYPT, data.size(), iv.data(), data.data(), data.data());
            } else {
                mbedtls_des3_crypt_cbc(&_dec_context, MBEDTLS_DES_DECRYPT, data.size(), iv.data(), data.data(), data.data());
            }
            return iv;
        }
    protected:
        block_t encipher(range<bin_data::iterator> data) override {
            return do_crypto(data, true);
        }
        block_t decipher(range<bin_data::iterator> data) override {
            return do_crypto(data, false);
        }
    };

}

#endif //APERTURAPORTA_DESFIRE2_H
