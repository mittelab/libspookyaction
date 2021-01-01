//
// Created by Pietro Saccardi on 29/12/2020.
//

#ifndef APERTURAPORTA_DESFIRE2_H
#define APERTURAPORTA_DESFIRE2_H

#include <array>

#include <mbedtls/des.h>
#include <mbedtls/aes.h>
#include <rom/crc.h>
#include <cassert>
#include "bin_data.hpp"

namespace desfire {
    using pn532::bin_data;
    template <class It>
    using range = pn532::range<It>;
    using pn532::bin_stream;


    class cipher {
    public:
        struct config;

        virtual void prepare_tx(bin_data &data, std::size_t offset, config const &cfg) = 0;
        /**
         * Assume that status byte comes last.
         */
        virtual void confirm_rx(bin_data &data, config const &cfg) {}

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

        /**
         *
         * @tparam ByteIterator
         * @tparam N A unsigned integer size matching the crc size, e.g. ''std::uint32_t'' for a CRC32.
         * @tparam Fn Must match signature ''N crc_fn(ByteIterator b, ByteIterator e, N init)''.
         * @param begin
         * @param end
         * @param crc_fn
         * @param init
         * @return
         */
        template <class ByteIterator, class N, class Fn>
        static std::pair<ByteIterator, bool> find_crc_tail(ByteIterator begin, ByteIterator end, Fn &&crc_fn, N init) {
            static const auto nonzero_byte_pred = [](std::uint8_t b) -> bool { return b != 0; };
            // Store the last successful crc and end of the payload
            ByteIterator last_payload_end = end;
            bool crc_pass = false;
            if (begin != end) {
                assert(std::distance(begin, end) % block_size == 0);
                // Find the last nonzero byte, get and iterator to the element past that.
                // This is given by reverse scanning for a nonzero byte, and getting the underlying iterator.
                // Since the reverse iterator holds an underlying iterator to the next element (in the normal traversal
                // sense), we can just get that.
                const auto rev_end = std::reverse_iterator<ByteIterator>(end);
                auto end_payload = std::find_if(rev_end, rev_end + block_size, nonzero_byte_pred).base();
                for (   // Compute the crc until the supposed end of the payload
                        N crc = crc_fn(begin, end_payload, init);
                    // Keep advancing the supposed end of the payload until end
                        end_payload != end;
                    // Update the crc with one byte at a time
                        crc = crc_fn(end_payload, std::next(end_payload), crc), ++end_payload
                        ) {
                    if (crc == N(0)) {
                        // This is a valid end of the payload with a successful crc check
                        last_payload_end = end_payload;
                        crc_pass = true;
                    }
                }
            }
            return {last_payload_end, crc_pass};
        }
    };

    class cipher_legacy_scheme : public virtual cipher, public cipher_traits<8, 4, 2> {
    protected:
        static constexpr std::uint16_t crc_init = 0x6363;

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

        virtual crc_t compute_crc(range<bin_data::const_iterator> data, std::uint16_t init) {
            /* @note This is correct, we need to negate the init value (0x6363, as per spec), negate the output value
             * (that is documented in ESP's CRC header), and remember to send LSB first.
             */
            const std::uint16_t word = ~crc16_le(~init, data.data(), data.size());
            return {std::uint8_t(word & 0xff), std::uint8_t(word >> 8)};
        }

        virtual bool drop_padding_verify_crc(bin_data &d) {
            static const auto crc_fn = [](bin_data::const_iterator b, bin_data::const_iterator e, std::uint16_t init) -> std::uint16_t {
                return ~crc16_le(~init, &*b, std::distance(b, e));
            };
            const auto end_payload_did_verify = find_crc_tail(std::begin(d), std::end(d), crc_fn, crc_init);
            if (end_payload_did_verify.second) {
                const std::size_t payload_length = std::distance(std::begin(d), end_payload_did_verify.first);
                // In case of error, make sure to not get any weird size/number
                d.resize(std::max(payload_length, crc_size) - crc_size);
                return true;
            }
            return false;
        }

        void prepare_tx(bin_data &data, std::size_t offset, config const &cfg) override {
            if (offset >= data.size()) {
                return;  // Nothing to do
            }
            switch (cfg.mode) {
                case comm_mode::plain:
                    break;  // Nothing to do
                case comm_mode::mac:
                    assert(offset < data.size() - 1);
                    if (cfg.do_mac) {
                        // Apply mac overrides mode.
                        data << compute_mac(data.view(offset));
                    }
                    break;
                case comm_mode::cipher:
                    assert(offset < data.size() - 1);
                    if (cfg.do_cipher) {
                        if (cfg.do_crc) {
                            data.reserve(offset + padded_length(data.size() + crc_size - offset));
                            data << compute_crc(data.view(offset), crc_init);
                        } else {
                            data.reserve(offset + padded_length(data.size() - offset));
                        }
                        data.resize(offset + padded_length(data.size() - offset), 0x00);
                        // This is actually correct. The legacy mode of the Mifare does only encryption and not
                        // decryption, so we will have to decrypt before sending.
                        decipher(data.view(offset));
                    }
                    break;
            }
        }

        void confirm_rx(bin_data &data, config const &cfg) override {
            if (data.size() == 1) {
                // Just status byte, return as-is
                return;
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
                            /// @todo return success
                        } else {
                            /// @todo return mac_check_failed
                        }
                    }
                    break;
                case comm_mode::cipher:
                    if (cfg.do_cipher) {
                        // Pop the status byte
                        const std::uint8_t status = data.back();
                        data.pop_back();
                        // Decipher what's left
                        decipher(data.view(0, data.size()));
                        // Truncate the padding and the crc
                        const bool did_verify = drop_padding_verify_crc(data);
                        // Reappend the status byte
                        data << status;
                        /// @todo Return success or crc_check_failed depending on did_verify
                    }
                    break;
            }
        }
    };

    template <std::size_t BlockSize>
    class cipher_scheme : public virtual cipher, public cipher_traits<BlockSize, 8, 4> {
    public:
        using traits_base = cipher_traits<BlockSize, 8, 4>;
        using typename traits_base::mac_t;
        using typename traits_base::crc_t;
        using typename traits_base::block_t;

        using traits_base::padded_length;
        using traits_base::crc_size;
        using traits_base::block_size;

    private:
        static constexpr std::size_t cmac_subkey_length = 24;
        using cmac_subkey_t = std::array<std::uint8_t, cmac_subkey_length>;

        cmac_subkey_t _cmac_subkey_pad;
        cmac_subkey_t _cmac_subkey_nopad;
        block_t _global_iv;

    protected:
        static constexpr std::uint32_t crc_init = 0xffffffff;

        virtual void encipher(range<bin_data::iterator> data, block_t &iv) = 0;
        virtual void decipher(range<bin_data::iterator> data, block_t &iv) = 0;

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
            encipher(buffer.view(), _global_iv);
            return {_global_iv[0], _global_iv[1], _global_iv[2], _global_iv[3], _global_iv[4], _global_iv[5],
                    _global_iv[6], _global_iv[7]};
        }

        /**
         * Computes the CRC32 of @p data, returns LSB first.
         */
        virtual crc_t compute_crc(range<bin_data::const_iterator> data, std::uint32_t init) {
            const std::uint32_t dword = ~crc32_le(~init, data.data(), data.size());
            return {
                    std::uint8_t(dword & 0xff),
                    std::uint8_t((dword >>  8) & 0xff),
                    std::uint8_t((dword >> 16) & 0xff),
                    std::uint8_t((dword >> 24) & 0xff)
            };
        }

        virtual bool drop_padding_verify_crc(bin_data &d) {
            static const auto crc_fn = [](bin_data::const_iterator b, bin_data::const_iterator e, std::uint32_t init) -> std::uint32_t {
                return ~crc32_le(~init, &*b, std::distance(b, e));
            };
            const auto end_payload_did_verify = traits_base::find_crc_tail(std::begin(d), std::end(d), crc_fn, crc_init);
            if (end_payload_did_verify.second) {
                const std::size_t payload_length = std::distance(std::begin(d), end_payload_did_verify.first);
                // In case of error, make sure to not get any weird size/number
                d.resize(std::max(payload_length, crc_size) - crc_size);
                return true;
            }
            return false;
        }

        void prepare_tx(bin_data &data, std::size_t offset, config const &cfg) override {
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
                    data.reserve(offset + padded_length(data.size() + crc_size - offset));
                    // CRC has to be computed on the whole data
                    data << compute_crc(data.view(), crc_init);
                } else {
                    data.reserve(offset + padded_length(data.size() - offset));
                }
                data.resize(offset + padded_length(data.size() - offset), 0x00);
                encipher(data.view(offset), _global_iv);
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

    class cipher_3k3des final : public cipher_scheme<8> {
        mbedtls_des3_context _enc_context;
        mbedtls_des3_context _dec_context;

    public:
        explicit cipher_3k3des(std::array<std::uint8_t, 24> const &key) : _enc_context{}, _dec_context{} {
            mbedtls_des3_init(&_enc_context);
            mbedtls_des3_init(&_dec_context);
            mbedtls_des3_set3key_enc(&_enc_context, key.data());
            mbedtls_des3_set3key_enc(&_dec_context, key.data());
        }

        ~cipher_3k3des() override {
            mbedtls_des3_free(&_enc_context);
            mbedtls_des3_free(&_dec_context);
        }

    private:
        void do_crypto(range<bin_data::iterator> data, block_t &iv, bool encrypt) {
            assert(data.size() % block_size == 0);
            if (encrypt) {
                mbedtls_des3_crypt_cbc(&_enc_context, MBEDTLS_DES_ENCRYPT, data.size(), iv.data(), data.data(), data.data());
            } else {
                mbedtls_des3_crypt_cbc(&_dec_context, MBEDTLS_DES_DECRYPT, data.size(), iv.data(), data.data(), data.data());
            }
        }
    protected:
        void encipher(range<bin_data::iterator> data, block_t &iv) override {
            do_crypto(data, iv, true);
        }

        void decipher(range<bin_data::iterator> data, block_t &iv) override {
            do_crypto(data, iv, false);
        }
    };

    class cipher_aes final : public cipher_scheme<16> {
        mbedtls_aes_context _enc_context;
        mbedtls_aes_context _dec_context;

    public:
        explicit cipher_aes(std::array<std::uint8_t, 16> const &key) : _enc_context{}, _dec_context{} {
            mbedtls_aes_init(&_enc_context);
            mbedtls_aes_init(&_dec_context);
            mbedtls_aes_setkey_enc(&_enc_context, key.data(), 8 * key.size());
            mbedtls_aes_setkey_enc(&_dec_context, key.data(), 8 * key.size());
        }

        ~cipher_aes() override {
            mbedtls_aes_free(&_enc_context);
            mbedtls_aes_free(&_dec_context);
        }

    private:
        void do_crypto(range<bin_data::iterator> data, block_t &iv, bool encrypt) {
            assert(data.size() % block_size == 0);
            if (encrypt) {
                mbedtls_aes_crypt_cbc(&_enc_context, MBEDTLS_AES_ENCRYPT, data.size(), iv.data(), data.data(), data.data());
            } else {
                mbedtls_aes_crypt_cbc(&_dec_context, MBEDTLS_AES_DECRYPT, data.size(), iv.data(), data.data(), data.data());
            }
        }
    protected:
        void encipher(range<bin_data::iterator> data, block_t &iv) override {
            do_crypto(data, iv, true);
        }

        void decipher(range<bin_data::iterator> data, block_t &iv) override {
            do_crypto(data, iv, false);
        }
    };
}

#endif //APERTURAPORTA_DESFIRE2_H
