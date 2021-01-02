//
// Created by Pietro Saccardi on 02/01/2021.
//

#ifndef APERTURAPORTA_CIPHER_IMPL_HPP
#define APERTURAPORTA_CIPHER_IMPL_HPP

#include <mbedtls/des.h>
#include <mbedtls/aes.h>
#include "cipher_scheme_impl.hpp"

namespace desfire {

    class cipher_des final : public cipher_legacy_scheme {
        mbedtls_des_context _enc_context;
        mbedtls_des_context _dec_context;
    public:
        explicit cipher_des(std::array<std::uint8_t, 8> const &key);

        ~cipher_des() override;

    private:
        block_t do_crypto(range<bin_data::iterator> data, bool encrypt);

    protected:
        inline block_t encipher(range<bin_data::iterator> data) override;

        inline block_t decipher(range<bin_data::iterator> data) override;
    };

    class cipher_2k3des final : public cipher_legacy_scheme {
        mbedtls_des3_context _enc_context;
        mbedtls_des3_context _dec_context;

    public:
        explicit cipher_2k3des(std::array<std::uint8_t, 16> const &key);

        ~cipher_2k3des() override;

    private:
        block_t do_crypto(range<bin_data::iterator> data, bool encrypt);

    protected:
        inline block_t encipher(range<bin_data::iterator> data) override;

        inline block_t decipher(range<bin_data::iterator> data) override;
    };

    class cipher_3k3des final : public cipher_scheme<8, 0x1b> {
        mbedtls_des3_context _enc_context;
        mbedtls_des3_context _dec_context;

    public:
        explicit cipher_3k3des(std::array<std::uint8_t, 24> const &key);

        ~cipher_3k3des() override;

    private:
        void do_crypto(range<bin_data::iterator> data, block_t &iv, bool encrypt);

    protected:
        inline void encipher(range<bin_data::iterator> data, block_t &iv) override;

        inline void decipher(range<bin_data::iterator> data, block_t &iv) override;
    };

    class cipher_aes final : public cipher_scheme<16, 0x87> {
        mbedtls_aes_context _enc_context;
        mbedtls_aes_context _dec_context;

    public:
        explicit cipher_aes(std::array<std::uint8_t, 16> const &key);

        ~cipher_aes() override;

    private:
        void do_crypto(range<bin_data::iterator> data, block_t &iv, bool encrypt);

    protected:
        inline void encipher(range<bin_data::iterator> data, block_t &iv) override;

        inline void decipher(range<bin_data::iterator> data, block_t &iv) override;
    };
}

namespace desfire {
    cipher_des::block_t cipher_des::encipher(range<bin_data::iterator> data) {
        return do_crypto(data, true);
    }

    cipher_des::block_t cipher_des::decipher(range<bin_data::iterator> data) {
        return do_crypto(data, false);
    }

    cipher_2k3des::block_t cipher_2k3des::encipher(range<bin_data::iterator> data) {
        return do_crypto(data, true);
    }

    cipher_2k3des::block_t cipher_2k3des::decipher(range<bin_data::iterator> data) {
        return do_crypto(data, false);
    }

    void cipher_3k3des::encipher(range<bin_data::iterator> data, cipher_3k3des::block_t &iv) {
        do_crypto(data, iv, true);
    }

    void cipher_3k3des::decipher(range<bin_data::iterator> data, cipher_3k3des::block_t &iv) {
        do_crypto(data, iv, false);
    }

    void cipher_aes::encipher(range<bin_data::iterator> data, cipher_aes::block_t &iv) {
        do_crypto(data, iv, true);
    }

    void cipher_aes::decipher(range<bin_data::iterator> data, cipher_aes::block_t &iv) {
        do_crypto(data, iv, false);
    }
}

#endif //APERTURAPORTA_CIPHER_IMPL_HPP
