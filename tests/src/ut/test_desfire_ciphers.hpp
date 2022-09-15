//
// Created by spak on 3/16/21.
//

#ifndef SPOOKY_ACTION_TEST_DESFIRE_CIPHERS_HPP
#define SPOOKY_ACTION_TEST_DESFIRE_CIPHERS_HPP

#include <desfire/cipher_provider.hpp>
#include <desfire/crypto.hpp>
#include <desfire/esp32/crypto_impl.hpp>
#include <mlab/bin_data.hpp>
#include <unity.h>

namespace ut {
    namespace {
        using mlab::range;
    }

    /**
     * Enables usage of @ref desfire::cipher_default with DES and 2K3DES.
     * This is used in some of the examples from hack.cert.pl, which employ the "modern" authentication command with
     * legacy ciphers. It is unclear how to use CMAC in this case because we do not know what constants to use in the
     * subkey derivation, so that is disabled and broken, but other than that, it allows us to replay the examples
     * retrieved from the web.
     */
    template <class CryptoImpl, std::size_t BlockSize = 8>
    class fake_cmac_crypto final : public desfire::crypto_with_cmac {
        static_assert(std::is_base_of_v<desfire::crypto, CryptoImpl>);
        CryptoImpl _impl;

    protected:
        void setup_primitives_with_key(range<std::uint8_t const *> key) override;

    public:
        fake_cmac_crypto();

        [[nodiscard]] desfire::cipher_type cipher_type() const override;
        void init_session(range<std::uint8_t const *> random_data) override;
        void do_crypto(range<std::uint8_t *> data, range<std::uint8_t *> iv, desfire::crypto_operation op) override;
        void setup_with_key(range<std::uint8_t const *> key) override;
        mac_t do_cmac(range<std::uint8_t const *> data, range<std::uint8_t *> iv) override;
    };

    using always_default_cipher_provider = desfire::typed_cipher_provider<
            fake_cmac_crypto<desfire::esp32::crypto_des>,
            fake_cmac_crypto<desfire::esp32::crypto_2k3des>,
            desfire::esp32::crypto_3k3des,
            desfire::esp32::crypto_aes,
            desfire::cipher_default, desfire::cipher_default,
            desfire::cipher_default, desfire::cipher_default>;

    namespace desfire_ciphers {
        void test_des();
        void test_2k3des();
        void test_3k3des();
        void test_aes();
        void test_crc32();
        void test_crc16();
        void test_aes_kdf();
        void test_3k3des_kdf();
    }// namespace desfire_ciphers

}// namespace ut

namespace ut {

    template <class CryptoImpl, std::size_t BlockSize>
    fake_cmac_crypto<CryptoImpl, BlockSize>::fake_cmac_crypto() : crypto_with_cmac{BlockSize, 0x00}, _impl{} {}

    template <class CryptoImpl, std::size_t BlockSize>
    desfire::crypto_with_cmac::mac_t fake_cmac_crypto<CryptoImpl, BlockSize>::do_cmac(range<std::uint8_t const *> data, range<std::uint8_t *> iv) {
        TEST_FAIL_MESSAGE("Attempt to compute a CMAC with a fake CMAC crypto. This is not supported.");
        return {};
    }

    template <class CryptoImpl, std::size_t BlockSize>
    desfire::cipher_type fake_cmac_crypto<CryptoImpl, BlockSize>::cipher_type() const {
        return _impl.cipher_type();
    }

    template <class CryptoImpl, std::size_t BlockSize>
    void fake_cmac_crypto<CryptoImpl, BlockSize>::init_session(range<std::uint8_t const *> random_data) {
        _impl.init_session(random_data);
    }

    template <class CryptoImpl, std::size_t BlockSize>
    void fake_cmac_crypto<CryptoImpl, BlockSize>::setup_with_key(range<std::uint8_t const *> key) {
        _impl.setup_with_key(key);
    }

    template <class CryptoImpl, std::size_t BlockSize>
    void fake_cmac_crypto<CryptoImpl, BlockSize>::setup_primitives_with_key(range<std::uint8_t const *> key) {
        TEST_FAIL_MESSAGE("Attempt to setup a CMAC with a fake CMAC crypto. This is not supported.");
    }

    template <class CryptoImpl, std::size_t BlockSize>
    void fake_cmac_crypto<CryptoImpl, BlockSize>::do_crypto(range<std::uint8_t *> data, range<std::uint8_t *> iv, desfire::crypto_operation op) {
        _impl.do_crypto(data, iv, op);
    }
}// namespace ut

#endif//SPOOKY_ACTION_TEST_DESFIRE_CIPHERS_HPP
