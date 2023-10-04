//
// Created by spak on 3/16/21.
//

#include <catch.hpp>
#include <desfire/esp32/cipher_provider.hpp>
#include <desfire/kdf.hpp>


namespace ut::desfire_ciphers {
    using namespace desfire;

    /**
     * Enables usage of @ref desfire::protocol_default with DES and 2K3DES.
     * This is used in some of the examples from hack.cert.pl, which employ the "modern" authentication command with
     * legacy ciphers. It is unclear how to use CMAC in this case because we do not know what constants to use in the
     * subkey derivation, so that is disabled and broken, but other than that, it allows us to replay the examples
     * retrieved from the web.
     */
    template <class CryptoImpl, std::size_t BlockSize, std::size_t KeySize>
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

        /// @brief Informal protocol
        [[nodiscard]] std::array<std::uint8_t, KeySize> diversify_key_an10922(mlab::bin_data &diversify_input);
    };

    using always_default_cipher_provider = desfire::typed_cipher_provider<
            fake_cmac_crypto<desfire::esp32::crypto_des, 8, 8>,
            fake_cmac_crypto<desfire::esp32::crypto_2k3des, 8, 16>,
            desfire::esp32::crypto_3k3des,
            desfire::esp32::crypto_aes,
            desfire::protocol_default, desfire::protocol_default,
            desfire::protocol_default, desfire::protocol_default>;

    TEST_CASE("DES cipher", "[cipher][des]") {
        // Test using examples from https://hack.cert.pl/files/desfire-9f122c71e0057d4f747d2ee295b0f5f6eef8ac32.html
        // The examples from the website use ISO auth also for legacy auth, which means we need to use global IV
        auto c = always_default_cipher_provider{}.protocol_from_key(key<cipher_type::des>{});

        SECTION("Cmd1") {
            bin_data enc_data = {0x5D, 0x99, 0x4C, 0xE0, 0x85, 0xF2, 0x40, 0x89, /* status */ 0xAF};
            const bin_data dec_data = {0x4F, 0xD1, 0xB7, 0x59, 0x42, 0xA8, 0xB8, 0xE1, /* status */ 0xAF};
            c->confirm_rx(enc_data, comm_mode::ciphered_no_crc);
            CHECK(dec_data == enc_data);
        }

        SECTION("Cmd2") {
            bin_data dec_data = {0x84, 0x9B, 0x36, 0xC5, 0xF8, 0xBF, 0x4A, 0x09, 0xD1, 0xB7, 0x59, 0x42, 0xA8, 0xB8, 0xE1, 0x4F};
            const bin_data enc_data = {0x21, 0xD0, 0xAD, 0x5F, 0x2F, 0xD9, 0x74, 0x54, 0xA7, 0x46, 0xCC, 0x80, 0x56, 0x7F, 0x1B, 0x1C};
            c->prepare_tx(dec_data, 0, comm_mode::ciphered_no_crc);
            CHECK(enc_data == dec_data);
        }

        SECTION("Cmd3") {
            bin_data enc_data = {0x91, 0x3C, 0x6D, 0xED, 0x84, 0x22, 0x1C, 0x41, /* status */ 0x00};
            const bin_data dec_data = {0x9B, 0x36, 0xC5, 0xF8, 0xBF, 0x4A, 0x09, 0x84, /* status */ 0x00};
            c->confirm_rx(enc_data, comm_mode::ciphered_no_crc);
            CHECK(dec_data == enc_data);
        }
    }

    TEST_CASE("2K3DES cipher", "[cipher][2k3des]") {
        // Test using examples from https://hack.cert.pl/files/desfire-9f122c71e0057d4f747d2ee295b0f5f6eef8ac32.html
        // The examples from the website use ISO auth also for legacy auth, which means we need to use global IV
        auto c = always_default_cipher_provider{}.protocol_from_key(key<cipher_type::des>{});

        SECTION("Cmd1") {
            bin_data enc_data = {0xDE, 0x50, 0xF9, 0x23, 0x10, 0xCA, 0xF5, 0xA5, /* status */ 0xAF};
            const bin_data dec_data = {0x4C, 0x64, 0x7E, 0x56, 0x72, 0xE2, 0xA6, 0x51, /* status */ 0xAF};
            c->confirm_rx(enc_data, comm_mode::ciphered_no_crc);
            CHECK(enc_data == dec_data);
        }

        SECTION("Cmd2") {
            bin_data dec_data = {0xC9, 0x6C, 0xE3, 0x5E, 0x4D, 0x60, 0x87, 0xF2, 0x64, 0x7E, 0x56, 0x72, 0xE2, 0xA6, 0x51, 0x4C};
            const bin_data enc_data = {0xE0, 0x06, 0x16, 0x66, 0x87, 0x04, 0xD5, 0x54, 0x9C, 0x8D, 0x6A, 0x13, 0xA0, 0xF8, 0xFC, 0xED};
            c->prepare_tx(dec_data, 0, comm_mode::ciphered_no_crc);
            CHECK(enc_data == dec_data);
        }

        SECTION("Cmd3") {
            bin_data enc_data = {0x1D, 0x9D, 0x29, 0x54, 0x69, 0x7D, 0xE7, 0x60, /* status */ 0x00};
            const bin_data dec_data = {0x6C, 0xE3, 0x5E, 0x4D, 0x60, 0x87, 0xF2, 0xC9, /* status */ 0x00};
            c->confirm_rx(enc_data, comm_mode::ciphered_no_crc);
            CHECK(enc_data == dec_data);
        }
    }

    TEST_CASE("3K3DES cipher", "[cipher][3k3des]") {
        // Test using examples from https://hack.cert.pl/files/desfire-9f122c71e0057d4f747d2ee295b0f5f6eef8ac32.html
        auto c = desfire::esp32::default_cipher_provider{}.protocol_from_key(key<cipher_type::des3_3k>{});

        SECTION("Cmd1") {
            bin_data enc_data = {0xBC, 0x1C, 0x57, 0x0B, 0xC9, 0x48, 0x15, 0x61, 0x87, 0x13, 0x23, 0x64, 0xE4, 0xDC, 0xE1, 0x76, /* status */ 0xAF};
            const bin_data dec_data = {0x31, 0x6E, 0x6D, 0x76, 0xA4, 0x49, 0xF9, 0x25, 0xBA, 0x30, 0x4F, 0xB2, 0x65, 0x36, 0x56, 0xA2, /* status */ 0xAF};
            c->confirm_rx(enc_data, comm_mode::ciphered_no_crc);
            CHECK(enc_data == dec_data);
        }

        SECTION("Cmd2") {
            bin_data dec_data = {0x36, 0xC5, 0xF8, 0xBF, 0x4A, 0x09, 0xAC, 0x23, 0x9E, 0x8D, 0xA0, 0xC7, 0x32, 0x51, 0xD4, 0xAB, 0x6E, 0x6D, 0x76, 0xA4, 0x49, 0xF9, 0x25, 0xBA, 0x30, 0x4F, 0xB2, 0x65, 0x36, 0x56, 0xA2, 0x31};
            const bin_data enc_data = {0xDD, 0xDC, 0x9A, 0x77, 0x59, 0x7F, 0x03, 0xA4, 0x0C, 0x7F, 0xAA, 0x36, 0x2F, 0x45, 0xA8, 0xEA, 0xDB, 0xE4, 0x6A, 0x11, 0x5D, 0x98, 0x19, 0x8C, 0xBF, 0x36, 0xA6, 0xE5, 0x1B, 0x39, 0xD8, 0x7C};
            c->prepare_tx(dec_data, 0, comm_mode::ciphered_no_crc);
            CHECK(enc_data == dec_data);
        }

        SECTION("Cmd3") {
            bin_data enc_data = {0x72, 0x44, 0xD9, 0x35, 0xED, 0x9A, 0x13, 0x06, 0xCD, 0x8C, 0x84, 0x1A, 0x7C, 0x1D, 0xE3, 0x9A, /* status */ 0x00};
            const bin_data dec_data = {0xC5, 0xF8, 0xBF, 0x4A, 0x09, 0xAC, 0x23, 0x9E, 0x8D, 0xA0, 0xC7, 0x32, 0x51, 0xD4, 0xAB, 0x36, /* status */ 0x00};
            c->confirm_rx(enc_data, comm_mode::ciphered_no_crc);
            CHECK(enc_data == dec_data);
        }
    }

    TEST_CASE("AES cipher", "[cipher][aes]") {
        // Test using examples from https://hack.cert.pl/files/desfire-9f122c71e0057d4f747d2ee295b0f5f6eef8ac32.html
        auto c = desfire::esp32::default_cipher_provider{}.protocol_from_key(key<cipher_type::aes128>{});

        SECTION("Cmd1") {
            bin_data enc_data = {0xB9, 0x69, 0xFD, 0xFE, 0x56, 0xFD, 0x91, 0xFC, 0x9D, 0xE6, 0xF6, 0xF2, 0x13, 0xB8, 0xFD, 0x1E, /* status */ 0xAF};
            const bin_data dec_data = {0xC0, 0x5D, 0xDD, 0x71, 0x4F, 0xD7, 0x88, 0xA6, 0xB7, 0xB7, 0x54, 0xF3, 0xC4, 0xD0, 0x66, 0xE8, /* status */ 0xAF};
            c->confirm_rx(enc_data, comm_mode::ciphered_no_crc);
            CHECK(enc_data == dec_data);
        }

        SECTION("Cmd2") {
            bin_data dec_data = {0xF4, 0x4B, 0x26, 0xF5, 0x68, 0x6F, 0x3A, 0x39, 0x1C, 0xD3, 0x8E, 0xBD, 0x10, 0x77, 0x22, 0x81, 0x5D, 0xDD, 0x71, 0x4F, 0xD7, 0x88, 0xA6, 0xB7, 0xB7, 0x54, 0xF3, 0xC4, 0xD0, 0x66, 0xE8, 0xC0};
            const bin_data enc_data = {0x36, 0xAA, 0xD7, 0xDF, 0x6E, 0x43, 0x6B, 0xA0, 0x8D, 0x18, 0x61, 0x38, 0x30, 0xA7, 0x0D, 0x5A, 0xD4, 0x3E, 0x3D, 0x3F, 0x4A, 0x8D, 0x47, 0x54, 0x1E, 0xEE, 0x62, 0x3A, 0x93, 0x4E, 0x47, 0x74};
            c->prepare_tx(dec_data, 0, comm_mode::ciphered_no_crc);
            CHECK(enc_data == dec_data);
        }

        SECTION("Cmd3") {
            bin_data enc_data = {0x80, 0x0D, 0xB6, 0x80, 0xBC, 0x14, 0x6B, 0xD1, 0x21, 0xD6, 0x57, 0x8F, 0x2D, 0x2E, 0x20, 0x59, /* status */ 0x00};
            const bin_data dec_data = {0x4B, 0x26, 0xF5, 0x68, 0x6F, 0x3A, 0x39, 0x1C, 0xD3, 0x8E, 0xBD, 0x10, 0x77, 0x22, 0x81, 0xF4, /* status */ 0x00};
            c->confirm_rx(enc_data, comm_mode::ciphered_no_crc);
            CHECK(enc_data == dec_data);
        }
    }

    TEST_CASE("DES cipher direction", "[cipher][des]") {
        /**
         * @note This test checks that the direction of the protocol matches the odd implementation in Desfire, which
         * requires to de-cipher the data that we are sending. See note on @ref protocol_legacy.
         */
        const auto k = key<cipher_type::des>{0, {0xc8, 0x6d, 0xb4, 0x4f, 0x05, 0x52, 0xb6, 0x9b}};
        esp32::crypto_des c{};
        c.setup_with_key(k.as_range());
        bin_data dec_data = {0x00, 0x02, 0x04, 0x07, 0x08, 0x0a, 0x0c, 0x0e, 0x00, 0x02, 0x04, 0x07, 0x08, 0x0a, 0x0c, 0x0e, 0x2a, 0xec, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        const bin_data enc_data = {0xae, 0x99, 0x2b, 0xd7, 0x2b, 0x90, 0x32, 0x4f, 0x3e, 0x2c, 0xf2, 0xf3, 0x5e, 0x4f, 0xd7, 0x9a, 0x99, 0xbe, 0xa5, 0x61, 0xad, 0x04, 0x24, 0xbc};
        std::array<std::uint8_t, 8> iv{0, 0, 0, 0, 0, 0, 0, 0};
        c.do_crypto(dec_data.data_view(), mlab::make_range(iv), crypto_operation::encrypt);
        CHECK(enc_data == dec_data);
    }

    TEST_CASE("2K3DES cipher with version", "[cipher][2k3des]") {
        /// @note This key has a nonzero version (see k.body()[3] & 0x1 != 0)
        const auto k = key<cipher_type::des3_2k>{0, {0x00, 0x10, 0x20, 0x31, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xB0, 0xA0, 0x90, 0x80}};
        auto c = always_default_cipher_provider{}.protocol_from_key(k);
        bin_data enc_data = {0xB2, 0x95, 0x57, 0x99, 0x26, 0x15, 0x5A, 0xE3, /* status */ 0xAF};
        const bin_data dec_data = {0xBC, 0xD8, 0x29, 0x97, 0x47, 0x33, 0x2D, 0xAF, /* status */ 0xAF};
        c->confirm_rx(enc_data, comm_mode::ciphered_no_crc);
        CHECK(enc_data == dec_data);
    }

    TEST_CASE("3K3DES cipher with version", "[cipher][3k3des]") {
        /// @note This key has a nonzero version (see k.body()[3] & 0x1 != 0)
        const auto k = key<cipher_type::des3_3k>{0, {0x00, 0x10, 0x20, 0x31, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xB0, 0xA0, 0x90, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0x00}};
        auto c = desfire::esp32::default_cipher_provider{}.protocol_from_key(k);
        bin_data enc_data = {0xFA, 0x2F, 0xB9, 0xA1, 0x7B, 0x35, 0x9D, 0x03, 0x4D, 0xF3, 0xEB, 0x1C, 0x41, 0x79, 0x20, 0x7E, /* status */ 0xAF};
        const bin_data dec_data = {0xF4, 0xD6, 0x56, 0x42, 0xAE, 0xEB, 0x3D, 0x12, 0xFB, 0x8A, 0xC6, 0xFE, 0x46, 0xCE, 0x7A, 0x2F, /* status */ 0xAF};
        c->confirm_rx(enc_data, comm_mode::ciphered_no_crc);
        CHECK(enc_data == dec_data);
    }

    TEST_CASE("AES KDF", "[kdf][aes]") {
        desfire::esp32::default_cipher_provider cipher_provider{};
        bin_data div_data = {0x04, 0x78, 0x2E, 0x21, 0x80, 0x1D, 0x80, 0x30, 0x42, 0xF5, 0x4E, 0x58, 0x50, 0x20, 0x41, 0x62, 0x75};

        const desfire::key_body<16> k{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
        const desfire::key_body<16> exp_div_key{0xA8, 0xDD, 0x63, 0xA3, 0xB8, 0x9D, 0x54, 0xB3, 0x7C, 0xA8, 0x02, 0x47, 0x3F, 0xDA, 0x91, 0x75};

        const auto div_key = kdf_an10922(key<cipher_type::aes128>{0, k}, cipher_provider, div_data);

        CHECK(div_key.body() == exp_div_key);
    }

    TEST_CASE("3K3DES KDF", "[kdf][3k3des]") {
        desfire::esp32::default_cipher_provider cipher_provider{};
        bin_data div_data = {0x04, 0x78, 0x2E, 0x21, 0x80, 0x1D, 0x80, 0x30, 0x42, 0xF5, 0x4E, 0x58, 0x50};

        const desfire::key_body<24> k{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
        const desfire::key_body<24> exp_div_key{0x2E, 0x0D, 0xD0, 0x37, 0x74, 0xD3, 0xFA, 0x9B, 0x57, 0x05, 0xAB, 0x0B, 0xDA, 0x91, 0xCA, 0x0B, 0x55, 0xB8, 0xE0, 0x7F, 0xCD, 0xBF, 0x10, 0xEC};

        const auto div_key = kdf_an10922(key<cipher_type::des3_3k>{0, k}, cipher_provider, div_data);

        CHECK(div_key.body() == exp_div_key);
    }

    TEST_CASE("2K3DES KDF", "[kdf][2k3des]") {
        desfire::esp32::default_cipher_provider cipher_provider{};
        bin_data div_data = {0x04, 0x78, 0x2E, 0x21, 0x80, 0x1D, 0x80, 0x30, 0x42, 0xF5, 0x4E, 0x58, 0x50, 0x20, 0x41};

        const desfire::key_body<16> k{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
        const desfire::key_body<16> exp_div_key{0x16, 0xF9, 0x58, 0x7D, 0x9E, 0x89, 0x10, 0xC9, 0x6B, 0x96, 0x48, 0xD0, 0x06, 0x10, 0x7D, 0xD7};

        const auto div_key = kdf_an10922(key<cipher_type::des3_2k>{0, k}, cipher_provider, div_data);

        CHECK(div_key.body() == exp_div_key);
    }

    TEST_CASE("CRC32", "[crc]") {
        SECTION("Short payload") {
            const bin_data payload = {0xC4, 0x00, 0x00, 0x10, 0x20, 0x31, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xB0, 0xA0, 0x90, 0x80};
            const std::uint32_t expected_crc = 0x5001ffc5;
            const std::uint32_t computed_crc = compute_crc32(payload);
            CHECK(expected_crc == computed_crc);
        }
        SECTION("Long payload") {
            const bin_data payload = {0xC4, 0x00, 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xB0, 0xA0, 0x90, 0x80, 0x10};
            const std::uint32_t expected_crc = 0x6be6c6d2;
            const std::uint32_t computed_crc = compute_crc32(payload);
            CHECK(expected_crc == computed_crc);
        }
    }

    TEST_CASE("CRC16", "[crc]") {
        const bin_data payload = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
        const std::uint16_t expected_crc = 0x5530;
        const std::uint16_t computed_crc = compute_crc16(payload);
        CHECK(expected_crc == computed_crc);
    }

    template <class CryptoImpl, std::size_t BlockSize, std::size_t KeySize>
    fake_cmac_crypto<CryptoImpl, BlockSize, KeySize>::fake_cmac_crypto() : crypto_with_cmac{BlockSize, 0x00}, _impl{} {}

    template <class CryptoImpl, std::size_t BlockSize, std::size_t KeySize>
    desfire::crypto_with_cmac::mac_t fake_cmac_crypto<CryptoImpl, BlockSize, KeySize>::do_cmac(range<std::uint8_t const *> data, range<std::uint8_t *> iv) {
        FAIL("Attempt to compute a CMAC with a fake CMAC crypto. This is not supported.");
        return {};
    }

    template <class CryptoImpl, std::size_t BlockSize, std::size_t KeySize>
    desfire::cipher_type fake_cmac_crypto<CryptoImpl, BlockSize, KeySize>::cipher_type() const {
        return _impl.cipher_type();
    }

    template <class CryptoImpl, std::size_t BlockSize, std::size_t KeySize>
    void fake_cmac_crypto<CryptoImpl, BlockSize, KeySize>::init_session(range<std::uint8_t const *> random_data) {
        _impl.init_session(random_data);
    }

    template <class CryptoImpl, std::size_t BlockSize, std::size_t KeySize>
    void fake_cmac_crypto<CryptoImpl, BlockSize, KeySize>::setup_with_key(range<std::uint8_t const *> key) {
        _impl.setup_with_key(key);
    }

    template <class CryptoImpl, std::size_t BlockSize, std::size_t KeySize>
    void fake_cmac_crypto<CryptoImpl, BlockSize, KeySize>::setup_primitives_with_key(range<std::uint8_t const *> key) {
        FAIL("Attempt to setup a CMAC with a fake CMAC crypto. This is not supported.");
    }

    template <class CryptoImpl, std::size_t BlockSize, std::size_t KeySize>
    void fake_cmac_crypto<CryptoImpl, BlockSize, KeySize>::do_crypto(range<std::uint8_t *> data, range<std::uint8_t *> iv, desfire::crypto_operation op) {
        _impl.do_crypto(data, iv, op);
    }

    template <class CryptoImpl, std::size_t BlockSize, std::size_t KeySize>
    std::array<std::uint8_t, KeySize> fake_cmac_crypto<CryptoImpl, BlockSize, KeySize>::diversify_key_an10922(mlab::bin_data &diversify_input) {
        return _impl.diversify_key_an10922(diversify_input);
    }
}// namespace ut::desfire_ciphers