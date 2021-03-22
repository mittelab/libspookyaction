//
// Created by spak on 3/16/21.
//

#include "test_desfire_ciphers.hpp"
#include <desfire/cipher_impl.hpp>
#include <desfire/data.hpp>
#include <unity.h>

namespace ut::desfire_ciphers {
    namespace {
        using namespace ::desfire;
    }
    void test_des() {
        {
            // Test using examples from https://hack.cert.pl/files/desfire-9f122c71e0057d4f747d2ee295b0f5f6eef8ac32.html
            const auto k = key<cipher_type::des>{};
            cipher_des c{k.k};
            // The examples from the website use ISO auth also for legacy auth, which means we need to use global IV
            {
                iv_session session{c, cipher_iv::global};
                {
                    bin_data enc_data = {0x5D, 0x99, 0x4C, 0xE0, 0x85, 0xF2, 0x40, 0x89, /* status */ 0xAF};
                    const bin_data dec_data = {0x4F, 0xD1, 0xB7, 0x59, 0x42, 0xA8, 0xB8, 0xE1, /* status */ 0xAF};
                    c.confirm_rx(enc_data, cipher_mode::ciphered_no_crc);
                    TEST_ASSERT_EQUAL_HEX8_ARRAY(dec_data.data(), enc_data.data(), std::min(enc_data.size(), dec_data.size()));
                    TEST_ASSERT_EQUAL(enc_data.size(), dec_data.size());
                }
                {
                    bin_data dec_data = {0x84, 0x9B, 0x36, 0xC5, 0xF8, 0xBF, 0x4A, 0x09, 0xD1, 0xB7, 0x59, 0x42, 0xA8, 0xB8, 0xE1, 0x4F};
                    const bin_data enc_data = {0x21, 0xD0, 0xAD, 0x5F, 0x2F, 0xD9, 0x74, 0x54, 0xA7, 0x46, 0xCC, 0x80, 0x56, 0x7F, 0x1B, 0x1C};
                    c.prepare_tx(dec_data, 0, cipher_mode::ciphered_no_crc);
                    TEST_ASSERT_EQUAL_HEX8_ARRAY(enc_data.data(), dec_data.data(), std::min(enc_data.size(), dec_data.size()));
                    TEST_ASSERT_EQUAL(enc_data.size(), dec_data.size());
                }
                {
                    bin_data enc_data = {0x91, 0x3C, 0x6D, 0xED, 0x84, 0x22, 0x1C, 0x41, /* status */ 0x00};
                    const bin_data dec_data = {0x9B, 0x36, 0xC5, 0xF8, 0xBF, 0x4A, 0x09, 0x84, /* status */ 0x00};
                    c.confirm_rx(enc_data, cipher_mode::ciphered_no_crc);
                    TEST_ASSERT_EQUAL_HEX8_ARRAY(dec_data.data(), enc_data.data(), std::min(enc_data.size(), dec_data.size()));
                    TEST_ASSERT_EQUAL(enc_data.size(), dec_data.size());
                }
            }
        }
        {
            /**
             * @note This test checks that the direction of the cipher matches the odd implementation in Desfire, which
             * requires to de-cipher the data that we are sending. See note on @ref cipher_scheme_legacy.
             */
            const auto k = key<cipher_type::des>{0, {0xc8, 0x6d, 0xb4, 0x4f, 0x05, 0x52, 0xb6, 0x9b}};
            cipher_des c{k.k};
            bin_data dec_data = {0x00, 0x02, 0x04, 0x07, 0x08, 0x0a, 0x0c, 0x0e, 0x00, 0x02, 0x04, 0x07, 0x08, 0x0a, 0x0c, 0x0e, 0x2a, 0xec, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
            const bin_data enc_data = {0xae, 0x99, 0x2b, 0xd7, 0x2b, 0x90, 0x32, 0x4f, 0x3e, 0x2c, 0xf2, 0xf3, 0x5e, 0x4f, 0xd7, 0x9a, 0x99, 0xbe, 0xa5, 0x61, 0xad, 0x04, 0x24, 0xbc};
            std::array<std::uint8_t, 8> iv{0, 0, 0, 0, 0, 0, 0, 0};
            c.do_crypto(dec_data.view(), crypto_direction::encrypt, iv);
            TEST_ASSERT_EQUAL_HEX8_ARRAY(enc_data.data(), dec_data.data(), std::min(enc_data.size(), dec_data.size()));
        }
    }

    void test_2k3des() {
        // Test using examples from https://hack.cert.pl/files/desfire-9f122c71e0057d4f747d2ee295b0f5f6eef8ac32.html
        {
            const auto k = key<cipher_type::des3_2k>{};
            cipher_2k3des c{k.k};
            // The examples from the website use ISO auth also for legacy auth, which means we need to use global IV
            {
                iv_session session{c, cipher_iv::global};
                {
                    bin_data enc_data = {0xDE, 0x50, 0xF9, 0x23, 0x10, 0xCA, 0xF5, 0xA5, /* status */ 0xAF};
                    const bin_data dec_data = {0x4C, 0x64, 0x7E, 0x56, 0x72, 0xE2, 0xA6, 0x51, /* status */ 0xAF};
                    c.confirm_rx(enc_data, cipher_mode::ciphered_no_crc);
                    TEST_ASSERT_EQUAL_HEX8_ARRAY(dec_data.data(), enc_data.data(), std::min(enc_data.size(), dec_data.size()));
                    TEST_ASSERT_EQUAL(enc_data.size(), dec_data.size());
                }
                {
                    bin_data dec_data = {0xC9, 0x6C, 0xE3, 0x5E, 0x4D, 0x60, 0x87, 0xF2, 0x64, 0x7E, 0x56, 0x72, 0xE2, 0xA6, 0x51, 0x4C};
                    const bin_data enc_data = {0xE0, 0x06, 0x16, 0x66, 0x87, 0x04, 0xD5, 0x54, 0x9C, 0x8D, 0x6A, 0x13, 0xA0, 0xF8, 0xFC, 0xED};
                    c.prepare_tx(dec_data, 0, cipher_mode::ciphered_no_crc);
                    TEST_ASSERT_EQUAL_HEX8_ARRAY(enc_data.data(), dec_data.data(), std::min(enc_data.size(), dec_data.size()));
                    TEST_ASSERT_EQUAL(enc_data.size(), dec_data.size());
                }
                {
                    bin_data enc_data = {0x1D, 0x9D, 0x29, 0x54, 0x69, 0x7D, 0xE7, 0x60, /* status */ 0x00};
                    const bin_data dec_data = {0x6C, 0xE3, 0x5E, 0x4D, 0x60, 0x87, 0xF2, 0xC9, /* status */ 0x00};
                    c.confirm_rx(enc_data, cipher_mode::ciphered_no_crc);
                    TEST_ASSERT_EQUAL_HEX8_ARRAY(dec_data.data(), enc_data.data(), std::min(enc_data.size(), dec_data.size()));
                    TEST_ASSERT_EQUAL(enc_data.size(), dec_data.size());
                }
            }
        }
        {
            /// @note This key has a nonzero version (see k.k[3] & 0x1 != 0)
            const auto k = key<cipher_type::des3_2k>{0, {0x00, 0x10, 0x20, 0x31, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xB0, 0xA0, 0x90, 0x80}};
            cipher_2k3des c{k.k};
            {
                bin_data enc_data = {0xB2, 0x95, 0x57, 0x99, 0x26, 0x15, 0x5A, 0xE3, /* status */ 0xAF};
                const bin_data dec_data = {0xBC, 0xD8, 0x29, 0x97, 0x47, 0x33, 0x2D, 0xAF, /* status */ 0xAF};
                c.confirm_rx(enc_data, cipher_mode::ciphered_no_crc);
                TEST_ASSERT_EQUAL_HEX8_ARRAY(dec_data.data(), enc_data.data(), std::min(enc_data.size(), dec_data.size()));
                TEST_ASSERT_EQUAL(enc_data.size(), dec_data.size());
            }
        }
    }

    void test_3k3des() {
        // Test using examples from https://hack.cert.pl/files/desfire-9f122c71e0057d4f747d2ee295b0f5f6eef8ac32.html
        {
            const auto k = key<cipher_type::des3_3k>{};
            cipher_3k3des c{k.k};
            {
                bin_data enc_data = {0xBC, 0x1C, 0x57, 0x0B, 0xC9, 0x48, 0x15, 0x61, 0x87, 0x13, 0x23, 0x64, 0xE4, 0xDC, 0xE1, 0x76, /* status */ 0xAF};
                const bin_data dec_data = {0x31, 0x6E, 0x6D, 0x76, 0xA4, 0x49, 0xF9, 0x25, 0xBA, 0x30, 0x4F, 0xB2, 0x65, 0x36, 0x56, 0xA2, /* status */ 0xAF};
                c.confirm_rx(enc_data, cipher_mode::ciphered_no_crc);
                TEST_ASSERT_EQUAL_HEX8_ARRAY(dec_data.data(), enc_data.data(), std::min(enc_data.size(), dec_data.size()));
                TEST_ASSERT_EQUAL(enc_data.size(), dec_data.size());
            }
            {
                bin_data dec_data = {0x36, 0xC5, 0xF8, 0xBF, 0x4A, 0x09, 0xAC, 0x23, 0x9E, 0x8D, 0xA0, 0xC7, 0x32, 0x51, 0xD4, 0xAB, 0x6E, 0x6D, 0x76, 0xA4, 0x49, 0xF9, 0x25, 0xBA, 0x30, 0x4F, 0xB2, 0x65, 0x36, 0x56, 0xA2, 0x31};
                const bin_data enc_data = {0xDD, 0xDC, 0x9A, 0x77, 0x59, 0x7F, 0x03, 0xA4, 0x0C, 0x7F, 0xAA, 0x36, 0x2F, 0x45, 0xA8, 0xEA, 0xDB, 0xE4, 0x6A, 0x11, 0x5D, 0x98, 0x19, 0x8C, 0xBF, 0x36, 0xA6, 0xE5, 0x1B, 0x39, 0xD8, 0x7C};
                c.prepare_tx(dec_data, 0, cipher_mode::ciphered_no_crc);
                TEST_ASSERT_EQUAL_HEX8_ARRAY(enc_data.data(), dec_data.data(), std::min(enc_data.size(), dec_data.size()));
                TEST_ASSERT_EQUAL(enc_data.size(), dec_data.size());
            }
            {
                bin_data enc_data = {0x72, 0x44, 0xD9, 0x35, 0xED, 0x9A, 0x13, 0x06, 0xCD, 0x8C, 0x84, 0x1A, 0x7C, 0x1D, 0xE3, 0x9A, /* status */ 0x00};
                const bin_data dec_data = {0xC5, 0xF8, 0xBF, 0x4A, 0x09, 0xAC, 0x23, 0x9E, 0x8D, 0xA0, 0xC7, 0x32, 0x51, 0xD4, 0xAB, 0x36, /* status */ 0x00};
                c.confirm_rx(enc_data, cipher_mode::ciphered_no_crc);
                TEST_ASSERT_EQUAL_HEX8_ARRAY(dec_data.data(), enc_data.data(), std::min(enc_data.size(), dec_data.size()));
                TEST_ASSERT_EQUAL(enc_data.size(), dec_data.size());
            }
        }
        {
            /// @note This key has a nonzero version (see k.k[3] & 0x1 != 0)
            const auto k = key<cipher_type::des3_3k>{0, {0x00, 0x10, 0x20, 0x31, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xB0, 0xA0, 0x90, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0x00}};
            cipher_3k3des c{k.k};
            {
                bin_data enc_data = {0xFA, 0x2F, 0xB9, 0xA1, 0x7B, 0x35, 0x9D, 0x03, 0x4D, 0xF3, 0xEB, 0x1C, 0x41, 0x79, 0x20, 0x7E, /* status */ 0xAF};
                const bin_data dec_data = {0xF4, 0xD6, 0x56, 0x42, 0xAE, 0xEB, 0x3D, 0x12, 0xFB, 0x8A, 0xC6, 0xFE, 0x46, 0xCE, 0x7A, 0x2F, /* status */ 0xAF};
                c.confirm_rx(enc_data, cipher_mode::ciphered_no_crc);
                TEST_ASSERT_EQUAL_HEX8_ARRAY(dec_data.data(), enc_data.data(), std::min(enc_data.size(), dec_data.size()));
                TEST_ASSERT_EQUAL(enc_data.size(), dec_data.size());
            }
        }
    }

    void test_aes() {
        // Test using examples from https://hack.cert.pl/files/desfire-9f122c71e0057d4f747d2ee295b0f5f6eef8ac32.html
        const auto k = key<cipher_type::aes128>{};
        cipher_aes c{k.k};
        {
            bin_data enc_data = {0xB9, 0x69, 0xFD, 0xFE, 0x56, 0xFD, 0x91, 0xFC, 0x9D, 0xE6, 0xF6, 0xF2, 0x13, 0xB8, 0xFD, 0x1E, /* status */ 0xAF};
            const bin_data dec_data = {0xC0, 0x5D, 0xDD, 0x71, 0x4F, 0xD7, 0x88, 0xA6, 0xB7, 0xB7, 0x54, 0xF3, 0xC4, 0xD0, 0x66, 0xE8, /* status */ 0xAF};
            c.confirm_rx(enc_data, cipher_mode::ciphered_no_crc);
            TEST_ASSERT_EQUAL_HEX8_ARRAY(dec_data.data(), enc_data.data(), std::min(enc_data.size(), dec_data.size()));
            TEST_ASSERT_EQUAL(enc_data.size(), dec_data.size());
        }
        {
            bin_data dec_data = {0xF4, 0x4B, 0x26, 0xF5, 0x68, 0x6F, 0x3A, 0x39, 0x1C, 0xD3, 0x8E, 0xBD, 0x10, 0x77, 0x22, 0x81, 0x5D, 0xDD, 0x71, 0x4F, 0xD7, 0x88, 0xA6, 0xB7, 0xB7, 0x54, 0xF3, 0xC4, 0xD0, 0x66, 0xE8, 0xC0};
            const bin_data enc_data = {0x36, 0xAA, 0xD7, 0xDF, 0x6E, 0x43, 0x6B, 0xA0, 0x8D, 0x18, 0x61, 0x38, 0x30, 0xA7, 0x0D, 0x5A, 0xD4, 0x3E, 0x3D, 0x3F, 0x4A, 0x8D, 0x47, 0x54, 0x1E, 0xEE, 0x62, 0x3A, 0x93, 0x4E, 0x47, 0x74};
            c.prepare_tx(dec_data, 0, cipher_mode::ciphered_no_crc);
            TEST_ASSERT_EQUAL_HEX8_ARRAY(enc_data.data(), dec_data.data(), std::min(enc_data.size(), dec_data.size()));
            TEST_ASSERT_EQUAL(enc_data.size(), dec_data.size());
        }
        {
            bin_data enc_data = {0x80, 0x0D, 0xB6, 0x80, 0xBC, 0x14, 0x6B, 0xD1, 0x21, 0xD6, 0x57, 0x8F, 0x2D, 0x2E, 0x20, 0x59, /* status */ 0x00};
            const bin_data dec_data = {0x4B, 0x26, 0xF5, 0x68, 0x6F, 0x3A, 0x39, 0x1C, 0xD3, 0x8E, 0xBD, 0x10, 0x77, 0x22, 0x81, 0xF4, /* status */ 0x00};
            c.confirm_rx(enc_data, cipher_mode::ciphered_no_crc);
            TEST_ASSERT_EQUAL_HEX8_ARRAY(dec_data.data(), enc_data.data(), std::min(enc_data.size(), dec_data.size()));
            TEST_ASSERT_EQUAL(enc_data.size(), dec_data.size());
        }
    }

    void test_crc32() {
        {
            const bin_data payload = {0xC4, 0x00, 0x00, 0x10, 0x20, 0x31, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xB0, 0xA0, 0x90, 0x80};
            const std::uint32_t expected_crc = 0x5001ffc5;
            const std::uint32_t computed_crc = compute_crc32(payload);
            TEST_ASSERT_EQUAL(expected_crc, computed_crc);
        }
        {
            const bin_data payload = {0xC4, 0x00, 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xB0, 0xA0, 0x90, 0x80, 0x10};
            const std::uint32_t expected_crc = 0x6be6c6d2;
            const std::uint32_t computed_crc = compute_crc32(payload);
            TEST_ASSERT_EQUAL(expected_crc, computed_crc);
        }
    }

    void test_crc16() {
        const bin_data payload = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
        const std::uint16_t expected_crc = 0x5530;
        const std::uint16_t computed_crc = compute_crc16(payload);
        TEST_ASSERT_EQUAL(expected_crc, computed_crc);
    }
}// namespace ut::desfire