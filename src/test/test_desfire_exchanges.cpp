//
// Created by spak on 3/17/21.
//

#include "test_desfire_exchanges.hpp"
#include "test_desfire_ciphers.hpp"
#include <desfire/esp32/crypto_impl.hpp>
#include <desfire/tag.hpp>
#include <list>
#include <numeric>
#include <unity.h>

namespace ut::desfire_exchanges {
    namespace {
        using namespace ::desfire;

        struct assert_comm_pcd final : public pcd {
            std::list<std::pair<mlab::bin_data, mlab::bin_data>> txrx_fifo;

            std::pair<mlab::bin_data, bool> communicate(mlab::bin_data const &data) override;

            void append(std::initializer_list<std::uint8_t> tx, std::initializer_list<std::uint8_t> rx);
        };

        std::pair<mlab::bin_data, bool> assert_comm_pcd::communicate(const mlab::bin_data &data) {
            auto txrx_pair = std::move(txrx_fifo.front());
            txrx_fifo.pop_front();
            TEST_ASSERT_EQUAL_HEX8_ARRAY(txrx_pair.first.data(), data.data(), std::min(txrx_pair.first.size(), data.size()));
            TEST_ASSERT_EQUAL(txrx_pair.first.size(), data.size());
            return {std::move(txrx_pair.second), true};
        }

        void assert_comm_pcd::append(std::initializer_list<std::uint8_t> tx,
                                     std::initializer_list<std::uint8_t> rx) {
            txrx_fifo.emplace_back(tx, rx);
        }
    }// namespace

    struct session {
        ::desfire::tag &tag;

        template <cipher_type Cipher>
        inline session(::desfire::tag &tag_, key<Cipher> const &session_key, app_id app, std::uint8_t key_no);

        inline ~session();
    };

    template <cipher_type Cipher>
    session::session(::desfire::tag &tag_, key<Cipher> const &session_key, app_id app, std::uint8_t key_no) : tag{tag_} {
        tag.template ut_init_session(session_key, app, key_no);
    }

    session::~session() {
        tag.logout(false);
    }

    void test_change_key_aes() {
        assert_comm_pcd pcd;
        tag tag{pcd, std::make_unique<esp32::default_cipher_provider>()};

        session session{tag, key<cipher_type::aes128>{0, {0xF4, 0x4B, 0x26, 0xF5, 0xC0, 0x5D, 0xDD, 0x71, 0x10, 0x77, 0x22, 0x81, 0xC4, 0xD0, 0x66, 0xE8}}, {0x00, 0xAE, 0x16}, 0};

        pcd.append({0xC4, 0x00, 0xE9, 0xF8, 0x5E, 0x21, 0x94, 0x96, 0xC2, 0xB5, 0x8C, 0x10, 0x90, 0xDC, 0x39, 0x35, 0xFA, 0xE9, 0xE8, 0x40, 0xCF, 0x61, 0xB3, 0x83, 0xD9, 0x53, 0x19, 0x46, 0x25, 0x6B, 0x1F, 0x11, 0x0C, 0x10},
                   {0x00, 0x00});

        tag.change_key(key<cipher_type::aes128>(0, {0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xB0, 0xA0, 0x90, 0x80}, 0x10));
    }


    void test_change_key_2k3des() {
        assert_comm_pcd pcd;
        // The examples from the website use ISO auth also for legacy auth, which means we need to use global IV
        tag tag{pcd, std::make_unique<always_default_cipher_provider>()};

        session session{tag, key<cipher_type::des>{0, {0xc8, 0x6d, 0xb4, 0x4f, 0xd3, 0x20, 0xd9, 0x39}}, {0x00, 0x00, 0x02}, 0};

        pcd.append({0xc4, 0x00, 0xb2, 0x99, 0xf1, 0x06, 0xa0, 0x73, 0x23, 0x44, 0x90, 0x7b, 0x03, 0x41, 0xe6, 0x46, 0x3d, 0x42, 0x41, 0x42, 0x33, 0xa2, 0x8a, 0x12, 0xb1, 0x94},
                   {0x00});

        tag.change_key(key<cipher_type::des3_2k>{0, {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e}, 0x10});
    }

    void test_change_key_des() {
        assert_comm_pcd pcd;
        // The examples from the website use ISO auth also for legacy auth, which means we need to use global IV
        tag tag{pcd, std::make_unique<always_default_cipher_provider>()};

        session session{tag, key<cipher_type::des>{0, {0xc8, 0x6d, 0xb4, 0x4f, 0x9e, 0x5d, 0x3a, 0xb9}}, {0x00, 0x00, 0x01}, 0};

        pcd.append({0xc4, 0x00, 0x38, 0xb6, 0xba, 0xb4, 0xd0, 0x68, 0xd7, 0xa8, 0x04, 0x77, 0x9e, 0xb1, 0x35, 0x93, 0x82, 0xa8, 0x3d, 0xca, 0xd9, 0x01, 0xe4, 0x48, 0xac, 0x27},
                   {0x00});

        tag.change_key(key<cipher_type::des>{0, {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe}, 0x10});
    }

    void test_create_write_file_rx_cmac() {
        assert_comm_pcd pcd;
        tag tag{pcd, std::make_unique<esp32::default_cipher_provider>()};

        session session{tag, key<cipher_type::aes128>{0, {0x40, 0xE7, 0xD2, 0x71, 0x62, 0x6F, 0xFB, 0xD4, 0x9C, 0x53, 0x0E, 0x3D, 0x30, 0x4F, 0x5B, 0x17}}, {0x00, 0xae, 0x16}, 0};

        const bin_data data_to_write = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33};

        pcd.append({0xCD, 0x05, 0x00, 0x11, 0x00, 0x50, 0x00, 0x00}, {0x00, 0xA7, 0x53, 0x16, 0xAD, 0x15, 0x96, 0xB9, 0x53});
        pcd.append({0x6f}, {0x00, 0x05, 0x2D, 0x5F, 0xF6, 0x7F, 0xFE, 0xC9, 0xD2, 0xD3});
        pcd.append({0xf5, 0x05}, {0x00, 0x00, 0x00, 0x11, 0x00, 0x50, 0x00, 0x00, 0x2A, 0xAC, 0x75, 0x17, 0x02, 0x4E, 0x09, 0xDC});
        pcd.append({0x3D, 0x05, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33}, {0x00, 0x76, 0x5C, 0x9D, 0xAA, 0x50, 0xEC, 0xB6, 0x2F});

        TEST_ASSERT(tag.create_file(5, file_settings<file_type::standard>{
                                               generic_file_settings{file_security::none, access_rights::from_mask(0x0011)},
                                               data_file_settings{.size = 80}}))

        TEST_ASSERT(tag.get_file_ids())

        TEST_ASSERT(tag.write_data(5, 0, data_to_write))
    }

    void test_get_key_version_rx_cmac() {
        assert_comm_pcd pcd;
        tag tag{pcd, std::make_unique<esp32::default_cipher_provider>()};

        {
            session session{tag, key<cipher_type::aes128>{0, {0x90, 0xF7, 0xA2, 0x01, 0x91, 0x03, 0x68, 0x45, 0xEC, 0x63, 0xDE, 0xCD, 0x54, 0x4B, 0x99, 0x31}}, {0x00, 0xae, 0x16}, 0};

            pcd.append({0x64, 0x00}, {0x00, 0x10, 0x8A, 0x8F, 0xA3, 0x6F, 0x55, 0xCD, 0x21, 0x0D});

            TEST_ASSERT(tag.get_key_version(0))
        }
        {
            session session{tag, key<cipher_type::des3_3k>{0, {0xD0, 0x54, 0x2A, 0x86, 0x58, 0x14, 0xD2, 0x50, 0x4E, 0x9A, 0x18, 0x7C, 0xC0, 0x66, 0x68, 0xC0, 0x9C, 0x70, 0x56, 0x82, 0x58, 0x22, 0x7A, 0xFC}}, {0x00, 0xde, 0x24}, 0};

            pcd.append({0x64, 0x00}, {0x00, 0x10, 0xAD, 0x4A, 0x52, 0xB1, 0xE3, 0x1C, 0xC7, 0x41});

            TEST_ASSERT(tag.get_key_version(0))
        }
    }

    void test_write_data_cmac_des() {
        assert_comm_pcd pcd;
        tag tag{pcd, std::make_unique<esp32::default_cipher_provider>()};

        session session{tag, key<cipher_type::des>{0, {0xc8, 0x6d, 0xb4, 0x4f, 0x23, 0x43, 0xba, 0x56}}, {0x00, 0xde, 0x01}, 0};

        bin_data file_data;
        file_data.resize(32);
        std::iota(std::begin(file_data), std::end(file_data), 0x00);

        pcd.append({0xf5, 0x00}, {0x00, 0x00, 0x01, 0x00, 0x00, 0x20, 0x00, 0x00});
        pcd.append({0x3d, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x9a, 0xa8, 0x3a, 0x44}, {0x00});

        tag.write_data(0x00, 0, file_data);
    }

}// namespace ut::desfire_exchanges