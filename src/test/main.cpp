#include <unity.h>
#include <driver/uart.h>
#include <pn532/hsu.hpp>
#include <pn532/nfc.hpp>
#include <driver/gpio.h>
#include <esp_log.h>
#include <pn532/desfire_pcd.hpp>
#include <desfire/tag.hpp>
#include <desfire/data.hpp>
#include <desfire/msg.hpp>
#include "utils.hpp"
#include <string>
#include <cstdio>
#include <numeric>

#define TEST_TAG "UT"
#define TX_PIN   (GPIO_NUM_17)
#define RX_PIN   (GPIO_NUM_16)
#define BUF_SIZE (1024)

namespace {
    std::unique_ptr<pn532::hsu> serial = nullptr;
    std::unique_ptr<pn532::nfc> tag_reader = nullptr;
    std::unique_ptr<pn532::desfire_pcd> pcd = nullptr;
    std::unique_ptr<desfire::tag> mifare = nullptr;


    template <class T, class ...Args>
    std::unique_ptr<T> make_unique(Args &&...args) {
        return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
    }

    bool is_ok(pn532::nfc::r<bool> const &r) {
        return r and *r;
    }

    mlab::bin_data const &heavy_load() {
        static mlab::bin_data load;
        if (load.empty()) {
            load.resize(0x100);
            std::iota(std::begin(load), std::end(load), 0x00);
        }
        return load;
    }

}

namespace ut {

    struct app_with_keys {
        desfire::app_id aid;
        desfire::any_key default_key;
        desfire::any_key secondary_key;

        template <desfire::cipher_type Cipher>
        static app_with_keys make(desfire::app_id aid_, desfire::key<Cipher> secondary_key_, desfire::key<Cipher> default_key_ = {})
        {
            return app_with_keys{.aid = aid_, .default_key = desfire::any_key(default_key_), .secondary_key = desfire::any_key(secondary_key_)};
        }

    };

    static const std::array<app_with_keys, 4> test_apps = {{
            app_with_keys::make<desfire::cipher_type::des>({0x0, 0x0, 0x1}, {0, {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe}, 0x10}),
            app_with_keys::make<desfire::cipher_type::des3_2k>({0x0, 0x0, 0x2}, {0, {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e}, 0x10}),
            app_with_keys::make<desfire::cipher_type::des3_3k>({0x0, 0x0, 0x3}, {0, {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e, 0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e}, 0x10}),
            app_with_keys::make<desfire::cipher_type::aes128>({0x0, 0x0, 0x4}, {0, {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf}, 0x10})
    }};

}

void setup_uart_pn532() {
    uart_config_t uart_config = {
            .baud_rate = 115200,
            .data_bits = UART_DATA_8_BITS,
            .parity    = UART_PARITY_DISABLE,
            .stop_bits = UART_STOP_BITS_1,
            .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
            .rx_flow_ctrl_thresh = 122,
            .use_ref_tick = true
    };
    uart_param_config(UART_NUM_1, &uart_config);
    uart_driver_install(UART_NUM_1, BUF_SIZE, BUF_SIZE, 0, nullptr, 0);
    uart_set_pin(UART_NUM_1, TX_PIN, RX_PIN, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);

    serial = make_unique<pn532::hsu>(UART_NUM_1);
    tag_reader = make_unique<pn532::nfc>(*serial);
    serial->wake();
    const auto r_sam = tag_reader->sam_configuration(pn532::sam_mode::normal, pn532::one_sec);
    TEST_ASSERT(r_sam);
}


void test_get_fw() {
    TEST_ASSERT_NOT_EQUAL(tag_reader, nullptr);

    const auto r_fw = tag_reader->get_firmware_version();
    TEST_ASSERT(r_fw);
    ESP_LOGI(TEST_TAG, "IC version %u, version: %u.%u", r_fw->ic, r_fw->version, r_fw->revision);
}

void test_diagnostics() {
    TEST_ASSERT_NOT_EQUAL(tag_reader, nullptr);

    TEST_ASSERT(is_ok(tag_reader->diagnose_rom()));
    TEST_ASSERT(is_ok(tag_reader->diagnose_ram()));
    TEST_ASSERT(is_ok(tag_reader->diagnose_comm_line()));
    TEST_ASSERT(
            is_ok(tag_reader->diagnose_self_antenna(pn532::low_current_thr::mA_25, pn532::high_current_thr::mA_150)));
}

void test_scan_mifare() {
    TEST_ASSERT_NOT_EQUAL(tag_reader, nullptr);
    ESP_LOGI(TEST_TAG, "Please bring card close now (searching for one passive 106 kbps target)...");
    const auto r_scan = tag_reader->initiator_list_passive_kbps106_typea();
    TEST_ASSERT(r_scan);
    ESP_LOGI(TEST_TAG, "Found %u targets (passive, 106 kbps, type A).", r_scan->size());
    if (r_scan) {
        for (pn532::target_kbps106_typea const &target : *r_scan) {
            ESP_LOGI(TEST_TAG, "Logical index %u; NFC ID:", target.logical_index);
            ESP_LOG_BUFFER_HEX_LEVEL(TEST_TAG, target.info.nfcid.data(), target.info.nfcid.size(), ESP_LOG_INFO);
        }
    }
}

void test_scan_all() {
    TEST_ASSERT_NOT_EQUAL(tag_reader, nullptr);
    ESP_LOGI(TEST_TAG, "Please bring card close now (searching for any target)...");
    const auto r_scan = tag_reader->initiator_auto_poll();
    TEST_ASSERT(r_scan);
    ESP_LOGI(TEST_TAG, "Found %u targets.", r_scan->size());
    if (r_scan) {
        for (std::size_t i = 0; i < r_scan->size(); ++i) {
            ESP_LOGI(TEST_TAG, "%u. %s", i + 1, pn532::to_string(r_scan->at(i).type()));
        }
    }
}

void test_pn532_cycle_rf() {
    TEST_ASSERT_NOT_EQUAL(tag_reader, nullptr);
    const auto r_status = tag_reader->get_general_status();
    TEST_ASSERT(r_status);
    for (auto const &target : r_status->targets) {
        TEST_ASSERT(tag_reader->initiator_deselect(target.logical_index));
    }
    TEST_ASSERT(tag_reader->rf_configuration_field(true, false));
}

void test_data_exchange() {
    TEST_ASSERT_NOT_EQUAL(tag_reader, nullptr);
    ESP_LOGI(TEST_TAG, "Please bring card close now (searching for one passive 106 kbps target)...");
    const auto r_scan = tag_reader->initiator_list_passive_kbps106_typea(1, 10 * pn532::one_sec);
    if (not r_scan or r_scan->empty()) {
        TEST_FAIL_MESSAGE("Could not find a suitable card for testing.");
        return;
    }
    ESP_LOGI(TEST_TAG, "Found one target:");
    auto const &nfcid = r_scan->front().info.nfcid;
    ESP_LOG_BUFFER_HEX_LEVEL(TEST_TAG, nfcid.data(), nfcid.size(), ESP_LOG_INFO);
    ESP_LOGI(TEST_TAG, "Exchanging data.");
    const auto idx = r_scan->front().logical_index;
    const auto r_exchange = tag_reader->initiator_data_exchange(idx, {0x5a, 0x00, 0x00, 0x00});
    if (not r_exchange) {
        TEST_FAIL_MESSAGE("Exchange failed.");
        return;
    }
    ESP_LOGI(TEST_TAG, "Exchange successful, received:");
    ESP_LOG_BUFFER_HEX_LEVEL(TEST_TAG, r_exchange->second.data(), r_exchange->second.size(), ESP_LOG_INFO);
    TEST_ASSERT_EQUAL(r_exchange->first.error, pn532::controller_error::none);
    TEST_ASSERT_EQUAL(r_exchange->second.size(), 1);
    TEST_ASSERT_EQUAL(r_exchange->second.front(), 0x0);
}

void test_cipher_des() {
    {
        // Test using examples from https://hack.cert.pl/files/desfire-9f122c71e0057d4f747d2ee295b0f5f6eef8ac32.html
        const auto k = desfire::key<desfire::cipher_type::des>{};
        desfire::cipher_des c{k.k};
        // The examples from the website use ISO auth also for legacy auth, which means we need to use global IV
        {
            desfire::iv_session session{c, desfire::cipher_iv::global};
            {
                desfire::bin_data enc_data = {0x5D, 0x99, 0x4C, 0xE0, 0x85, 0xF2, 0x40, 0x89, /* status */ 0xAF};
                const desfire::bin_data dec_data = {0x4F, 0xD1, 0xB7, 0x59, 0x42, 0xA8, 0xB8, 0xE1, /* status */ 0xAF};
                c.confirm_rx(enc_data, desfire::cipher_cfg_crypto_nocrc);
                TEST_ASSERT_EQUAL_HEX8_ARRAY(dec_data.data(), enc_data.data(), std::min(enc_data.size(), dec_data.size()));
                TEST_ASSERT_EQUAL(enc_data.size(), dec_data.size());
            }
            {
                desfire::bin_data dec_data = {0x84, 0x9B, 0x36, 0xC5, 0xF8, 0xBF, 0x4A, 0x09, 0xD1, 0xB7, 0x59, 0x42, 0xA8, 0xB8, 0xE1, 0x4F};
                const desfire::bin_data enc_data = {0x21, 0xD0, 0xAD, 0x5F, 0x2F, 0xD9, 0x74, 0x54, 0xA7, 0x46, 0xCC, 0x80, 0x56, 0x7F, 0x1B, 0x1C};
                c.prepare_tx(dec_data, 0, desfire::cipher_cfg_crypto_nocrc);
                TEST_ASSERT_EQUAL_HEX8_ARRAY(enc_data.data(), dec_data.data(), std::min(enc_data.size(), dec_data.size()));
                TEST_ASSERT_EQUAL(enc_data.size(), dec_data.size());
            }
            {
                desfire::bin_data enc_data = {0x91, 0x3C, 0x6D, 0xED, 0x84, 0x22, 0x1C, 0x41, /* status */ 0x00};
                const desfire::bin_data dec_data = {0x9B, 0x36, 0xC5, 0xF8, 0xBF, 0x4A, 0x09, 0x84, /* status */ 0x00};
                c.confirm_rx(enc_data, desfire::cipher_cfg_crypto_nocrc);
                TEST_ASSERT_EQUAL_HEX8_ARRAY(dec_data.data(), enc_data.data(), std::min(enc_data.size(), dec_data.size()));
                TEST_ASSERT_EQUAL(enc_data.size(), dec_data.size());
            }
        }
    }
    {
        /**
         * @note This test checks that the direction of the cipher matches the odd implementation in Desfire, which
         * requires to de-cipher the data that we are sending. See note on @ref desfire::cipher_legacy_scheme.
         */
        const auto k = desfire::key<desfire::cipher_type::des>{0, {0xc8, 0x6d, 0xb4, 0x4f, 0x05, 0x52, 0xb6, 0x9b}};
        desfire::cipher_des c{k.k};
        desfire::bin_data dec_data = {0x00, 0x02, 0x04, 0x07, 0x08, 0x0a, 0x0c, 0x0e, 0x00, 0x02, 0x04, 0x07, 0x08, 0x0a, 0x0c, 0x0e, 0x2a, 0xec, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        const desfire::bin_data enc_data = {0xae, 0x99, 0x2b, 0xd7, 0x2b, 0x90, 0x32, 0x4f, 0x3e, 0x2c, 0xf2, 0xf3, 0x5e, 0x4f, 0xd7, 0x9a, 0x99, 0xbe, 0xa5, 0x61, 0xad, 0x04, 0x24, 0xbc};
        std::array<std::uint8_t, 8> iv{0, 0, 0, 0, 0, 0, 0, 0};
        c.do_crypto(dec_data.view(), desfire::crypto_mode::encrypt, iv);
        TEST_ASSERT_EQUAL_HEX8_ARRAY(enc_data.data(), dec_data.data(), std::min(enc_data.size(), dec_data.size()));
    }
}

void test_cipher_2k3des() {
    // Test using examples from https://hack.cert.pl/files/desfire-9f122c71e0057d4f747d2ee295b0f5f6eef8ac32.html
    {
        const auto k = desfire::key<desfire::cipher_type::des3_2k>{};
        desfire::cipher_2k3des c{k.k};
        // The examples from the website use ISO auth also for legacy auth, which means we need to use global IV
        {
            desfire::iv_session session{c, desfire::cipher_iv::global};
            {
                desfire::bin_data enc_data = {0xDE, 0x50, 0xF9, 0x23, 0x10, 0xCA, 0xF5, 0xA5, /* status */ 0xAF};
                const desfire::bin_data dec_data = {0x4C, 0x64, 0x7E, 0x56, 0x72, 0xE2, 0xA6, 0x51, /* status */ 0xAF};
                c.confirm_rx(enc_data, desfire::cipher_cfg_crypto_nocrc);
                TEST_ASSERT_EQUAL_HEX8_ARRAY(dec_data.data(), enc_data.data(), std::min(enc_data.size(), dec_data.size()));
                TEST_ASSERT_EQUAL(enc_data.size(), dec_data.size());
            }
            {
                desfire::bin_data dec_data = {0xC9, 0x6C, 0xE3, 0x5E, 0x4D, 0x60, 0x87, 0xF2, 0x64, 0x7E, 0x56, 0x72, 0xE2, 0xA6, 0x51, 0x4C};
                const desfire::bin_data enc_data = {0xE0, 0x06, 0x16, 0x66, 0x87, 0x04, 0xD5, 0x54, 0x9C, 0x8D, 0x6A, 0x13, 0xA0, 0xF8, 0xFC, 0xED};
                c.prepare_tx(dec_data, 0, desfire::cipher_cfg_crypto_nocrc);
                TEST_ASSERT_EQUAL_HEX8_ARRAY(enc_data.data(), dec_data.data(), std::min(enc_data.size(), dec_data.size()));
                TEST_ASSERT_EQUAL(enc_data.size(), dec_data.size());
            }
            {
                desfire::bin_data enc_data = {0x1D, 0x9D, 0x29, 0x54, 0x69, 0x7D, 0xE7, 0x60, /* status */ 0x00};
                const desfire::bin_data dec_data = {0x6C, 0xE3, 0x5E, 0x4D, 0x60, 0x87, 0xF2, 0xC9, /* status */ 0x00};
                c.confirm_rx(enc_data, desfire::cipher_cfg_crypto_nocrc);
                TEST_ASSERT_EQUAL_HEX8_ARRAY(dec_data.data(), enc_data.data(), std::min(enc_data.size(), dec_data.size()));
                TEST_ASSERT_EQUAL(enc_data.size(), dec_data.size());
            }
        }
    }
    {
        /// @note This key has a nonzero version (see k.k[3] & 0x1 != 0)
        const auto k = desfire::key<desfire::cipher_type::des3_2k>{0, {0x00, 0x10, 0x20, 0x31, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xB0, 0xA0, 0x90, 0x80}};
        desfire::cipher_2k3des c{k.k};
        {
            desfire::bin_data enc_data = {0xB2, 0x95, 0x57, 0x99, 0x26, 0x15, 0x5A, 0xE3, /* status */ 0xAF};
            const desfire::bin_data dec_data = {0xBC, 0xD8, 0x29, 0x97, 0x47, 0x33, 0x2D, 0xAF, /* status */ 0xAF};
            c.confirm_rx(enc_data, desfire::cipher_cfg_crypto_nocrc);
            TEST_ASSERT_EQUAL_HEX8_ARRAY(dec_data.data(), enc_data.data(), std::min(enc_data.size(), dec_data.size()));
            TEST_ASSERT_EQUAL(enc_data.size(), dec_data.size());
        }
    }
}

void test_cipher_3k3des() {
    // Test using examples from https://hack.cert.pl/files/desfire-9f122c71e0057d4f747d2ee295b0f5f6eef8ac32.html
    {
        const auto k = desfire::key<desfire::cipher_type::des3_3k>{};
        desfire::cipher_3k3des c{k.k};
        {
            desfire::bin_data enc_data = {0xBC, 0x1C, 0x57, 0x0B, 0xC9, 0x48, 0x15, 0x61, 0x87, 0x13, 0x23, 0x64, 0xE4, 0xDC, 0xE1, 0x76, /* status */ 0xAF};
            const desfire::bin_data dec_data = {0x31, 0x6E, 0x6D, 0x76, 0xA4, 0x49, 0xF9, 0x25, 0xBA, 0x30, 0x4F, 0xB2, 0x65, 0x36, 0x56, 0xA2, /* status */ 0xAF};
            c.confirm_rx(enc_data, desfire::cipher_cfg_crypto_nocrc);
            TEST_ASSERT_EQUAL_HEX8_ARRAY(dec_data.data(), enc_data.data(), std::min(enc_data.size(), dec_data.size()));
            TEST_ASSERT_EQUAL(enc_data.size(), dec_data.size());
        }
        {
            desfire::bin_data dec_data = {0x36, 0xC5, 0xF8, 0xBF, 0x4A, 0x09, 0xAC, 0x23, 0x9E, 0x8D, 0xA0, 0xC7, 0x32, 0x51, 0xD4, 0xAB, 0x6E, 0x6D, 0x76, 0xA4, 0x49, 0xF9, 0x25, 0xBA, 0x30, 0x4F, 0xB2, 0x65, 0x36, 0x56, 0xA2, 0x31};
            const desfire::bin_data enc_data = {0xDD, 0xDC, 0x9A, 0x77, 0x59, 0x7F, 0x03, 0xA4, 0x0C, 0x7F, 0xAA, 0x36, 0x2F, 0x45, 0xA8, 0xEA, 0xDB, 0xE4, 0x6A, 0x11, 0x5D, 0x98, 0x19, 0x8C, 0xBF, 0x36, 0xA6, 0xE5, 0x1B, 0x39, 0xD8, 0x7C};
            c.prepare_tx(dec_data, 0, desfire::cipher_cfg_crypto_nocrc);
            TEST_ASSERT_EQUAL_HEX8_ARRAY(enc_data.data(), dec_data.data(), std::min(enc_data.size(), dec_data.size()));
            TEST_ASSERT_EQUAL(enc_data.size(), dec_data.size());
        }
        {
            desfire::bin_data enc_data = {0x72, 0x44, 0xD9, 0x35, 0xED, 0x9A, 0x13, 0x06, 0xCD, 0x8C, 0x84, 0x1A, 0x7C, 0x1D, 0xE3, 0x9A, /* status */ 0x00};
            const desfire::bin_data dec_data = {0xC5, 0xF8, 0xBF, 0x4A, 0x09, 0xAC, 0x23, 0x9E, 0x8D, 0xA0, 0xC7, 0x32, 0x51, 0xD4, 0xAB, 0x36, /* status */ 0x00};
            c.confirm_rx(enc_data, desfire::cipher_cfg_crypto_nocrc);
            TEST_ASSERT_EQUAL_HEX8_ARRAY(dec_data.data(), enc_data.data(), std::min(enc_data.size(), dec_data.size()));
            TEST_ASSERT_EQUAL(enc_data.size(), dec_data.size());
        }
    }
    {
        /// @note This key has a nonzero version (see k.k[3] & 0x1 != 0)
        const auto k = desfire::key<desfire::cipher_type::des3_3k>{0, {0x00, 0x10, 0x20, 0x31, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xB0, 0xA0, 0x90, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0x00}};
        desfire::cipher_3k3des c{k.k};
        {
            desfire::bin_data enc_data = {0xFA, 0x2F, 0xB9, 0xA1, 0x7B, 0x35, 0x9D, 0x03, 0x4D, 0xF3, 0xEB, 0x1C, 0x41, 0x79, 0x20, 0x7E, /* status */ 0xAF};
            const desfire::bin_data dec_data = {0xF4, 0xD6, 0x56, 0x42, 0xAE, 0xEB, 0x3D, 0x12, 0xFB, 0x8A, 0xC6, 0xFE, 0x46, 0xCE, 0x7A, 0x2F, /* status */ 0xAF};
            c.confirm_rx(enc_data, desfire::cipher_cfg_crypto_nocrc);
            TEST_ASSERT_EQUAL_HEX8_ARRAY(dec_data.data(), enc_data.data(), std::min(enc_data.size(), dec_data.size()));
            TEST_ASSERT_EQUAL(enc_data.size(), dec_data.size());
        }
    }
}

void test_cipher_aes() {
    // Test using examples from https://hack.cert.pl/files/desfire-9f122c71e0057d4f747d2ee295b0f5f6eef8ac32.html
    const auto k = desfire::key<desfire::cipher_type::aes128>{};
    desfire::cipher_aes c{k.k};
    {
        desfire::bin_data enc_data = {0xB9, 0x69, 0xFD, 0xFE, 0x56, 0xFD, 0x91, 0xFC, 0x9D, 0xE6, 0xF6, 0xF2, 0x13, 0xB8, 0xFD, 0x1E, /* status */ 0xAF};
        const desfire::bin_data dec_data = {0xC0, 0x5D, 0xDD, 0x71, 0x4F, 0xD7, 0x88, 0xA6, 0xB7, 0xB7, 0x54, 0xF3, 0xC4, 0xD0, 0x66, 0xE8, /* status */ 0xAF};
        c.confirm_rx(enc_data, desfire::cipher_cfg_crypto_nocrc);
        TEST_ASSERT_EQUAL_HEX8_ARRAY(dec_data.data(), enc_data.data(), std::min(enc_data.size(), dec_data.size()));
        TEST_ASSERT_EQUAL(enc_data.size(), dec_data.size());
    }
    {
        desfire::bin_data dec_data = {0xF4, 0x4B, 0x26, 0xF5, 0x68, 0x6F, 0x3A, 0x39, 0x1C, 0xD3, 0x8E, 0xBD, 0x10, 0x77, 0x22, 0x81, 0x5D, 0xDD, 0x71, 0x4F, 0xD7, 0x88, 0xA6, 0xB7, 0xB7, 0x54, 0xF3, 0xC4, 0xD0, 0x66, 0xE8, 0xC0};
        const desfire::bin_data enc_data = {0x36, 0xAA, 0xD7, 0xDF, 0x6E, 0x43, 0x6B, 0xA0, 0x8D, 0x18, 0x61, 0x38, 0x30, 0xA7, 0x0D, 0x5A, 0xD4, 0x3E, 0x3D, 0x3F, 0x4A, 0x8D, 0x47, 0x54, 0x1E, 0xEE, 0x62, 0x3A, 0x93, 0x4E, 0x47, 0x74};
        c.prepare_tx(dec_data, 0, desfire::cipher_cfg_crypto_nocrc);
        TEST_ASSERT_EQUAL_HEX8_ARRAY(enc_data.data(), dec_data.data(), std::min(enc_data.size(), dec_data.size()));
        TEST_ASSERT_EQUAL(enc_data.size(), dec_data.size());
    }
    {
        desfire::bin_data enc_data = {0x80, 0x0D, 0xB6, 0x80, 0xBC, 0x14, 0x6B, 0xD1, 0x21, 0xD6, 0x57, 0x8F, 0x2D, 0x2E, 0x20, 0x59, /* status */ 0x00};
        const desfire::bin_data dec_data = {0x4B, 0x26, 0xF5, 0x68, 0x6F, 0x3A, 0x39, 0x1C, 0xD3, 0x8E, 0xBD, 0x10, 0x77, 0x22, 0x81, 0xF4, /* status */ 0x00};
        c.confirm_rx(enc_data, desfire::cipher_cfg_crypto_nocrc);
        TEST_ASSERT_EQUAL_HEX8_ARRAY(dec_data.data(), enc_data.data(), std::min(enc_data.size(), dec_data.size()));
        TEST_ASSERT_EQUAL(enc_data.size(), dec_data.size());
    }
}

void test_change_key_aes() {
    ut::assert_comm_controller ctrl;
    desfire::tag tag{ctrl};

    ut::session session{tag, desfire::key<desfire::cipher_type::aes128>{
            0, {0xF4, 0x4B, 0x26, 0xF5, 0xC0, 0x5D, 0xDD, 0x71, 0x10, 0x77, 0x22, 0x81, 0xC4, 0xD0, 0x66, 0xE8}
    }, {0x00, 0xAE, 0x16}, 0};

    ctrl.append({0xC4, 0x00, 0xE9, 0xF8, 0x5E, 0x21, 0x94, 0x96, 0xC2, 0xB5, 0x8C, 0x10, 0x90, 0xDC, 0x39, 0x35, 0xFA, 0xE9, 0xE8, 0x40, 0xCF, 0x61, 0xB3, 0x83, 0xD9, 0x53, 0x19, 0x46, 0x25, 0x6B, 0x1F, 0x11, 0x0C, 0x10},
                {0x00, 0x00});

    tag.change_key(desfire::key<desfire::cipher_type::aes128>(0, {0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xB0, 0xA0, 0x90, 0x80}, 0x10));
}


void test_change_key_2k3des() {
    ut::assert_comm_controller ctrl;
    desfire::tag tag{ctrl};

    ut::session session{tag, desfire::key<desfire::cipher_type::des>{
            0, {0xc8, 0x6d, 0xb4, 0x4f, 0xd3, 0x20, 0xd9, 0x39}
    }, {0x00, 0x00, 0x02}, 0};

    ctrl.append({0xc4, 0x00, 0xb2, 0x99, 0xf1, 0x06, 0xa0, 0x73, 0x23, 0x44, 0x90, 0x7b, 0x03, 0x41, 0xe6, 0x46, 0x3d, 0x42, 0x41, 0x42, 0x33, 0xa2, 0x8a, 0x12, 0xb1, 0x94},
                {0x00});

    tag.change_key(desfire::key<desfire::cipher_type::des3_2k>{0, {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e}, 0x10});
}

void test_change_key_des() {
    ut::assert_comm_controller ctrl;
    desfire::tag tag{ctrl};

    ut::session session{tag, desfire::key<desfire::cipher_type::des>{
            0, {0xc8, 0x6d, 0xb4, 0x4f, 0x9e, 0x5d, 0x3a, 0xb9}
    }, {0x00, 0x00, 0x01}, 0};

    ctrl.append({0xc4, 0x00, 0x38, 0xb6, 0xba, 0xb4, 0xd0, 0x68, 0xd7, 0xa8, 0x04, 0x77, 0x9e, 0xb1, 0x35, 0x93, 0x82, 0xa8, 0x3d, 0xca, 0xd9, 0x01, 0xe4, 0x48, 0xac, 0x27},
                {0x00});

    tag.change_key(desfire::key<desfire::cipher_type::des>{0, {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe}, 0x10});
}

void test_create_write_file_rx_cmac() {
    ut::assert_comm_controller ctrl;
    desfire::tag tag{ctrl};

    ut::session session{tag, desfire::key<desfire::cipher_type::aes128>{
        0, {0x40, 0xE7, 0xD2, 0x71, 0x62, 0x6F, 0xFB, 0xD4, 0x9C, 0x53, 0x0E, 0x3D, 0x30, 0x4F, 0x5B, 0x17}
    }, {0x00, 0xae, 0x16}, 0};

    const desfire::bin_data data_to_write = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33};

    ctrl.append({0xCD, 0x05, 0x00, 0x11, 0x00, 0x50, 0x00, 0x00}, {0x00, 0xA7, 0x53, 0x16, 0xAD, 0x15, 0x96, 0xB9, 0x53});
    ctrl.append({0x6f}, {0x00, 0x05, 0x2D, 0x5F, 0xF6, 0x7F, 0xFE, 0xC9, 0xD2, 0xD3});
    ctrl.append({0xf5, 0x05}, {0x00, 0x00, 0x00, 0x11, 0x00, 0x50, 0x00, 0x00, 0x2A, 0xAC, 0x75, 0x17, 0x02, 0x4E, 0x09, 0xDC});
    ctrl.append({0x3D, 0x05, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33}, {0x00, 0x76, 0x5C, 0x9D, 0xAA, 0x50, 0xEC, 0xB6, 0x2F});

    TEST_ASSERT(tag.create_file(5, desfire::file_settings<desfire::file_type::standard>{
        desfire::generic_file_settings{desfire::comm_mode::plain, desfire::access_rights::from_mask(0x0011)},
        desfire::data_file_settings{.size = 80}
    }));

    TEST_ASSERT(tag.get_file_ids());

    TEST_ASSERT(tag.write_data(5, 0, data_to_write));
}

void test_get_key_version_rx_cmac() {
    ut::assert_comm_controller ctrl;
    desfire::tag tag{ctrl};

    {
        ut::session session{tag, desfire::key<desfire::cipher_type::aes128>{
                0, {0x90, 0xF7, 0xA2, 0x01, 0x91, 0x03, 0x68, 0x45, 0xEC, 0x63, 0xDE, 0xCD, 0x54, 0x4B, 0x99, 0x31}
        }, {0x00, 0xae, 0x16}, 0};

        ctrl.append({0x64, 0x00}, {0x00, 0x10, 0x8A, 0x8F, 0xA3, 0x6F, 0x55, 0xCD, 0x21, 0x0D});

        TEST_ASSERT(tag.get_key_version(0));
    }
    {
        ut::session session{tag, desfire::key<desfire::cipher_type::des3_3k>{
                0, {0xD0, 0x54, 0x2A, 0x86, 0x58, 0x14, 0xD2, 0x50, 0x4E, 0x9A, 0x18, 0x7C, 0xC0, 0x66, 0x68, 0xC0, 0x9C, 0x70, 0x56, 0x82, 0x58, 0x22, 0x7A, 0xFC}
        }, {0x00, 0xde, 0x24}, 0};

        ctrl.append({0x64, 0x00}, {0x00, 0x10, 0xAD, 0x4A, 0x52, 0xB1, 0xE3, 0x1C, 0xC7, 0x41});

        TEST_ASSERT(tag.get_key_version(0));
    }
}

void test_write_data_cmac_des() {
    ut::assert_comm_controller ctrl;
    desfire::tag tag{ctrl};

    ut::session session{tag, desfire::key<desfire::cipher_type::des>{
            0, {0xc8, 0x6d, 0xb4, 0x4f, 0x23, 0x43, 0xba, 0x56}
    }, {0x00, 0xde, 0x01}, 0};

    desfire::bin_data file_data;
    file_data.resize(32);
    std::iota(std::begin(file_data), std::end(file_data), 0x00);

    ctrl.append({0xf5, 0x00}, {0x00, 0x00, 0x01, 0x00, 0x00, 0x20, 0x00, 0x00});
    ctrl.append({0x3d, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x9a, 0xa8, 0x3a, 0x44}, {0x00});

    tag.write_data(0x00, 0, file_data);
}

void test_crc32() {
    {
        const mlab::bin_data payload = {0xC4, 0x00, 0x00, 0x10, 0x20, 0x31, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xB0, 0xA0, 0x90, 0x80};
        const std::uint32_t expected_crc = 0x5001ffc5;
        const std::uint32_t computed_crc = desfire::compute_crc32(payload);
        TEST_ASSERT_EQUAL(expected_crc, computed_crc);
    }
    {
        const mlab::bin_data payload = {0xC4, 0x00, 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xB0, 0xA0, 0x90, 0x80, 0x10};
        const std::uint32_t expected_crc = 0x6be6c6d2;
        const std::uint32_t computed_crc = desfire::compute_crc32(payload);
        TEST_ASSERT_EQUAL(expected_crc, computed_crc);
    }
}

void test_crc16() {
    const mlab::bin_data payload = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
    const std::uint16_t expected_crc = 0x5530;
    const std::uint16_t computed_crc = desfire::compute_crc16(payload);
    TEST_ASSERT_EQUAL(expected_crc, computed_crc);
}

void issue_header(std::string const &title) {
    ESP_LOGI(TEST_TAG, "--------------------------------------------------------------------------------");
    const std::size_t tail_length = std::max(68u, title.length()) - title.length();
    const std::string header = "---------- " + title + " " + std::string(tail_length, '-');
    ESP_LOGI(TEST_TAG, "%s", header.c_str());
    vTaskDelay(2000 / portTICK_PERIOD_MS);
}

void issue_format_warning() {
    ESP_LOGW(TEST_TAG, "The following test are destructive and will format the PICC!");
    ESP_LOGW(TEST_TAG, "Remove the tag from RF field if you care for your data.");
    for (unsigned i = 3; i > 0; --i) {
        ESP_LOGW(TEST_TAG, "%d...", i);
        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }
}

void test_auth_attempt(desfire::tag::r<> const &r) {
    TEST_ASSERT_NOT_EQUAL(tag_reader, nullptr);
    if (not r) {
        ESP_LOGW(TEST_TAG, "Authentication failed: %s", desfire::to_string(r.error()));
        if (not pcd->last_result()) {
            ESP_LOGW(TEST_TAG, "Last PCD error: %s", pn532::to_string(pcd->last_result().error()));
        } else {
            ESP_LOGW(TEST_TAG, "Last controller error: %s", pn532::to_string(pcd->last_result()->error));
        }
        TEST_FAIL();
    }
}

void setup_mifare() {
    TEST_ASSERT_NOT_EQUAL(tag_reader, nullptr);

    ESP_LOGI(TEST_TAG, "Please bring card close now (searching for one passive 106 kbps target)...");
    const auto r_scan = tag_reader->initiator_list_passive_kbps106_typea(1, 10 * pn532::one_sec);
    if (not r_scan or r_scan->empty()) {
        TEST_FAIL_MESSAGE("Could not find a suitable card for testing.");
        return;
    }
    ESP_LOGI(TEST_TAG, "Found one target:");
    auto const &nfcid = r_scan->front().info.nfcid;
    ESP_LOG_BUFFER_HEX_LEVEL(TEST_TAG, nfcid.data(), nfcid.size(), ESP_LOG_INFO);

    pcd = std::unique_ptr<pn532::desfire_pcd>(new pn532::desfire_pcd(*tag_reader, r_scan->front().logical_index));
    mifare = std::unique_ptr<desfire::tag>(new desfire::tag(*pcd));
}

void test_mifare_base() {
    TEST_ASSERT_NOT_EQUAL(pcd, nullptr);
    TEST_ASSERT_NOT_EQUAL(mifare, nullptr);

    issue_format_warning();

    TEST_ASSERT(mifare->select_application(desfire::root_app));
    test_auth_attempt(mifare->authenticate(desfire::key<desfire::cipher_type::des>{}));
    TEST_ASSERT(mifare->format_picc());

    const auto r_info = mifare->get_info();
    TEST_ASSERT(r_info);
    ESP_LOGI(TEST_TAG, "Card info:");
    ESP_LOGI(TEST_TAG, "    vendor id: %02x", r_info->hardware.vendor_id);
    ESP_LOGI(TEST_TAG, "   hw version: %d.%d", r_info->hardware.version_major, r_info->hardware.version_minor);
    ESP_LOGI(TEST_TAG, "   sw version: %d.%d", r_info->software.version_major, r_info->software.version_minor);
    ESP_LOGI(TEST_TAG, "  storage [B]: %s%u",
             (r_info->hardware.size.bytes_upper_bound() > r_info->hardware.size.bytes_lower_bound() ? "> " : ""),
             r_info->hardware.size.bytes_lower_bound());
    ESP_LOGI(TEST_TAG, "    serial no: %02x %02x %02x %02x %02x %02x %02x",
             r_info->serial_no[0], r_info->serial_no[1], r_info->serial_no[2], r_info->serial_no[3],
             r_info->serial_no[4], r_info->serial_no[5], r_info->serial_no[6]);
    ESP_LOGI(TEST_TAG, "     batch no: %02x %02x %02x %02x %02x",
             r_info->batch_no[0], r_info->batch_no[1], r_info->batch_no[2], r_info->batch_no[3], r_info->batch_no[4]);
    ESP_LOGI(TEST_TAG, "   production: %02x %02x -> year %02u, week %u", r_info->production_week,
             r_info->production_year, r_info->production_year, r_info->production_week);

    const auto r_mem = mifare->get_free_mem();
    TEST_ASSERT(r_mem);
    ESP_LOGI(TEST_TAG, " free mem [B]: %d", *r_mem);
}

void test_mifare_uid() {
    TEST_ASSERT_NOT_EQUAL(pcd, nullptr);
    TEST_ASSERT_NOT_EQUAL(mifare, nullptr);

    TEST_ASSERT(mifare->select_application(desfire::root_app));
    test_auth_attempt(mifare->authenticate(desfire::key<desfire::cipher_type::des>{}));

    const auto r_info = mifare->get_info();
    TEST_ASSERT(r_info);
    const auto uid = r_info->serial_no;

    const auto r_get_uid = mifare->get_card_uid();
    TEST_ASSERT(r_get_uid);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(uid.data(), r_get_uid->data(), uid.size());
}

void test_mifare_create_apps() {
    TEST_ASSERT_NOT_EQUAL(pcd, nullptr);
    TEST_ASSERT_NOT_EQUAL(mifare, nullptr);

    for (ut::app_with_keys const &app : ut::test_apps) {
        const auto ct = app.default_key.type();
        ESP_LOGI(TEST_TAG, "Creating app with cipher %s.", desfire::to_string(ct));
        TEST_ASSERT(mifare->select_application(desfire::root_app));
        TEST_ASSERT(mifare->authenticate(desfire::key<desfire::cipher_type::des>{}));
        TEST_ASSERT(mifare->create_application(app.aid, desfire::app_settings{ct}));
        TEST_ASSERT(mifare->select_application(app.aid));
        test_auth_attempt(mifare->authenticate(app.default_key));
    }

    TEST_ASSERT(mifare->select_application(desfire::root_app));
    const auto r_app_ids = mifare->get_application_ids();
    TEST_ASSERT(r_app_ids);
    if (r_app_ids) {
        std::array<bool, 4> got_all_ids = {false, false, false, false};
        TEST_ASSERT_GREATER_OR_EQUAL(r_app_ids->size(), 4);
        for (std::size_t i = 0; i < r_app_ids->size(); ++i) {
            desfire::app_id const &aid = r_app_ids->at(i);
            ESP_LOGI(TEST_TAG, "  %d. AID %02x %02x %02x", i + 1, aid[0], aid[1], aid[2]);
            if (aid[0] == aid[1] and aid[0] == 0 and 0 < aid[2] and aid[2] < 5) {
                TEST_ASSERT_EQUAL_HEX8_ARRAY(ut::test_apps[aid[2] - 1].aid.data(), aid.data(), aid.size());
                got_all_ids[aid[2] - 1] = true;
            }
        }
        TEST_ASSERT(got_all_ids[0]);
        TEST_ASSERT(got_all_ids[1]);
        TEST_ASSERT(got_all_ids[2]);
        TEST_ASSERT(got_all_ids[3]);
    }
}

void test_mifare_change_app_key() {
    TEST_ASSERT(pcd != nullptr and mifare != nullptr);

    for (ut::app_with_keys const &app : ut::test_apps) {
        ESP_LOGI(TEST_TAG, "Changing same key of app with cipher %s.", desfire::to_string(app.default_key.type()));
        TEST_ASSERT(mifare->select_application(app.aid));
        if (not mifare->authenticate(app.default_key)) {
            ESP_LOGW(TEST_TAG, "Default key not working, attempting secondary key and reset...");
            TEST_ASSERT(mifare->authenticate(app.secondary_key));
            TEST_ASSERT(mifare->change_key(app.default_key));
            ESP_LOGI(TEST_TAG, "Reset app key to default, continuing!");
            TEST_ASSERT(mifare->authenticate(app.default_key));
        }
        TEST_ASSERT(mifare->change_key(app.secondary_key));
        TEST_ASSERT(mifare->authenticate(app.secondary_key));
        const auto res_key_version = mifare->get_key_version(app.secondary_key.key_number());
        TEST_ASSERT(res_key_version);
        TEST_ASSERT_EQUAL(app.secondary_key.version(), *res_key_version);
        auto res_key_settings = mifare->get_app_settings();
        TEST_ASSERT(res_key_settings);
        res_key_settings->rights.dir_access_without_auth = true;
        TEST_ASSERT(mifare->change_app_settings(res_key_settings->rights));
        res_key_settings->rights.dir_access_without_auth = false;
        TEST_ASSERT(mifare->change_app_settings(res_key_settings->rights));
        TEST_ASSERT(mifare->change_key(app.default_key));
    }
}

struct file_test {
    desfire::comm_mode mode = desfire::comm_mode::plain;
    desfire::cipher_type cipher = desfire::cipher_type::none;
    desfire::file_type ftype = desfire::file_type::standard;

    const char *mode_description() const {
        switch (mode) {
            case desfire::comm_mode::plain:  return "plain";
            case desfire::comm_mode::cipher: return "cipher";
            case desfire::comm_mode::mac:    return "mac";
            default: return nullptr;
        }
    }

    const char *cipher_description() const {
        switch (cipher) {
            case desfire::cipher_type::des:     return "des";
            case desfire::cipher_type::des3_2k: return "des3_2k";
            case desfire::cipher_type::des3_3k: return "des3_3k";
            case desfire::cipher_type::aes128:  return "aes128";
            default: return nullptr;
        }
    }

    const char *ftype_description() const {
        switch (ftype) {
            case desfire::file_type::standard:      return "standard";
            case desfire::file_type::backup:        return "backup";
            case desfire::file_type::value:         return "value";
            case desfire::file_type::linear_record: return "linear_record";
            case desfire::file_type::cyclic_record: return "cyclic_record";
            default: return nullptr;
        }
    }

    const char *description() const {
        static std::string buffer;
        buffer.reserve(128);
        buffer = "test_file(desfire::comm_mode::";
        buffer.append(mode_description());
        buffer.append(", desfire::cipher_type::");
        buffer.append(cipher_description());
        buffer.append(", desfire::file_type::");
        buffer.append(ftype_description());
        buffer.append(")");
        return buffer.c_str();
    }

    static void perform_standard_data_file_test(ut::test_file const &file) {
        TEST_ASSERT(pcd != nullptr and mifare != nullptr);
        TEST_ASSERT(mifare->write_data(file.fid, 0, heavy_load()));
        const auto r_read = mifare->read_data(file.fid, 0, heavy_load().size());
        TEST_ASSERT(r_read);
        TEST_ASSERT_EQUAL(heavy_load().size(), r_read->size());
        TEST_ASSERT_EQUAL_HEX8_ARRAY(heavy_load().data(), r_read->data(), heavy_load().size());
    }

    static void perform_backup_data_file_test(ut::test_file const &file) {
        TEST_ASSERT(pcd != nullptr and mifare != nullptr);
        TEST_ASSERT(mifare->write_data(file.fid, 0, heavy_load()));
        const auto r_read_before_commit = mifare->read_data(file.fid, 0, heavy_load().size());
        TEST_ASSERT(r_read_before_commit);
        TEST_ASSERT_EACH_EQUAL_HEX8(0x00, r_read_before_commit->data(), r_read_before_commit->size());
        TEST_ASSERT(mifare->commit_transaction());
        const auto r_read = mifare->read_data(file.fid, 0, heavy_load().size());;
        TEST_ASSERT(r_read);
        TEST_ASSERT_EQUAL(heavy_load().size(), r_read->size());
        TEST_ASSERT_EQUAL_HEX8_ARRAY(heavy_load().data(), r_read->data(), heavy_load().size());
    }

    static void perform_value_file_test(ut::test_file const &file) {
        TEST_ASSERT(pcd != nullptr and mifare != nullptr);

        const auto test_get_value = [&](std::int32_t expected) {
            const auto res_read = mifare->get_value(file.fid);
            TEST_ASSERT(res_read);
            TEST_ASSERT_EQUAL(expected, *res_read);
        };

        test_get_value(0);
        TEST_ASSERT(mifare->credit(file.fid, 2));
        test_get_value(0);  // Did not commit yet
        TEST_ASSERT(mifare->commit_transaction());
        test_get_value(2);
        TEST_ASSERT(mifare->debit(file.fid, 5));
        TEST_ASSERT(mifare->commit_transaction());
        test_get_value(-3);
    }

    static void perform_record_file_test(ut::test_file const &file) {
        TEST_ASSERT(pcd != nullptr and mifare != nullptr);

        using record_t = std::array<std::uint8_t, 8>;

        static const mlab::bin_data nibble = {0x00, 0x01, 0x02, 0x03};

        const auto test_get_record_count = [&](std::uint32_t expected) {
            const auto res_settings = mifare->get_file_settings(file.fid);
            TEST_ASSERT(res_settings);
            TEST_ASSERT_EQUAL(expected, res_settings->record_settings().record_count);
        };

        test_get_record_count(0);
        TEST_ASSERT(mifare->write_record(file.fid, 4, nibble));
        TEST_ASSERT(mifare->commit_transaction());
        test_get_record_count(1);
        const auto res_records = mifare->read_records<record_t>(file.fid, 0);
        TEST_ASSERT(res_records);
        TEST_ASSERT_EQUAL(res_records->size(), 1);
        const record_t expected = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03};
        TEST_ASSERT_EQUAL_HEX8_ARRAY(expected.data(), res_records->front().data(), 8);
        TEST_ASSERT(mifare->clear_record_file(file.fid));
        TEST_ASSERT(mifare->commit_transaction());
    }

    void perform_test() const {
        TEST_ASSERT(pcd != nullptr and mifare != nullptr);
        static const desfire::any_key root_key{desfire::key<desfire::cipher_type::des>{}};

        // Make sure there is enough space to run. 1376B is a decent estimate for how much space is needed
        TEST_ASSERT(mifare->select_application(desfire::root_app));
        TEST_ASSERT(mifare->authenticate(root_key));
        const auto r_free_mem = mifare->get_free_mem();
        TEST_ASSERT(r_free_mem);
        if (*r_free_mem < 1376) {
            ESP_LOGI(TEST_TAG, "Formatting to recover space (only %d B free).", *r_free_mem);
            TEST_ASSERT(mifare->format_picc());
        }

        ut::test_app const &app = ut::get_test_app(cipher);
        ut::test_file const &file = ut::get_test_file(ftype, mode);
        app.ensure_created(*mifare, root_key);
        app.ensure_selected_and_primary(*mifare);
        TEST_ASSERT_EQUAL_HEX8_ARRAY(app.aid.data(), mifare->active_app().data(), 3);
        TEST_ASSERT_EQUAL(app.primary_key.key_number(), mifare->active_key_no());
        file.delete_preexisting(*mifare);
        TEST_ASSERT(mifare->create_file(file.fid, file.settings));

        switch (ftype) {
            case desfire::file_type::standard:
                perform_standard_data_file_test(file);
                break;
            case desfire::file_type::backup:
                perform_backup_data_file_test(file);
                break;
            case desfire::file_type::value:
                perform_value_file_test(file);
                break;
            case desfire::file_type::linear_record:  // [[fallthough]];
            case desfire::file_type::cyclic_record:
                perform_record_file_test(file);
                break;
            default:
                break;
        }
        TEST_ASSERT(mifare->delete_file(file.fid));
    }

    static file_test &instance() {
        static file_test _instance{};
        return _instance;
    }

    static void run() {
        instance().perform_test();
    }
};

void unity_main() {
    UNITY_BEGIN();
    esp_log_level_set("*", ESP_LOG_INFO);
    issue_header("MIFARE CIPHER TEST (no card)");
    RUN_TEST(test_crc16);
    RUN_TEST(test_crc32);
    RUN_TEST(test_cipher_des);
    RUN_TEST(test_cipher_2k3des);
    RUN_TEST(test_cipher_3k3des);
    RUN_TEST(test_cipher_aes);
    RUN_TEST(test_change_key_aes);
    RUN_TEST(test_change_key_des);
    RUN_TEST(test_change_key_2k3des);
    RUN_TEST(test_create_write_file_rx_cmac);
    RUN_TEST(test_get_key_version_rx_cmac);
    RUN_TEST(test_write_data_cmac_des);
    issue_header("HARDWARE SETUP (no card)");
    RUN_TEST(setup_uart_pn532);
    issue_header("PN532 TEST AND DIAGNOSTICS (no card)");
    RUN_TEST(test_get_fw);
    RUN_TEST(test_diagnostics);
    issue_header("PN532 SCAN TEST (optionally requires card)");
    RUN_TEST(test_scan_mifare);
    RUN_TEST(test_pn532_cycle_rf);
    RUN_TEST(test_scan_all);
    RUN_TEST(test_pn532_cycle_rf);
    issue_header("PN532 MIFARE COMM TEST (requires card)");
    RUN_TEST(test_data_exchange);
    RUN_TEST(test_pn532_cycle_rf);
    issue_header("MIFARE TEST (requires card)");
    RUN_TEST(setup_mifare);
    RUN_TEST(test_mifare_base);
    RUN_TEST(test_mifare_uid);
    RUN_TEST(test_mifare_create_apps);
    RUN_TEST(test_mifare_change_app_key);

    /**
     * Test file creation, deletion, and read/write cycle.
     *
     * @note Since Unity does not allow parms in RUN_TEST, let's store those into a structure and then use them to call
     * the actual test function. This will generate a separate test entry for each mode.
     */
    issue_format_warning();
    for (desfire::comm_mode mode : {desfire::comm_mode::plain, desfire::comm_mode::mac, desfire::comm_mode::cipher})
    {
        for (desfire::cipher_type cipher : {desfire::cipher_type::des, desfire::cipher_type::des3_2k,
                                            desfire::cipher_type::des3_3k, desfire::cipher_type::aes128})
        {
            for (desfire::file_type ftype : {desfire::file_type::standard, desfire::file_type::backup,
                                             desfire::file_type::value, desfire::file_type::linear_record,
                                             desfire::file_type::cyclic_record})
            {
                file_test::instance().mode = mode;
                file_test::instance().cipher = cipher;
                file_test::instance().ftype = ftype;
                UnityDefaultTestRun(&file_test::run, file_test::instance().description(), __LINE__);
            }
        }
    }

    /**
     * Teardown.
     */
    if (tag_reader != nullptr) {
        if (pcd != nullptr) {
            tag_reader->initiator_deselect(pcd->target_logical_index());
        }
        tag_reader->rf_configuration_field(true, false);
    }
    UNITY_END();
}

#ifdef KEYCARD_UNIT_TEST_MAIN

#ifdef __cplusplus
extern "C" {
#endif

void app_main() {
    unity_main();
}

#ifdef __cplusplus
}
#endif

#endif
