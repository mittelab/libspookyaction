#ifdef TEST_MAIN

#include <unity.h>
#include <driver/uart.h>
#include <pn532/hsu.hpp>
#include <pn532/nfc.hpp>
#include <esp_log.h>
#include <pn532/desfire_pcd.hpp>
#include <desfire/tag.hpp>
#include <desfire/data.hpp>
#include <desfire/msg.hpp>
#include <string>

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
    TEST_ASSERT(bool(r_sam));
}


void test_get_fw() {
    TEST_ASSERT(tag_reader != nullptr);

    const auto r_fw = tag_reader->get_firmware_version();
    TEST_ASSERT(bool(r_fw));
    ESP_LOGI(TEST_TAG, "IC version %u, version: %u.%u", r_fw->ic, r_fw->version, r_fw->revision);
}

void test_diagnostics() {
    TEST_ASSERT(tag_reader != nullptr);

    TEST_ASSERT(is_ok(tag_reader->diagnose_rom()));
    TEST_ASSERT(is_ok(tag_reader->diagnose_ram()));
    TEST_ASSERT(is_ok(tag_reader->diagnose_comm_line()));
    TEST_ASSERT(
            is_ok(tag_reader->diagnose_self_antenna(pn532::low_current_thr::mA_25, pn532::high_current_thr::mA_150)));
}

void test_scan_mifare() {
    TEST_ASSERT(tag_reader != nullptr);
    const auto r_scan = tag_reader->initiator_list_passive_kbps106_typea();
    TEST_ASSERT(bool(r_scan));
    ESP_LOGI(TEST_TAG, "Found %u targets (passive, 106 kbps, type A).", r_scan->size());
    if (r_scan) {
        for (pn532::target_kbps106_typea const &target : *r_scan) {
            ESP_LOGI(TEST_TAG, "Logical index %u; NFC ID:", target.logical_index);
            ESP_LOG_BUFFER_HEX_LEVEL(TEST_TAG, target.info.nfcid.data(), target.info.nfcid.size(), ESP_LOG_INFO);
        }
    }
}

void test_scan_all() {
    TEST_ASSERT(tag_reader != nullptr);
    const auto r_scan = tag_reader->initiator_auto_poll();
    TEST_ASSERT(bool(r_scan));
    ESP_LOGI(TEST_TAG, "Found %u targets.", r_scan->size());
    if (r_scan) {
        for (std::size_t i = 0; i < r_scan->size(); ++i) {
            ESP_LOGI(TEST_TAG, "%u. %s", i + 1, pn532::to_string(r_scan->at(i).type()));
        }
    }
}

void test_data_exchange() {
    TEST_ASSERT(tag_reader != nullptr);
    ESP_LOGI(TEST_TAG, "Searching for one passive 106 kbps target. Please bring card close.");
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
    TEST_ASSERT(r_exchange->first.error == pn532::controller_error::none);
    TEST_ASSERT(r_exchange->second.size() == 1 and r_exchange->second.front() == 0x0);
}

void test_cipher_des() {
    // Test using examples from https://hack.cert.pl/files/desfire-9f122c71e0057d4f747d2ee295b0f5f6eef8ac32.html
    const auto k = desfire::key<desfire::cipher_type::des>{0, {0, 0, 0, 0, 0, 0, 0, 0}};
    desfire::cipher_des c{k.k};
    // The examples from the website use ISO auth also for legacy auth, which means we need to use global IV
    {
        desfire::iv_session session{c, desfire::cipher_iv::global};
        {
            desfire::bin_data enc_data = {0x5D, 0x99, 0x4C, 0xE0, 0x85, 0xF2, 0x40, 0x89, /* status */ 0xAF};
            const desfire::bin_data dec_data = {0x4F, 0xD1, 0xB7, 0x59, 0x42, 0xA8, 0xB8, 0xE1, /* status */ 0xAF};
            c.confirm_rx(enc_data, desfire::cipher_cfg_crypto_nocrc);
            TEST_ASSERT(enc_data == dec_data);
        }
        {
            desfire::bin_data dec_data = {0x84, 0x9B, 0x36, 0xC5, 0xF8, 0xBF, 0x4A, 0x09, 0xD1, 0xB7, 0x59, 0x42, 0xA8, 0xB8, 0xE1, 0x4F};
            const desfire::bin_data enc_data = {0x21, 0xD0, 0xAD, 0x5F, 0x2F, 0xD9, 0x74, 0x54, 0xA7, 0x46, 0xCC, 0x80, 0x56, 0x7F, 0x1B, 0x1C};
            c.prepare_tx(dec_data, 0, desfire::cipher_cfg_crypto_nocrc);
            TEST_ASSERT(enc_data == dec_data);
        }
        {
            desfire::bin_data enc_data = {0x91, 0x3C, 0x6D, 0xED, 0x84, 0x22, 0x1C, 0x41, /* status */ 0x00};
            const desfire::bin_data dec_data = {0x9B, 0x36, 0xC5, 0xF8, 0xBF, 0x4A, 0x09, 0x84, /* status */ 0x00};
            c.confirm_rx(enc_data, desfire::cipher_cfg_crypto_nocrc);
            TEST_ASSERT(enc_data == dec_data);
        }
    }
}

void test_cipher_2k3des() {
    // Test using examples from https://hack.cert.pl/files/desfire-9f122c71e0057d4f747d2ee295b0f5f6eef8ac32.html
    const auto k = desfire::key<desfire::cipher_type::des3_2k>{0, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
    desfire::cipher_2k3des c{k.k};
    // The examples from the website use ISO auth also for legacy auth, which means we need to use global IV
    {
        desfire::iv_session session{c, desfire::cipher_iv::global};
        {
            desfire::bin_data enc_data = {0xDE, 0x50, 0xF9, 0x23, 0x10, 0xCA, 0xF5, 0xA5, /* status */ 0xAF};
            const desfire::bin_data dec_data = {0x4C, 0x64, 0x7E, 0x56, 0x72, 0xE2, 0xA6, 0x51, /* status */ 0xAF};
            c.confirm_rx(enc_data, desfire::cipher_cfg_crypto_nocrc);
            TEST_ASSERT(enc_data == dec_data);
        }
        {
            desfire::bin_data dec_data = {0xC9, 0x6C, 0xE3, 0x5E, 0x4D, 0x60, 0x87, 0xF2, 0x64, 0x7E, 0x56, 0x72, 0xE2, 0xA6, 0x51, 0x4C};
            const desfire::bin_data enc_data = {0xE0, 0x06, 0x16, 0x66, 0x87, 0x04, 0xD5, 0x54, 0x9C, 0x8D, 0x6A, 0x13, 0xA0, 0xF8, 0xFC, 0xED};
            c.prepare_tx(dec_data, 0, desfire::cipher_cfg_crypto_nocrc);
            TEST_ASSERT(enc_data == dec_data);
        }
        {
            desfire::bin_data enc_data = {0x1D, 0x9D, 0x29, 0x54, 0x69, 0x7D, 0xE7, 0x60, /* status */ 0x00};
            const desfire::bin_data dec_data = {0x6C, 0xE3, 0x5E, 0x4D, 0x60, 0x87, 0xF2, 0xC9, /* status */ 0x00};
            c.confirm_rx(enc_data, desfire::cipher_cfg_crypto_nocrc);
            TEST_ASSERT(enc_data == dec_data);
        }
    }
}

void test_cipher_3k3des() {
    // Test using examples from https://hack.cert.pl/files/desfire-9f122c71e0057d4f747d2ee295b0f5f6eef8ac32.html
    const auto k = desfire::key<desfire::cipher_type::des3_3k>{0, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
    desfire::cipher_3k3des c{k.k};
    {
        desfire::bin_data enc_data = {0xBC, 0x1C, 0x57, 0x0B, 0xC9, 0x48, 0x15, 0x61, 0x87, 0x13, 0x23, 0x64, 0xE4, 0xDC, 0xE1, 0x76, /* status */ 0xAF};
        const desfire::bin_data dec_data = {0x31, 0x6E, 0x6D, 0x76, 0xA4, 0x49, 0xF9, 0x25, 0xBA, 0x30, 0x4F, 0xB2, 0x65, 0x36, 0x56, 0xA2, /* status */ 0xAF};
        c.confirm_rx(enc_data, desfire::cipher_cfg_crypto_nocrc);
        TEST_ASSERT(enc_data == dec_data);
    }
    {
        desfire::bin_data dec_data = {0x36, 0xC5, 0xF8, 0xBF, 0x4A, 0x09, 0xAC, 0x23, 0x9E, 0x8D, 0xA0, 0xC7, 0x32, 0x51, 0xD4, 0xAB, 0x6E, 0x6D, 0x76, 0xA4, 0x49, 0xF9, 0x25, 0xBA, 0x30, 0x4F, 0xB2, 0x65, 0x36, 0x56, 0xA2, 0x31};
        const desfire::bin_data enc_data = {0xDD, 0xDC, 0x9A, 0x77, 0x59, 0x7F, 0x03, 0xA4, 0x0C, 0x7F, 0xAA, 0x36, 0x2F, 0x45, 0xA8, 0xEA, 0xDB, 0xE4, 0x6A, 0x11, 0x5D, 0x98, 0x19, 0x8C, 0xBF, 0x36, 0xA6, 0xE5, 0x1B, 0x39, 0xD8, 0x7C};
        c.prepare_tx(dec_data, 0, desfire::cipher_cfg_crypto_nocrc);
        TEST_ASSERT(enc_data == dec_data);
    }
    {
        desfire::bin_data enc_data = {0x72, 0x44, 0xD9, 0x35, 0xED, 0x9A, 0x13, 0x06, 0xCD, 0x8C, 0x84, 0x1A, 0x7C, 0x1D, 0xE3, 0x9A, /* status */ 0x00};
        const desfire::bin_data dec_data = {0xC5, 0xF8, 0xBF, 0x4A, 0x09, 0xAC, 0x23, 0x9E, 0x8D, 0xA0, 0xC7, 0x32, 0x51, 0xD4, 0xAB, 0x36, /* status */ 0x00};
        c.confirm_rx(enc_data, desfire::cipher_cfg_crypto_nocrc);
        TEST_ASSERT(enc_data == dec_data);
    }
}

void test_cipher_aes() {
    // Test using examples from https://hack.cert.pl/files/desfire-9f122c71e0057d4f747d2ee295b0f5f6eef8ac32.html
    const auto k = desfire::key<desfire::cipher_type::aes128>{0, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
    desfire::cipher_aes c{k.k};
    {
        desfire::bin_data enc_data = {0xB9, 0x69, 0xFD, 0xFE, 0x56, 0xFD, 0x91, 0xFC, 0x9D, 0xE6, 0xF6, 0xF2, 0x13, 0xB8, 0xFD, 0x1E, /* status */ 0xAF};
        const desfire::bin_data dec_data = {0xC0, 0x5D, 0xDD, 0x71, 0x4F, 0xD7, 0x88, 0xA6, 0xB7, 0xB7, 0x54, 0xF3, 0xC4, 0xD0, 0x66, 0xE8, /* status */ 0xAF};
        c.confirm_rx(enc_data, desfire::cipher_cfg_crypto_nocrc);
        TEST_ASSERT(enc_data == dec_data);
    }
    {
        desfire::bin_data dec_data = {0xF4, 0x4B, 0x26, 0xF5, 0x68, 0x6F, 0x3A, 0x39, 0x1C, 0xD3, 0x8E, 0xBD, 0x10, 0x77, 0x22, 0x81, 0x5D, 0xDD, 0x71, 0x4F, 0xD7, 0x88, 0xA6, 0xB7, 0xB7, 0x54, 0xF3, 0xC4, 0xD0, 0x66, 0xE8, 0xC0};
        const desfire::bin_data enc_data = {0x36, 0xAA, 0xD7, 0xDF, 0x6E, 0x43, 0x6B, 0xA0, 0x8D, 0x18, 0x61, 0x38, 0x30, 0xA7, 0x0D, 0x5A, 0xD4, 0x3E, 0x3D, 0x3F, 0x4A, 0x8D, 0x47, 0x54, 0x1E, 0xEE, 0x62, 0x3A, 0x93, 0x4E, 0x47, 0x74};
        c.prepare_tx(dec_data, 0, desfire::cipher_cfg_crypto_nocrc);
        TEST_ASSERT(enc_data == dec_data);
    }
    {
        desfire::bin_data enc_data = {0x80, 0x0D, 0xB6, 0x80, 0xBC, 0x14, 0x6B, 0xD1, 0x21, 0xD6, 0x57, 0x8F, 0x2D, 0x2E, 0x20, 0x59, /* status */ 0x00};
        const desfire::bin_data dec_data = {0x4B, 0x26, 0xF5, 0x68, 0x6F, 0x3A, 0x39, 0x1C, 0xD3, 0x8E, 0xBD, 0x10, 0x77, 0x22, 0x81, 0xF4, /* status */ 0x00};
        c.confirm_rx(enc_data, desfire::cipher_cfg_crypto_nocrc);
        TEST_ASSERT(enc_data == dec_data);
    }
}

void issue_header(std::string const &title) {
    ESP_LOGI(TEST_TAG, "--------------------------------------------------------------------------------");
    const std::size_t tail_length = std::max(68u, title.length()) - title.length();
    const std::string header = "---------- " + title + " " + std::string(tail_length, '-');
    ESP_LOGI(TEST_TAG, "%s", header.c_str());
    vTaskDelay(2000 / portTICK_PERIOD_MS);
}


void test_auth_attempt(desfire::tag::r<> const &r) {
    TEST_ASSERT(pcd != nullptr);
    if (not r) {
        ESP_LOGW(TEST_TAG, "Authentication failed: %s", desfire::to_string(r.error()));
        if (not pcd->last_result()) {
            ESP_LOGW(TEST_TAG, "Last PCD error: %s", pn532::to_string(pcd->last_result().error()));
        } else {
            ESP_LOGW(TEST_TAG, "Last controller error: %s", pn532::to_string(pcd->last_result()->error));
        }
        TEST_FAIL();
    } else {
        ESP_LOGI(TEST_TAG, "Successful.");
    }
}

void setup_mifare() {
    TEST_ASSERT(tag_reader != nullptr);

    ESP_LOGI(TEST_TAG, "Searching for one passive 106 kbps target. Please bring card close.");
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
    TEST_ASSERT(pcd != nullptr and mifare != nullptr);
    ESP_LOGI(TEST_TAG, "Selecting default application.");
    TEST_ASSERT(mifare->select_application(desfire::root_app));
    ESP_LOGI(TEST_TAG, "Attempting auth with default DES key.");
    test_auth_attempt(mifare->authenticate(desfire::key<desfire::cipher_type::des>{}));
    ESP_LOGI(TEST_TAG, "Formatting PICC for testing.");
    TEST_ASSERT(mifare->format_picc());
}

void test_mifare_create_apps() {
    TEST_ASSERT(pcd != nullptr and mifare != nullptr);

    const std::array<desfire::any_key, 4> keys{
            desfire::any_key{desfire::key<desfire::cipher_type::des>{}},
            desfire::any_key{desfire::key<desfire::cipher_type::des3_2k>{}},
            desfire::any_key{desfire::key<desfire::cipher_type::des3_3k>{}},
            desfire::any_key{desfire::key<desfire::cipher_type::aes128>{}}
    };

    desfire::app_id app_id{0, 0, 0};
    for (desfire::any_key const &k : keys) {
        ++app_id.back();
        ESP_LOGI(TEST_TAG, "Attempting to create apps with cipher %s.", desfire::to_string(k.type()));
        TEST_ASSERT(mifare->select_application(desfire::root_app));
        TEST_ASSERT(mifare->authenticate(desfire::key<desfire::cipher_type::des>{}));
        TEST_ASSERT(mifare->create_application(app_id, desfire::key_settings{k.type()}));
        TEST_ASSERT(mifare->select_application(app_id));
        test_auth_attempt(mifare->authenticate(k));
    }
    TEST_ASSERT(mifare->select_application(desfire::root_app));
    TEST_ASSERT(mifare->format_picc());
}

extern "C" void app_main() {
    UNITY_BEGIN();
    issue_header("HARDWARE SETUP");
    RUN_TEST(setup_uart_pn532);
    issue_header("PN532 TEST AND DIAGNOSTICS");
    RUN_TEST(test_get_fw);
    RUN_TEST(test_diagnostics);
    issue_header("PN532 SCAN TEST (optionally place card)");
    RUN_TEST(test_scan_mifare);
    RUN_TEST(test_scan_all);
    issue_header("PN532 MIFARE COMM TEST (replace Mifare card)");
    RUN_TEST(test_data_exchange);
    issue_header("MIFARE CIPHER TEST");
    RUN_TEST(test_cipher_des);
    RUN_TEST(test_cipher_2k3des);
    RUN_TEST(test_cipher_3k3des);
    RUN_TEST(test_cipher_aes);
    issue_header("MIFARE TEST (replace Mifare card)");
    RUN_TEST(setup_mifare);
    RUN_TEST(test_mifare_base);
    RUN_TEST(test_mifare_create_apps);
    UNITY_END();
}

#endif
