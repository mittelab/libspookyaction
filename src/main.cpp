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


    template <class T, class ...Args>
    std::unique_ptr<T> make_unique(Args &&...args) {
        return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
    }

    bool is_ok(pn532::nfc::r<bool> const &r) {
        return r and *r;
    }

}

void setup_uart() {
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
}


void test_get_fw() {
    serial = make_unique<pn532::hsu>(UART_NUM_1);
    tag_reader = make_unique<pn532::nfc>(*serial);

    serial->wake();
    tag_reader->sam_configuration(pn532::sam_mode::normal, pn532::one_sec);
    const auto r_fw = tag_reader->get_firmware_version();
    TEST_ASSERT(bool(r_fw));
    ESP_LOGI(TEST_TAG, "IC version %u, version: %u.%u", r_fw->ic, r_fw->version, r_fw->revision);
}

void test_diagnostics() {
    TEST_ASSERT(is_ok(tag_reader->diagnose_rom()));
    TEST_ASSERT(is_ok(tag_reader->diagnose_ram()));
    TEST_ASSERT(is_ok(tag_reader->diagnose_comm_line()));
    TEST_ASSERT(
            is_ok(tag_reader->diagnose_self_antenna(pn532::low_current_thr::mA_25, pn532::high_current_thr::mA_150)));
}

void test_scan_mifare() {
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

void test_mifare() {
    ESP_LOGI(TEST_TAG, "Searching for one passive 106 kbps target. Please bring card close.");
    const auto r_scan = tag_reader->initiator_list_passive_kbps106_typea(1, 10 * pn532::one_sec);
    if (not r_scan or r_scan->empty()) {
        TEST_FAIL_MESSAGE("Could not find a suitable card for testing.");
        return;
    }
    ESP_LOGI(TEST_TAG, "Found one target:");
    auto const &nfcid = r_scan->front().info.nfcid;
    ESP_LOG_BUFFER_HEX_LEVEL(TEST_TAG, nfcid.data(), nfcid.size(), ESP_LOG_INFO);

    // Build controller
    auto pcd = pn532::desfire_pcd{*tag_reader, r_scan->front().logical_index};
    auto mifare = desfire::tag{pcd};

    ESP_LOGI(TEST_TAG, "Attempting auth with null DES key.");
    const desfire::key<desfire::cipher_type::des> k{0, {0, 0, 0, 0, 0, 0, 0, 0}};
    auto r_auth = mifare.authenticate(k);
    if (not r_auth) {
        ESP_LOGW(TEST_TAG, "Authentication failed: %s", desfire::to_string(r_auth.error()));
        if (not pcd.last_result()) {
            ESP_LOGW(TEST_TAG, "Last PCD error: %s", pn532::to_string(pcd.last_result().error()));
        } else {
            ESP_LOGW(TEST_TAG, "Last controller error: %s", pn532::to_string(pcd.last_result()->error));
        }
    }
    TEST_ASSERT(bool(r_auth));
    mifare.clear_authentication();
}

void issue_header(std::string const &title) {
    ESP_LOGI(TEST_TAG, "--------------------------------------------------------------------------------");
    const std::size_t tail_length = std::max(68u, title.length()) - title.length();
    const std::string header = "---------- " + title + " " + std::string(tail_length, '-');
    ESP_LOGI(TEST_TAG, "%s", header.c_str());
    vTaskDelay(2000 / portTICK_PERIOD_MS);
}

extern "C" void app_main() {
    UNITY_BEGIN();
    issue_header("HARDWARE SETUP");
    RUN_TEST(setup_uart);
    issue_header("PN532 TEST AND DIAGNOSTICS");
    RUN_TEST(test_get_fw);
    RUN_TEST(test_diagnostics);
    issue_header("PN532 SCAN TEST (optionally place card)");
    RUN_TEST(test_scan_mifare);
    RUN_TEST(test_scan_all);
    issue_header("PN532 MIFARE COMM TEST (replace Mifare card)");
    RUN_TEST(test_data_exchange);
    issue_header("MIFARE AUTHENTICATION TEST (replace Mifare card)");
    RUN_TEST(test_mifare);
    UNITY_END();
}

#endif
