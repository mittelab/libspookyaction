#ifdef TEST_MAIN

#include <unity.h>
#include <driver/uart.h>
#include <hsu.hpp>
#include <pn532.hpp>

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

void setup_uart()
{
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


void test_get_fw()
{
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
    TEST_ASSERT(is_ok(tag_reader->diagnose_self_antenna(pn532::low_current_thr::mA_25, pn532::high_current_thr::mA_130)));
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

extern "C" void app_main()
{
    UNITY_BEGIN();
    RUN_TEST(setup_uart);
    RUN_TEST(test_get_fw);
    RUN_TEST(test_diagnostics);
    RUN_TEST(test_scan_mifare);
    UNITY_END();
}

#endif
