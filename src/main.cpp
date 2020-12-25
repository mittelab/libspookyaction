#ifdef TEST_MAIN

#include <unity.h>
#include <driver/uart.h>
#include <hsu.hpp>
#include <pn532.hpp>

#define TEST_TAG "UT"
#define TX_PIN   (GPIO_NUM_17)
#define RX_PIN   (GPIO_NUM_16)
#define BUF_SIZE (1024)

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
    pn532::hsu serial{UART_NUM_1};
    pn532::nfc tag_reader{serial};
    serial.wake();
    tag_reader.sam_configuration(pn532::sam_mode::normal, pn532::one_sec);
    const auto r_fw = tag_reader.get_firmware_version();
    TEST_ASSERT(bool(r_fw));
    ESP_LOGI(TEST_TAG, "IC version %u, version: %u.%u", r_fw->ic, r_fw->version, r_fw->revision);
}

extern "C" void app_main()
{
    UNITY_BEGIN();
    RUN_TEST(setup_uart);
    RUN_TEST(test_get_fw);
    UNITY_END();
}

#endif
