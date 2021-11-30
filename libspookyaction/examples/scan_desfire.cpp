#include <pn532/controller.hpp>
#include <pn532/esp32/hsu.hpp>

#define TAG "EXAMPLE"

using namespace std::chrono_literals;

/**
 * @note This is the new function introduced in this example
 */
void scan_uuids(pn532::controller &pn532) {
    if (auto res = pn532.initiator_list_passive_kbps106_typea(); res) {
        for (pn532::target_kbps106_typea const &target : *res) {
            ESP_LOGI(TAG, "Logical index %u; NFC ID:", target.logical_index);
            ESP_LOG_BUFFER_HEX_LEVEL(TAG, target.info.nfcid.data(), target.info.nfcid.size(), ESP_LOG_INFO);
        }
    } else {
        ESP_LOGE(TAG, "Failed to scan for passive targets at 106kbps (type A), error: %s", pn532::to_string(res.error()));
    }
}


/**
 * @note This is identical to the example in @ref initialize.cpp.
 */
extern "C" void app_main() {
    static constexpr gpio_num_t gpio_serial_tx = GPIO_NUM_17;
    static constexpr gpio_num_t gpio_serial_rx = GPIO_NUM_16;
    static constexpr uart_config_t uart_config = {
            .baud_rate = 115200,
            .data_bits = UART_DATA_8_BITS,
            .parity = UART_PARITY_DISABLE,
            .stop_bits = UART_STOP_BITS_1,
            .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
            .rx_flow_ctrl_thresh = 122,
            .source_clk = UART_SCLK_REF_TICK};
    auto hsu_chn = pn532::esp32::hsu_channel(UART_NUM_1, uart_config, gpio_serial_tx, gpio_serial_rx);
    auto pn532 = pn532::controller(hsu_chn);
    if (not hsu_chn.wake()) {
        ESP_LOGE(TAG, "HSU did not wake!");
        return;
    }
    if (not pn532.sam_configuration(pn532::sam_mode::normal, 1s)) {
        ESP_LOGE(TAG, "Failed to initialize SAM");
        return;
    }
    if (not pn532.rf_configuration_field(false, true)) {
        ESP_LOGE(TAG, "Failed to switch RF field on");
        return;
    }
    scan_uuids(pn532);
}
