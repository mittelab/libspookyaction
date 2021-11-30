#include <pn532/controller.hpp>
#include <pn532/esp32/hsu.hpp>

#define TAG "EXAMPLE"

using namespace std::chrono_literals;

const char *bool_to_ok_fail(bool result) {
    return result ? "OK" : "FAIL";
}

const char *bool_to_yes_no(bool result) {
    return result ? "YES" : "NO";
}

/**
 * @note This is the new function introduced in this example
 */
void self_test(pn532::controller &pn532) {
    // Autotest PN532 ROM firmware
    ESP_LOGI(TAG, "ROM: %s", bool_to_ok_fail(bool(pn532.diagnose_rom())));

    // Autotest PN532 RAM
    ESP_LOGI(TAG, "RAM: %s", bool_to_ok_fail(bool(pn532.diagnose_ram())));

    // Check card presence via ART or ISO/IEC14443-4 card presence detection
    ESP_LOGI(TAG, "Card present: %s", bool_to_yes_no(bool(pn532.diagnose_attention_req_or_card_presence())));

    // Test comunication line
    ESP_LOGI(TAG, "Channel: %s", bool_to_ok_fail(bool(pn532.diagnose_comm_line())));

    // Test target polling, this will search for FeliCa card with 212kbps or 424kbps baudrate, return number of failed attempt
    ESP_LOGI(TAG, "Polling tag failures: ");
    if (const auto poll_result = pn532.diagnose_poll_target(true, true); poll_result) {
        ESP_LOGI(TAG, "   %d@212kbps %d@424kbps", poll_result->first, poll_result->second);
    } else {
        ESP_LOGI(TAG, "   Error: %s", pn532::to_string(poll_result.error()));
    }

    // Check antenna for open circuit, or short circuit
    const auto antenna_test_result = pn532.diagnose_self_antenna(pn532::bits::low_current_thr::mA_25, pn532::bits::high_current_thr::mA_150);
    ESP_LOGI(TAG, "Antenna: %s", bool_to_ok_fail(bool(antenna_test_result)));

    // Get firmware version of the tag
    ESP_LOGI(TAG, "PN532 info: ");
    if (const auto fw_version_result = pn532.get_firmware_version(); fw_version_result) {
        ESP_LOGI(TAG, "   IC: %#02x", fw_version_result->ic);
        ESP_LOGI(TAG, "   Version: %#02x", fw_version_result->version);
        ESP_LOGI(TAG, "   Revision: %#02x", fw_version_result->revision);
    } else {
        ESP_LOGI(TAG, "   Error: %s", pn532::to_string(fw_version_result.error()));
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
    self_test(pn532);
}
