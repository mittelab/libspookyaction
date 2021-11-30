#include <driver/gpio.h>
#include <driver/uart.h>
#include <pn532/controller.hpp>
#include <pn532/esp32/hsu.hpp>

#define PN532_SERIAL_TX (GPIO_NUM_17)
#define PN532_SERIAL_RX (GPIO_NUM_16)

using namespace std::chrono_literals;

std::pair<pn532::esp32::hsu_channel, pn532::controller> initialize_pn532() {
    static constexpr uart_config_t uart_config = {
            .baud_rate = 115200,
            .data_bits = UART_DATA_8_BITS,
            .parity = UART_PARITY_DISABLE,
            .stop_bits = UART_STOP_BITS_1,
            .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
            .rx_flow_ctrl_thresh = 122,
            .source_clk = UART_SCLK_REF_TICK};

    auto hsu_chn = pn532::esp32::hsu_channel(UART_NUM_1, uart_config, PN532_SERIAL_TX, PN532_SERIAL_RX);
    auto tag_reader = pn532::controller(hsu_chn);
    hsu_chn.wake();
    tag_reader.sam_configuration(pn532::sam_mode::normal, 1s);
    tag_reader.rf_configuration_retries(pn532::infty);
    // Switch on RF, disable auto field detection (used for card emulation)
    tag_reader.rf_configuration_field(false, true);
    return {std::move(hsu_chn), std::move(tag_reader)};
}

void selftest(pn532::controller &tag_reader) {
    // Autotest PN532 ROM firmware
    ESP_LOGI("EXAMPLE", "ROM: %s", tag_reader.diagnose_rom() ? "OK" : "FAIL");

    // Autotest PN532 RAM
    ESP_LOGI("EXAMPLE", "RAM: %s", tag_reader.diagnose_ram() ? "OK" : "FAIL");

    // Check card presence via ART or ISO/IEC14443-4 card presence detection
    ESP_LOGI("EXAMPLE", "CARD PRESENT: %s", tag_reader.diagnose_attention_req_or_card_presence() ? "YES" : "NO");

    // Test comunication line
    ESP_LOGI("EXAMPLE", "COMUNICATION: %s", tag_reader.diagnose_comm_line() ? "OK" : "FAIL");

    // Test target polling, this will search for FeliCa card with 212kbps or 424kbps baudrate, return number of failed attempt
    ESP_LOGI("EXAMPLE", "POLL TAG: ");
    if (const auto poll_result = tag_reader.diagnose_poll_target(true, true); poll_result) {
        ESP_LOGI("EXAMPLE", "%d@212kbps %d@424kbps", poll_result->first, poll_result->second);
    } else {
        ESP_LOGI("EXAMPLE", "ERROR (%s)", pn532::to_string(poll_result.error()));
    }

    // Check antenna for open circuit, or short circuit
    const auto antenna_test_result = tag_reader.diagnose_self_antenna(pn532::bits::low_current_thr::mA_25, pn532::bits::high_current_thr::mA_150);
    ESP_LOGI("EXAMPLE", "Antenna: %s", antenna_test_result ? "OK" : "ERROR");

    // Get firmware version of the tag
    ESP_LOGI("EXAMPLE", "PN532: ");
    if (const auto fw_version_result = tag_reader.get_firmware_version(); fw_version_result) {
        ESP_LOGI("EXAMPLE", "IC: %#02x", fw_version_result->ic);
        ESP_LOGI("EXAMPLE", "version: %#02x", fw_version_result->version);
        ESP_LOGI("EXAMPLE", "revision: %#02x", fw_version_result->revision);
    } else {
        ESP_LOGI("EXAMPLE", "ERROR (%s)", pn532::to_string(fw_version_result.error()));
    }
}

extern "C" void app_main() {
    auto [hsu_chn, tag_reader] = initialize_PN532();
    selftest(tag_reader);
}
