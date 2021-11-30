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

void get_uuid(pn532::controller &tag_reader) {
    if (auto ret = tag_reader.initiator_list_passive_kbps106_typea(); ret) {
        for (pn532::target_kbps106_typea const &target : *ret) {
            ESP_LOGI("EXAMPLE", "Logical index %u; NFC ID:", target.logical_index);
            ESP_LOG_BUFFER_HEX_LEVEL("EXAMPLE", target.info.nfcid.data(), target.info.nfcid.size(), ESP_LOG_INFO);
        }
    }
}

extern "C" void app_main() {
    auto [hsu_chn, tag_reader] = initialize_pn532();
    get_uuid(tag_reader);
}
