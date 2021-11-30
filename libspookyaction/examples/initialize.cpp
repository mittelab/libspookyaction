#include <pn532/controller.hpp>
#include <pn532/esp32/hsu.hpp>

#define TAG "EXAMPLE"

using namespace std::chrono_literals;

extern "C" void app_main() {
    // The GPIO pin number connected to the TX line on the PN532
    static constexpr gpio_num_t gpio_serial_tx = GPIO_NUM_17;
    // The GPIO pin number connected to the RX line on the PN532
    static constexpr gpio_num_t gpio_serial_rx = GPIO_NUM_16;
    // UART configuration. This is pretty much always the same
    static constexpr uart_config_t uart_config = {
            .baud_rate = 115200,
            .data_bits = UART_DATA_8_BITS,
            .parity = UART_PARITY_DISABLE,
            .stop_bits = UART_STOP_BITS_1,
            .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
            .rx_flow_ctrl_thresh = 122,
            .source_clk = UART_SCLK_REF_TICK};

    // Create a communication channel (high speed UART, HSU) with the PN532.
    auto hsu_chn = pn532::esp32::hsu_channel(UART_NUM_1, uart_config, gpio_serial_tx, gpio_serial_rx);

    // Create a new tag reader controller, i.e. a PN532 abstraction, that operates on top of the channel
    auto pn532 = pn532::controller(hsu_chn);

    // Wake up the channel. This wakes the PN532 too.
    if (not hsu_chn.wake()) {
        ESP_LOGE(TAG, "HSU did not wake!");
        return;
    }

    // Perform standard initialization, first initialize the Security Access Module, needed for everything
    if (not pn532.sam_configuration(pn532::sam_mode::normal, 1s)) {
        ESP_LOGE(TAG, "Failed to initialize SAM");
        return;
    }

    // Now switch RF on, disable automatic field detection (used in target mode).
    if (not pn532.rf_configuration_field(false, true)) {
        ESP_LOGE(TAG, "Failed to switch RF field on");
        return;
    }

    ESP_LOGI(TAG, "PN532 initialization successful.");
}
