#include <pn532/controller.hpp>
#include <pn532/esp32/hsu.hpp>
#include <pn532/scanner.hpp>
#include <thread>

#define TAG "EXAMPLE"

using namespace std::chrono_literals;

struct app_responder : pn532::scanner_responder {
    pn532::post_interaction interact(pn532::scanner &, pn532::scanned_target const &target) override {
        ESP_LOGI(TAG, "Detected %s target with ID:", pn532::to_string(target.type));
        ESP_LOG_BUFFER_HEX_LEVEL(TAG, target.nfcid.data(), target.nfcid.size(), ESP_LOG_INFO);
        // Do not log this target until it first leaves the RF range:
        return pn532::post_interaction::reject;
    }

    void on_leaving_rf(pn532::scanner &, pn532::scanned_target const &target) override {
        ESP_LOGI(TAG, "A %s target has left the RF field.", pn532::to_string(target.type));
    }
};

/**
 * @note This is identical to the example in @ref initialize.cpp aside from using @ref pn532::scanner
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
            .source_clk = UART_SCLK_DEFAULT};
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
    ESP_LOGI(TAG, "PN532 initialization successful.");
    pn532::scanner scanner{pn532};
    app_responder responder{};
    scanner.loop(responder);
}
