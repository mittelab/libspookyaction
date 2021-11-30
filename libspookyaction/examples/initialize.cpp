#include <driver/gpio.h>
#include <driver/uart.h>
#include <pn532/controller.hpp>
#include <pn532/esp32/hsu.hpp>

// PN532_SERIAL_TX: the GPIO pin number connected to the TX line on the PN532
#ifndef PN532_SERIAL_TX
#define PN532_SERIAL_TX (GPIO_NUM_17)
#endif

// PN532_SERIAL_RX: the GPIO pin number connected to the RX line on the PN532
#ifndef PN532_SERIAL_RX
#define PN532_SERIAL_RX (GPIO_NUM_16)
#endif

using namespace std::chrono_literals;

void initialize_pn532() {
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
}

extern "C" void app_main() {
    initialize_pn532();
}
