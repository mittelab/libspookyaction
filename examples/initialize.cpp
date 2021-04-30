#include "driver/gpio.h"
#include "driver/uart.h"
#include "unity.h"

#include <pn532/esp32/hsu.hpp>
#include <pn532/controller.hpp>

#define TXD (GPIO_NUM_17)
#define RXD (GPIO_NUM_16)
#define BUF_SIZE (1024)
#define UART_DUT UART_NUM_1

using namespace std::chrono_literals;

void initialize_PN532() {
    static constexpr uart_config_t uart_config = {
            .baud_rate = 115200,
            .data_bits = UART_DATA_8_BITS,
            .parity = UART_PARITY_DISABLE,
            .stop_bits = UART_STOP_BITS_1,
            .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
            .rx_flow_ctrl_thresh = 122,
            .source_clk = UART_SCLK_REF_TICK};

    auto serialDriver = pn532::esp32::hsu_channel(UART_DUT, uart_config, TXD, RXD);
    auto tagReader = pn532::controller(serialDriver);
    serialDriver.wake();
    tagReader.sam_configuration(pn532::sam_mode::normal, 1s);
    tagReader.rf_configuration_retries(pn532::infty);
    //Switch on RF, disable auto field detection (used for card emulation)
    tagReader.rf_configuration_field(false, true);
}


extern "C" void app_main() {
    initialize_PN532();
}
