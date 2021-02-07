#include "unity.h"
#include "driver/gpio.h"
#include "driver/uart.h"

#include <pn532/nfc.hpp>
#include <pn532/hsu.hpp>

#define TXD  (GPIO_NUM_17)
#define RXD  (GPIO_NUM_16)
#define BUF_SIZE (1024)
#define UART_DUT UART_NUM_1

auto serialDriver = pn532::hsu(UART_DUT);
auto tagReader = pn532::nfc(serialDriver);

void initialize_PN532(){
    uart_config_t uart_config = {
            .baud_rate = 115200,
            .data_bits = UART_DATA_8_BITS,
            .parity    = UART_PARITY_DISABLE,
            .stop_bits = UART_STOP_BITS_1,
            .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
            .rx_flow_ctrl_thresh = 122,
            .use_ref_tick = true
    };
    uart_param_config(UART_DUT, &uart_config);
    uart_driver_install(UART_DUT, BUF_SIZE, BUF_SIZE, 0, NULL, 0);
    uart_set_pin(UART_DUT, TXD, RXD, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);

    serialDriver.wake();
    TEST_ASSERT_TRUE(tagReader.sam_configuration(pn532::sam_mode::normal, pn532::one_sec));
    TEST_ASSERT_TRUE(tagReader.rf_configuration_retries(0xFF,0xFF, 0xFF));  //TODO: error send comand
    TEST_ASSERT_TRUE(tagReader.rf_configuration_field(false, true));        //Switch on RF, disable auto field detection (used for card emulation)
}

void get_uuid(){
    auto ret = tagReader.initiator_list_passive_kbps106_typea(1);
    TEST_ASSERT_TRUE(ret);
    //todo show UUID
}

extern "C" void app_main()
{
    initialize_PN532();
    get_uuid();
}
