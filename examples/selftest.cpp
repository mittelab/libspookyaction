#include "driver/gpio.h"
#include "driver/uart.h"
#include "unity.h"

#include <pn532/hsu.hpp>
#include <pn532/nfc.hpp>

#define TXD (GPIO_NUM_17)
#define RXD (GPIO_NUM_16)
#define BUF_SIZE (1024)
#define UART_DUT UART_NUM_1

auto serialDriver = pn532::hsu(UART_DUT);
auto tagReader = pn532::nfc(serialDriver);

void initialize_PN532() {
    uart_config_t uart_config = {
            .baud_rate = 115200,
            .data_bits = UART_DATA_8_BITS,
            .parity = UART_PARITY_DISABLE,
            .stop_bits = UART_STOP_BITS_1,
            .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
            .rx_flow_ctrl_thresh = 122,
            .use_ref_tick = true};
    uart_param_config(UART_DUT, &uart_config);
    uart_driver_install(UART_DUT, BUF_SIZE, BUF_SIZE, 0, NULL, 0);
    uart_set_pin(UART_DUT, TXD, RXD, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);

    serialDriver.wake();
    TEST_ASSERT_TRUE(tagReader.sam_configuration(pn532::sam_mode::normal, pn532::one_sec));
    TEST_ASSERT_TRUE(tagReader.rf_configuration_retries(0xFF, 0xFF, 0xFF));//TODO: error send comand
    TEST_ASSERT_TRUE(tagReader.rf_configuration_field(false, true));       //Switch on RF, disable auto field detection (used for card emulation)
}

void selftest() {
    //Autotest PN532 ROM firmware
    printf("ROM: %s\n", tagReader.diagnose_rom() ? "OK" : "FAIL");

    //Autotest PN532 RAM
    printf("RAM: %s\n", tagReader.diagnose_ram() ? "OK" : "FAIL");

    //check card presence via ART or ISO/IEC14443-4 card presence detection
    printf("CARD PRESENT: %s\n", tagReader.diagnose_attention_req_or_card_presence() ? "YES" : "NO");

    //Test comunication line
    printf("COMUNICATION: %s\n", tagReader.diagnose_comm_line() ? "OK" : "FAIL");

    // test target polling, this wills earch for FeliCa card with 212kbps or 424kbps baudrate, return number of failed attempt
    printf("POLL TAG: ");
    auto poll_ret = tagReader.diagnose_poll_target(true, true);
    if (!poll_ret) printf("ERROR (%s)\n", pn532::to_string(poll_ret.error()));
    else
        printf("%d@212kbts %d@424kbps\n", poll_ret->first, poll_ret->second);

    // Check antenna for open circuit, or short circuit
    auto ret = tagReader.diagnose_self_antenna(pn532::bits::low_current_thr::mA_25, pn532::bits::high_current_thr::mA_150);
    printf("Antenna: %s", ret ? "OK" : "ERROR");

    //get firmware version of the tag
    printf("PN532: ");
    auto firmware_ret = tagReader.get_firmware_version();
    if (firmware_ret) {
        printf("\nIC: %#02x\n", firmware_ret->ic);
        printf("version: %#02x\n", firmware_ret->version);
        printf("revision: %#02x\n", firmware_ret->revision);
    } else {
        printf("ERROR (%s)\n", pn532::to_string(firmware_ret.error()));
    }
}

extern "C" void app_main() {
    initialize_PN532();
    selftest();
}
