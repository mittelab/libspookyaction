#include "unity.h"
#include "driver/gpio.h"


#include <pn532.hpp>
#include <hsu.hpp>
#include <desfire.hpp>

// #define ECHO_TEST_TXD  (GPIO_NUM_4)
// #define ECHO_TEST_RXD  (GPIO_NUM_36)
#define ECHO_TEST_TXD  (GPIO_NUM_17)
#define ECHO_TEST_RXD  (GPIO_NUM_16)
#define BUF_SIZE (1024)
#define UART_DUT UART_NUM_1
#define VERSION {0x03, 0x32, 0x01, 0x06, 0x07}


PN532<HSU> test_pn532(UART_DUT);
AppKey<KEY_2K3DES> dfk(0x00);
DesfireApp<PN532<HSU>,AppKey<KEY_2K3DES>> tag_test(test_pn532,0x01,0,dfk);
uint8_t tagID;


void initialize_PN532()
{
    uart_config_t uart_config = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE
    };
    uart_param_config(UART_DUT, &uart_config);
    uart_driver_install(UART_DUT, BUF_SIZE, BUF_SIZE, 0, NULL, 0);
    uart_set_pin(UART_DUT, ECHO_TEST_TXD, ECHO_TEST_RXD, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    test_pn532.begin();
}

// void test_getFirmwareVersion()
// {
//     pn532_info_t chip;
//     TEST_ASSERT_TRUE(test_pn532.getFirmwareVersion(chip));
// }

void test_readGpio()
{
    TEST_ASSERT_TRUE(test_pn532.readGpio(PN532_GPIO_P71));
}

void test_writeGpio()
{
    TEST_ASSERT_TRUE(test_pn532.writeGpio(PN532_GPIO_P71,false));
}

void test_InAutoPoll()
{
    std::vector<uint8_t> data;
    TEST_ASSERT_TRUE(test_pn532.InAutoPoll(0x14,0x02,0x20,data));
    tagID = data[0];
}

void test_InSelect()
{
    ESP_LOGI(PN532_LOG,"TagID: %#02x",tagID);
    TEST_ASSERT_TRUE(test_pn532.InSelect(tagID));
}

//@TODO: DATA is worng
void test_InDataExchange()
{
    std::vector<uint8_t> data;
    TEST_ASSERT_TRUE(test_pn532.InDataExchange(tagID,{0x5A,0x00,0x00,0x00},data));
    ESP_LOG_BUFFER_HEX_LEVEL(PN532_LOG,data.data(),data.size(), ESP_LOG_ERROR);
    TEST_ASSERT_EQUAL_HEX8(0x00,data[0]);
}

//////////////////////////////////////////////////////////////
void test_desfire_select()
{
    tag_test.selectApp();
}

void test_desfire_auth()
{
    TEST_ASSERT_TRUE(tag_test.authenticate());
}


////////////////////////////////////////////////////////////


extern "C" void app_main()
{
    UNITY_BEGIN();
    RUN_TEST(initialize_PN532);
    //RUN_TEST(test_getFirmwareVersion);
    // RUN_TEST(test_readGpio);
    // RUN_TEST(test_writeGpio);
    RUN_TEST(test_InAutoPoll);
    RUN_TEST(test_InSelect);
    RUN_TEST(test_InDataExchange);
    //////////////////////////////
    RUN_TEST(test_desfire_select);
    RUN_TEST(test_desfire_auth);
    UNITY_END();
}
 