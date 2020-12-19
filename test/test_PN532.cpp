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
auto tag_test = build_desfire(test_pn532,0x01,0,dfk);
uint8_t tagID;


void initialize_PN532()
{
    uart_config_t uart_config = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .rx_flow_ctrl_thresh = 122,
        .source_clk = UART_SCLK_APB,
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

void test_desfire_list_application()
{
    std::vector<uint32_t> ids;
    tag_test.listApplication(ids);
    ESP_LOG_BUFFER_HEX_LEVEL(PN532_LOG,ids.data(),ids.size(), ESP_LOG_ERROR);
}

// void test_desfire_cmac()
// {
//     std::vector<uint32_t> ids;
//     std::array<uint8_t, 8> sk = {0xDC, 0xB0, 0x96, 0xC2, 0xA4, 0x0E, 0x78, 0xE0};
//     tag_test.appKey.setSessionKey(sk);
//     tag_test.appKey.iv = {0x9B, 0x97, 0xC2, 0xA1, 0xE4, 0x7B, 0x96, 0xDD};
//     std::vector<uint8_t> cmd = {0x64, 0x00};
//     std::array<uint8_t, 8> cmac;
//     tag_test.appKey.cmac(cmd.begin(),cmd.end(), cmac.begin());
//     ESP_LOG_BUFFER_HEX_LEVEL(PN532_LOG,cmac.data(),cmac.size(), ESP_LOG_ERROR);
// }

////////////////////////////////////////////////////////////

void test_desfire_cerate_app()
{
    std::vector<uint32_t> ids;
    tag_test.createApp(0x00DEAD);
    ESP_LOG_BUFFER_HEX_LEVEL(PN532_LOG,ids.data(),ids.size(), ESP_LOG_ERROR);
}


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
    RUN_TEST(test_desfire_list_application);
    // RUN_TEST(test_desfire_cmac);
    // RUN_TEST(test_desfire_cerate_app);
    UNITY_END();
}
