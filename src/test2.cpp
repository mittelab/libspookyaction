/* UART Echo Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#define PN532_DEFAULT_TIMEOUT (1000/portTICK_PERIOD_MS)


extern "C" {
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/uart.h"
#include "driver/gpio.h"

#include <esp_log.h>
}
#include <pn532.hpp>
#include <hsu.hpp>



#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG


/**
 * This is an example which echos any data it receives on UART1 back to the sender,
 * with hardware flow control turned off. It does not use UART driver event queue.
 *
 * - Port: UART1
 * - Receive (Rx) buffer: on
 * - Transmit (Tx) buffer: off
 * - Flow control: off
 * - Event queue: off
 * - Pin assignment: see defines below
 */

#define ECHO_TEST_TXD  (GPIO_NUM_4)
#define ECHO_TEST_RXD  (GPIO_NUM_36)


#define BUF_SIZE (1024)


void echo_task(void *pvParameters)
{
    /* Configure parameters of an UART driver,
     * communication pins and install the driver */
    uart_config_t uart_config = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE
    };
    uart_param_config(UART_NUM_1, &uart_config);
    uart_driver_install(UART_NUM_1, BUF_SIZE, BUF_SIZE, 0, NULL, 0);
    uart_set_pin(UART_NUM_1, ECHO_TEST_TXD, ECHO_TEST_RXD, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);

    PN532<HSU> test(UART_NUM_1);


    while(1)
    {

        test.sam_config();
        ESP_LOGE("main", "DONE");
        vTaskDelay(1000/portTICK_PERIOD_MS);
    }

}


extern "C" void app_main()
{
    esp_log_level_set(PN532_LOG, ESP_LOG_NONE);
    esp_log_level_set(PN532_LOG_RECEIVED_DATA, ESP_LOG_NONE);
    esp_log_level_set(PN532_LOG_SENT_DATA, ESP_LOG_NONE);
    esp_log_level_set("desfire", ESP_LOG_VERBOSE);
    //esp_log_level_set("desfire", ESP_LOG_NONE);
    xTaskCreate(echo_task, "uart_echo_task", 2048 * 2, NULL, 10, NULL);
}
