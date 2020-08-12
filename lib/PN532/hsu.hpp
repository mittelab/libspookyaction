#ifndef __HSU_HPP__
#define __HSU_HPP__


#include <vector>
#define PN532_DEFAULT_TIMEOUT (1000/portTICK_PERIOD_MS)



#ifdef __cplusplus
extern "C" {
#endif

#include <esp_log.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "driver/uart.h"

#ifdef __cplusplus
}
#endif

class HSU{
    public:
    uart_port_t device;

    HSU(uart_port_t port);
    int receive(std::vector<uint8_t> &data, TickType_t timeout = PN532_DEFAULT_TIMEOUT);
    int send(const uint8_t cmd, const std::vector<uint8_t> param = {}, TickType_t timeout = PN532_DEFAULT_TIMEOUT);
    int wait_ack(TickType_t timeout = 1000/portTICK_PERIOD_MS);
    int send_ack(bool ack=true, TickType_t timeout = 1000/portTICK_PERIOD_MS);
};
#endif