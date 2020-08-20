#ifndef __HSU_HPP__
#define __HSU_HPP__


#include <vector>
#include <iterator>
#include "instructions.hpp"
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
    int wake_up(TickType_t timeout = PN532_DEFAULT_TIMEOUT);
    template<typename Container> int receive(Container &data, TickType_t timeout = PN532_DEFAULT_TIMEOUT);
    template<typename Container> int send(const uint8_t cmd, Container param, TickType_t timeout = PN532_DEFAULT_TIMEOUT);
    int wait_ack(TickType_t timeout = 1000/portTICK_PERIOD_MS);
    int send_ack(bool ack=true, TickType_t timeout = 1000/portTICK_PERIOD_MS);
    template<typename Iter> bool fill_buffer(Iter first, Iter last, TickType_t timeout = 1000/portTICK_PERIOD_MS);
};
#include "hsu.cpp"

#endif