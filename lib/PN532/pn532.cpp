#include "pn532.hpp"
#include <array>
#define PN532_DEFAULT_TIMEOUT (1000/portTICK_PERIOD_MS)


template<class T>
int PN532<T>::cmd(const uint8_t cmd, const std::vector<uint8_t> param, TickType_t timeout)
{
    BaseType_t tWrite = xTaskGetTickCount();
    T::send(cmd, param, xTaskGetTickCount() - tWrite);
    return T::wait_ack(xTaskGetTickCount() - tWrite);
}

template<class T>
int PN532<T>::sam_config(TickType_t timeout)
{
    ESP_LOGI(PN532_LOG, "Configuring pn532 SAM as not used");
    const std::vector<uint8_t> ackbuff = {
        0x01,   // normal mode
        0x14,   // timeout 50ms * 20 = 1 second
        0x01    // use IRQ pin
    };
    return cmd(PN532_COMMAND_SAMCONFIGURATION, ackbuff, timeout);

}

template<class T>
int PN532<T>::data_exchange(const uint8_t command, const std::vector<uint8_t> param, std::vector<uint8_t> data, TickType_t timeout)
{
    BaseType_t tWrite = xTaskGetTickCount();
    if(cmd(command, param, xTaskGetTickCount() - tWrite) >= 0)
        return T::receive(data, xTaskGetTickCount() - tWrite);
}

// int PN532::wake_up(TickType_t timeout = PN532_DEFAULT_TIMEOUT)
// {
//     const char buffer[] = {0x55, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x02, 0xfe, 0xd4, 0x02, 0x2a, 0x00};
//     uart_write_bytes(port, buffer, sizeof(buffer));
//     return pn532_serial_readack(port, 1000/portTICK_PERIOD_MS);
//     return ESP_OK;
