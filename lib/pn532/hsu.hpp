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
#include <cstring>
#include "freertos/FreeRTOS.h"
#include "driver/uart.h"

#ifdef __cplusplus
}
#endif
#include <algorithm>

class HSU{

    public:
    uart_port_t device;

    HSU(uart_port_t port);
    bool wake_up(TickType_t timeout = PN532_DEFAULT_TIMEOUT);
    template<typename Container> bool receive(Container &data, TickType_t timeout = PN532_DEFAULT_TIMEOUT);
    template<typename Container> bool send(const uint8_t cmd, Container param, TickType_t timeout = PN532_DEFAULT_TIMEOUT);
    bool wait_ack(TickType_t timeout = 1000/portTICK_PERIOD_MS);
    bool send_ack(bool ack=true, TickType_t timeout = 1000/portTICK_PERIOD_MS);
    template<typename Iter> bool fill_buffer(Iter first, Iter last, TickType_t timeout = 1000/portTICK_PERIOD_MS);


};

/// TEMPLATE IMPLEMENTATION


template<typename Iter>
bool HSU::fill_buffer(Iter first, Iter last, TickType_t timeout)
{
    BaseType_t tWrite = xTaskGetTickCount();
    size_t received = 0;
    auto to_copy = std::distance(first,last);
    std::vector<uint8_t> buffer;
    buffer.reserve(to_copy);

    while( received < to_copy){
        if(xTaskGetTickCount() - tWrite > timeout){
            ESP_LOGE(PN532_LOG, "NO message received before timeout");
            return false;
        }
        uart_get_buffered_data_len(device, &received);
        vTaskDelay(10/portTICK_PERIOD_MS);
    }

    if(uart_read_bytes(device, buffer.data(), to_copy, timeout - xTaskGetTickCount() + tWrite) < to_copy)
    {
        ESP_LOGE(PN532_LOG, "Data copy failed");
        return false;

    }

    std::copy(buffer.begin(), buffer.begin() + to_copy, first);
    // ESP_LOGE(PN532_LOG, "COPIED DATA");
    // ESP_LOG_BUFFER_HEX_LEVEL(PN532_LOG, &*first, to_copy, ESP_LOG_ERROR);
    return true;
}

template<typename Container>
bool HSU::receive(Container &data, TickType_t timeout)
{
    std::array<uint8_t, 3> preamble = {PN532_PREAMBLE, PN532_STARTCODE1, PN532_STARTCODE2};
    data.clear();
    data.reserve(256);
    data.resize(5);
    BaseType_t tStart = xTaskGetTickCount();

    if(! fill_buffer(data.begin(),data.begin() + 5, timeout - xTaskGetTickCount() + tStart))
    {
        ESP_LOGE(PN532_LOG, "No Preamble found before timeout");
        return false;
    }
    // ESP_LOGE(PN532_LOG, "Preable found");
    if(! std::equal(data.begin(), data.begin() + preamble.size(), preamble.begin()))
    {
        ESP_LOGE(PN532_LOG, "Message doesn't start with the expected preable");
        ESP_LOGE(PN532_LOG, "%#02x %#02x %#02x",data[0],data[1],data[2]);
        // ESP_LOG_BUFFER_HEX_LEVEL(PN532_LOG,data.data(), data.size(), ESP_LOG_ERROR);
        return false;
    }
    // SIZE compute_checksum
    if(((data.at(3) + data.at(4)) & 0xFF) != 0x00)
    {
        ESP_LOGE(PN532_LOG, "Size compute_checksum failed, sum: %d, %d", data[3] ,data[4]);
        return false;
    }
    // ESP_LOGE(PN532_LOG, "Correct compute_checksum");
    data.resize(data[3]+7);

    if(! fill_buffer(data.begin() + 5 ,data.begin() + data[3] + 7, timeout - xTaskGetTickCount() + tStart))
    {
        ESP_LOGE(PN532_LOG, "mwssage isn't arrived before timeout");
        return false;
    }

    // DATA compute_checksum
    // TFI + DATA + compute_checksum = 0x00
    const uint32_t data_checksum = std::accumulate(data.begin() + 5, data.end(),0);

    ESP_LOG_BUFFER_HEX_LEVEL(PN532_LOG_RECEIVED_DATA, data.data(), data.size(), ESP_LOG_ERROR);
    if((data_checksum & 0xFF) != 0x00)
    {
        ESP_LOGE(PN532_LOG, "Data compute_checksum failed: %d", (data_checksum & 0xFF));
        return false;
    }
    if(data.back() != 0x00)
    {
        ESP_LOGE(PN532_LOG, "No postamble received");
        return false;
    }

    // Trim message
    data.pop_back();
    data.pop_back();
    data.erase(data.begin(),data.begin()+6);
    return true;
}

template<typename Container>
bool HSU::send(const uint8_t cmd, Container param, TickType_t timeout)
{
    std::vector<uint8_t> buffer = {
            PN532_PREAMBLE,
            PN532_STARTCODE1,
            PN532_STARTCODE2,
            static_cast<uint8_t>(param.size() + 2),
            static_cast<uint8_t>(~(param.size() + 2) + 1),
            PN532_HOSTTOPN532,
    };

    buffer.reserve(1 + param.size() + 8);
    buffer.push_back(cmd);
    buffer.insert(buffer.end(), param.begin(), param.end());


    // uint8_t compute_checksum = PN532_PREAMBLE + PN532_STARTCODE1 + PN532_STARTCODE2 + PN532_HOSTTOPN532 + cmd;
    // for (auto value: param)
    //     compute_checksum += value & 0xFF;

    const uint8_t checksum  = std::accumulate(param.begin(), param.end(), PN532_PREAMBLE + PN532_STARTCODE1 + PN532_STARTCODE2 + PN532_HOSTTOPN532 + cmd);

    buffer.push_back(~checksum & 0xFF);
    buffer.push_back(PN532_POSTAMBLE);

    // flush the RX buffer
    uart_flush_input(device);

    // write and block until transmission is finished (or timeout time expired)
    uart_write_bytes(device, (const char*) buffer.data(), buffer.size());
    ESP_LOG_BUFFER_HEX_LEVEL(PN532_LOG_SENT_DATA, buffer.data(), buffer.size(), ESP_LOG_ERROR);
    //return uart_wait_tx_done(device, timeout);
    return true;
}


#endif