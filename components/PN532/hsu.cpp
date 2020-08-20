#include "pn532.hpp"
#include <vector>
#include <array>
#include <numeric>
#define PN532_DEFAULT_TIMEOUT (1000/portTICK_PERIOD_MS)



HSU::HSU(uart_port_t port)
{
    device = port;
}

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

int HSU::wake_up(TickType_t timeout)
{
    std::array<uint8_t, 5> wake= {0x55, 0x55, 0x00, 0x00, 0x00};
    return uart_write_bytes(device, (const char *) wake.data(), wake.size());
}

template<typename Container>
int HSU::receive(Container &data, TickType_t timeout)
{
    std::array<uint8_t, 3> preamble = {PN532_PREAMBLE, PN532_STARTCODE1, PN532_STARTCODE2};
    std::vector<uint8_t> message_buffer;
    message_buffer.reserve(256);
    message_buffer.resize(5);
    BaseType_t tWrite = xTaskGetTickCount();

    if(! fill_buffer(message_buffer.begin(),message_buffer.begin() + 5, timeout))
    {
        ESP_LOGE(PN532_LOG, "No Preamble found before timeout");
        return ESP_FAIL;
    }
    // ESP_LOGE(PN532_LOG, "Preable found");
    if(! std::equal(message_buffer.begin(), message_buffer.begin() + preamble.size(),preamble.begin()))
    {
        ESP_LOGE(PN532_LOG, "Message doesn't start with the expected preable");
        ESP_LOGE(PN532_LOG, "%#02x %#02x %#02x",message_buffer[0],message_buffer[1],message_buffer[2]);
        // ESP_LOG_BUFFER_HEX_LEVEL(PN532_LOG,message_buffer.data(), message_buffer.size(), ESP_LOG_ERROR);
        return ESP_FAIL;
    }
    // SIZE checksum
    if(((message_buffer[3] + message_buffer[4]) & 0xFF) != 0x00)
    {
        ESP_LOGE(PN532_LOG, "Size checksum failed, sum: %d, %d", message_buffer[3] ,message_buffer[4]);
        return ESP_FAIL;
    }
    // ESP_LOGE(PN532_LOG, "Correct checksum");
    message_buffer.resize(message_buffer[3]+7);

    if(! fill_buffer(message_buffer.begin() + 5 ,message_buffer.begin() + message_buffer[3] + 7, timeout))
    {
        ESP_LOGE(PN532_LOG, "mwssage isn't arrived before timeout");
        return ESP_FAIL;
    }
    
    // DATA checksum
    // TFI + DATA + checksum = 0x00
    const uint32_t data_checksum = std::accumulate(message_buffer.begin() + 5, message_buffer.end(),0);

    ESP_LOG_BUFFER_HEX_LEVEL(PN532_LOG_RECEIVED_DATA, message_buffer.data(), message_buffer.size(), ESP_LOG_ERROR);
    if((data_checksum & 0xFF) != 0x00)
    {
        ESP_LOGE(PN532_LOG, "Data checksum failed: %d", (data_checksum & 0xFF));
        return ESP_FAIL;
    }
    data.resize(message_buffer[3] - 1);
    // Return the message
    std::copy(message_buffer.begin() + 6, message_buffer.end() - 2, data.begin());
    return ESP_OK;
}

template<typename Container>
int HSU::send(const uint8_t cmd, Container param, TickType_t timeout)
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
    buffer.insert(buffer.end(), cmd);
    buffer.insert(buffer.end(), param.begin(), param.end());


    uint8_t checksum = PN532_PREAMBLE + PN532_STARTCODE1 + PN532_STARTCODE2 + PN532_HOSTTOPN532 + cmd;

    for (auto value: param)
        checksum += value & 0xFF;

    buffer.push_back(~checksum);
    buffer.push_back(PN532_POSTAMBLE);

    // flush the RX buffer
    uart_flush_input(device);

    // write and block until transmission is finished (or timeout time expired)
    uart_write_bytes(device, (const char*) buffer.data(), buffer.size());
    ESP_LOG_BUFFER_HEX_LEVEL(PN532_LOG_SENT_DATA, buffer.data(), buffer.size(), ESP_LOG_ERROR);
    //return uart_wait_tx_done(device, timeout);
    return ESP_OK;
}

int HSU::wait_ack(TickType_t timeout)
{
    std::array<uint8_t, 6> ackbuff;
    std::array<uint8_t, 6> ack_message = PN532_ACK;

    ESP_LOGD(PN532_LOG, "waiting for ACK");


    if(!fill_buffer(ackbuff.begin(),ackbuff.begin() + 6,timeout))
        return ESP_FAIL;

    if(ack_message == ackbuff)
    {
        ESP_LOGI(PN532_LOG_RECEIVED_DATA, "ACK");
        ESP_LOGD(PN532_LOG, "Received ACK");
        return ESP_OK;
    }

    return ESP_FAIL;
}

int HSU::send_ack(bool ack, TickType_t timeout)
{
    std::array<uint8_t, 6> frame = ack? PN532_ACK : PN532_NACK;

    // write and block until transmission is finished (or timeout time expired)
    uart_write_bytes(device, (const char *)frame.data(), frame.size());
    return ESP_OK;
}