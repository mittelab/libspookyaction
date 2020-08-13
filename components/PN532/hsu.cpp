#include "pn532.hpp"
#include <vector>
#include <array>
#include <numeric>
#define PN532_DEFAULT_TIMEOUT (1000/portTICK_PERIOD_MS)



HSU::HSU(uart_port_t port)
{
    device = port;
}

int HSU::wake_up(TickType_t timeout)
{
    std::array<uint8_t, 5> wake= {0x55, 0x55, 0x00, 0x00, 0x00};
    return uart_write_bytes(device, (const char *) wake.data(), wake.size());
}

int HSU::receive(std::vector<uint8_t> &data, TickType_t timeout)
{
    uint8_t preamble[] = {PN532_PREAMBLE, PN532_STARTCODE1, PN532_STARTCODE2};
    std::vector<uint8_t> message_buffer;
    message_buffer.reserve(data.size() + 7);
    size_t size=0;
    BaseType_t tWrite = xTaskGetTickCount();

    //wait until atlest until the size is know
    while( size < 5){
        if(xTaskGetTickCount() - tWrite > timeout){
            ESP_LOGE(PN532_LOG, "NO message received before timeout");
            return ESP_FAIL;
        }
        uart_get_buffered_data_len(device, &size);
        vTaskDelay(10/portTICK_PERIOD_MS);
    }
    uart_read_bytes(device, message_buffer.data(), message_buffer.size(), timeout);

    if(memcmp(message_buffer.data(), preamble, sizeof(preamble)) != 0)
    {
        ESP_LOGE(PN532_LOG, "Message doesn't start with the expected preable");
        ESP_LOG_BUFFER_HEXDUMP(PN532_LOG,message_buffer.data(), message_buffer.size(), ESP_LOG_ERROR);
        return ESP_FAIL;
    }

    ESP_LOGD(PN532_LOG, "Message received");

    // SIZE checksum
    if(((message_buffer[3] + message_buffer[4]) & 0xFF) != 0x00)
    {
        ESP_LOGE(PN532_LOG, "Size checksum failed");
        ESP_LOG_BUFFER_HEXDUMP(PN532_LOG,message_buffer.data(), message_buffer.size(), ESP_LOG_ERROR);
        return ESP_FAIL;
    }

    // check if the buffer buffer is large enough
    if(message_buffer.size() < message_buffer[3] - 1)
    {
        ESP_LOGE(PN532_LOG, "Buffer[size %d] is smaller than the received message[size:%d]", message_buffer.size(), message_buffer[3] - 1);
        return ESP_FAIL;
    }

    // wait the rest of the message
    while(size < message_buffer[3] + 7){
        if(xTaskGetTickCount() - tWrite > timeout){
            ESP_LOGE(PN532_LOG, "Partial message received before timeout");
            return ESP_FAIL;
        }
        ESP_LOGE(PN532_LOG, "waiting for: %d Bytes ", message_buffer[3] + 7 - size);
        uart_get_buffered_data_len(device, &size);
        vTaskDelay(10/portTICK_PERIOD_MS);
    }

    // DATA checksum
    // TFI + DATA + checksum = 0x00
    const uint8_t data_checksum = std::accumulate(message_buffer.begin() + 5, message_buffer.begin() + 5 + message_buffer[3], 0);

    if((data_checksum & 0xFF) != 0x00)
    {
        ESP_LOGE(PN532_LOG, "Data checksum failed: %d", (data_checksum & 0xFF));
        ESP_LOG_BUFFER_HEXDUMP(PN532_LOG, message_buffer.data(), message_buffer.size(), ESP_LOG_ERROR);
        return ESP_FAIL;
    }

    // Return the message
    std::copy(message_buffer.begin() + 6, message_buffer.begin() + message_buffer[3] - 1, data.begin());
    uart_flush_input(device);
    ESP_LOG_BUFFER_HEX_LEVEL(PN532_LOG_RECEIVED_DATA, message_buffer.data(), message_buffer.size(), ESP_LOG_INFO);
    return ESP_OK;
}

int HSU::send(const uint8_t cmd, const std::vector<uint8_t> param, TickType_t timeout)
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
    uart_flush(device);

    // write and block until transmission is finished (or timeout time expired)
    uart_write_bytes(device, (const char*) buffer.data(), buffer.size());
    ESP_LOG_BUFFER_HEX_LEVEL(PN532_LOG_SENT_DATA, buffer.data(), buffer.size(), ESP_LOG_INFO);
    return uart_wait_tx_done(device, timeout);
}

int HSU::wait_ack(TickType_t timeout)
{
    std::array<uint8_t, 6> ackbuff;
    std::array<uint8_t, 6> ack_message = PN532_ACK;
    size_t size=0;
    BaseType_t tWrite = xTaskGetTickCount();
    ESP_LOGD(PN532_LOG, "waiting for ACK");
    while( size < 6 ){
        if(xTaskGetTickCount() - tWrite > timeout){
            ESP_LOGE(PN532_LOG, "NO ACK received");
            return ESP_FAIL;
        }
        uart_get_buffered_data_len(device, &size);
        vTaskDelay(10/portTICK_PERIOD_MS);
    }

    uart_read_bytes(device, ackbuff.data(), ackbuff.size(), xTaskGetTickCount() - tWrite);

    if(ack_message == ackbuff)
    {
        ESP_LOGI(PN532_LOG_RECEIVED_DATA, "ACK");
        ESP_LOGD(PN532_LOG, "Received ACK");
        return ESP_OK;
    }

    //uart_flush_input(port);

    return ESP_FAIL;
}

int HSU::send_ack(bool ack, TickType_t timeout)
{
    std::array<uint8_t, 6> frame = ack? PN532_ACK :  PN532_NACK;

    // flush the RX buffer
    uart_flush(device);

    // write and block until transmission is finished (or timeout time expired)
    uart_write_bytes(device, (const char *)frame.data(), frame.size());
    return uart_wait_tx_done(device, timeout);
}