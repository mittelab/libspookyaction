#include "hsu.hpp"
#include <vector>
#include <array>
#include <numeric>
#define PN532_DEFAULT_TIMEOUT (1000/portTICK_PERIOD_MS)



HSU::HSU(uart_port_t port)
{
    device = port;
}

bool HSU::wake_up(TickType_t timeout)
{
    std::array<uint8_t, 5> wake= {0x55, 0x55, 0x00, 0x00, 0x00};
    return uart_write_bytes(device, (const char *) wake.data(), wake.size()) == wake.size();
}

// template<typename Container>
// bool HSU::receive(Container &data, TickType_t timeout)
// {
//     std::array<uint8_t, 3> preamble = {PN532_PREAMBLE, PN532_STARTCODE1, PN532_STARTCODE2};
//     std::vector<uint8_t> message_buffer;
//     message_buffer.reserve(256);
//     message_buffer.resize(5);
//     BaseType_t tStart = xTaskGetTickCount();

//     if(! fill_buffer(message_buffer.begin(),message_buffer.begin() + 5, timeout - xTaskGetTickCount() + tStart))
//     {
//         ESP_LOGE(PN532_LOG, "No Preamble found before timeout");
//         return false;
//     }
//     // ESP_LOGE(PN532_LOG, "Preable found");
//     if(! std::equal(message_buffer.begin(), message_buffer.begin() + preamble.size(), preamble.begin()))
//     {
//         ESP_LOGE(PN532_LOG, "Message doesn't start with the expected preable");
//         ESP_LOGE(PN532_LOG, "%#02x %#02x %#02x",message_buffer[0],message_buffer[1],message_buffer[2]);
//         // ESP_LOG_BUFFER_HEX_LEVEL(PN532_LOG,message_buffer.data(), message_buffer.size(), ESP_LOG_ERROR);
//         return false;
//     }
//     // SIZE compute_checksum
//     if(((message_buffer[3] + message_buffer[4]) & 0xFF) != 0x00)
//     {
//         ESP_LOGE(PN532_LOG, "Size compute_checksum failed, sum: %d, %d", message_buffer[3] ,message_buffer[4]);
//         return false;
//     }
//     // ESP_LOGE(PN532_LOG, "Correct compute_checksum");
//     message_buffer.resize(message_buffer[3]+7);

//     if(! fill_buffer(message_buffer.begin() + 5 ,message_buffer.begin() + message_buffer[3] + 7, timeout - xTaskGetTickCount() + tStart))
//     {
//         ESP_LOGE(PN532_LOG, "mwssage isn't arrived before timeout");
//         return false;
//     }

//     // DATA compute_checksum
//     // TFI + DATA + compute_checksum = 0x00
//     const uint32_t data_checksum = std::accumulate(message_buffer.begin() + 5, message_buffer.end(),0);

//     ESP_LOG_BUFFER_HEX_LEVEL(PN532_LOG_RECEIVED_DATA, message_buffer.data(), message_buffer.size(), ESP_LOG_ERROR);
//     if((data_checksum & 0xFF) != 0x00)
//     {
//         ESP_LOGE(PN532_LOG, "Data compute_checksum failed: %d", (data_checksum & 0xFF));
//         return false;
//     }
//     data.resize(message_buffer[3] - 1);
//     // Return the message
//     std::copy(message_buffer.begin() + 6, message_buffer.end() - 2, data.begin());
//     return true;
// }

bool HSU::wait_ack(TickType_t timeout)
{
    std::array<uint8_t, 6> ackbuff;
    std::array<uint8_t, 6> ack_message = PN532_ACK;

    ESP_LOGD(PN532_LOG, "waiting for ACK");


    if(!fill_buffer(ackbuff.begin(),ackbuff.begin() + 6,timeout))
        return false;

    if(ack_message == ackbuff)
    {
        ESP_LOGI(PN532_LOG_RECEIVED_DATA, "ACK");
        ESP_LOGD(PN532_LOG, "Received ACK");
        return true;
    }

    return false;
}

bool HSU::send_ack(bool ack, TickType_t timeout)
{
    std::array<uint8_t, 6> frame = ack? PN532_ACK : PN532_NACK;

    // write and block until transmission is finished (or timeout time expired)
    uart_write_bytes(device, (const char *)frame.data(), frame.size());
    ESP_LOGI(PN532_LOG_SENT_DATA, "ACK");
    return true;
}