//
// Created by Pietro Saccardi on 21/12/2020.
//


#include <esp_log.h>
#include "pn532/log.h"
#include "pn532/hsu.hpp"

#define PN532_HSU_SEND_TAG "PN532-HSU >>"
#define PN532_HSU_RECV_TAG "PN532-HSU <<"

namespace pn532 {

    namespace {
        TickType_t duration_cast(std::chrono::milliseconds ms) {
            return ms.count() / portTICK_PERIOD_MS;
        }
    }

    bool hsu::wake() {
        reduce_timeout rt{ms{100}};
        // One 0x55 would be enough but I always snooze at least twice, so...
        if (not send_raw({0x55, 0x55, 0x55}, rt.remaining())) {
            return false;
        }
        return true;  // Assume awake
    }

    bool hsu::prepare_receive(std::chrono::milliseconds) {
        return true;
    }

    bool hsu::send_raw(const bin_data &data, std::chrono::milliseconds timeout) {
        reduce_timeout rt{timeout};
        // Flush RX buffer
        uart_flush_input(_port);
        // Send and block until transmission is finished (or timeout time expired)
        uart_write_bytes(_port, reinterpret_cast<const char *>(data.data()), data.size());
        ESP_LOG_BUFFER_HEX_LEVEL(PN532_HSU_SEND_TAG, data.data(), data.size(), ESP_LOG_VERBOSE);
        const auto result = uart_wait_tx_done(_port, duration_cast(rt.remaining()));
        if (result == ESP_OK) {
            return true;
        } else if (result == ESP_FAIL) {
            PN532_LOGE("Failure to send data via HSU, parameter error (port = %d).", static_cast<int>(_port));
        } else if (result != ESP_ERR_TIMEOUT) {
            PN532_LOGE("Unexpected result from uart_wait_tx_done: %d.", static_cast<int>(result));
        }
        // Timeout or error
        return false;
    }

    bool hsu::receive_raw(bin_data &data, const std::size_t length, std::chrono::milliseconds timeout) {
        data.resize(length);
        reduce_timeout rt{timeout};
        std::size_t read_length = 0;
        while (read_length < length and rt) {
            std::size_t buffer_length = 0;
            if (uart_get_buffered_data_len(_port, &buffer_length) != ESP_OK) {
                PN532_LOGE("Error when getting buffered data at uart %d.", static_cast<int>(_port));
            }
            if (buffer_length == 0) {
                // Wait a bit before retrying
                vTaskDelay(duration_cast(std::chrono::milliseconds{10}));
            } else {
                buffer_length = std::min(buffer_length, length - read_length);
                const auto n_bytes = uart_read_bytes(_port,
                                                     data.data() + read_length,
                                                     buffer_length, duration_cast(rt.remaining()));
                if (n_bytes < 0) {
                    PN532_LOGE("Failed to read %u bytes from uart %d.", buffer_length, static_cast<int>(_port));
                } else {
                    read_length += n_bytes;
                    if (n_bytes != buffer_length) {
                        PN532_LOGW("Read only %u bytes out of %u in uart %d.", n_bytes, buffer_length,
                             static_cast<int>(_port));
                    }
                }
            }
        }
        data.resize(read_length);
        ESP_LOG_BUFFER_HEX_LEVEL(PN532_HSU_RECV_TAG, data.data(), read_length, ESP_LOG_VERBOSE);
        return read_length >= length;
    }
}