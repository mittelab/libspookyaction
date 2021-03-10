//
// Created by Pietro Saccardi on 21/12/2020.
//


#include "pn532/hsu.hpp"
#include "pn532/log.h"

#define PN532_HSU_SEND_TAG "PN532-HSU >>"
#define PN532_HSU_RECV_TAG "PN532-HSU <<"

namespace pn532 {

    using namespace std::chrono_literals;

    namespace {
        [[nodiscard]] TickType_t duration_cast(std::chrono::milliseconds ms) {
            return pdMS_TO_TICKS(ms.count());
        }
    }// namespace


    bool hsu_channel::wake() {
        if (comm_operation op{*this, comm_mode::send, 100ms}; op.ok()) {
            // One 0x55 would be enough but I always snooze at least twice, so...
            static const bin_data wake_cmd = {0x55, 0x55, 0x55};
            return bool(op.update(raw_send(wake_cmd.view(), 100ms)));
        }
        return false;
    }

    bool hsu_channel::on_send_prepare(ms timeout) {
        // Flush RX buffer
        return uart_flush_input(_port) == ESP_OK;
    }

    channel::r<> hsu_channel::raw_send(mlab::range<bin_data::const_iterator> const &buffer, ms timeout) {
        reduce_timeout rt{timeout};
        ESP_LOG_BUFFER_HEX_LEVEL(PN532_HSU_SEND_TAG, buffer.data(), buffer.size(), ESP_LOG_VERBOSE);
        // Send and block until transmission is finished (or timeout time expired)
        if (uart_write_bytes(_port, reinterpret_cast<const char *>(buffer.data()), buffer.size()) != buffer.size()) {
            PN532_LOGE("Failure to send data via HSU, parameter error at at uart_write_bytes (port = %d).", static_cast<int>(_port));
            return error::comm_error;
        }
        const auto result = uart_wait_tx_done(_port, duration_cast(rt.remaining()));
        if (result == ESP_OK) {
            return mlab::result_success;
        } else if (result == ESP_ERR_TIMEOUT) {
            PN532_LOGE("Failure to send data via HSU, timeout at uart_wait_tx_done (port = %d).", static_cast<int>(_port));
            return error::comm_timeout;
        }
        if (result == ESP_FAIL) {
            PN532_LOGE("Failure to send data via HSU, parameter error (port = %d).", static_cast<int>(_port));
        } else {
            PN532_LOGE("Unexpected result from uart_wait_tx_done: %d.", static_cast<int>(result));
        }
        return error::comm_error;
    }

    channel::r<> hsu_channel::raw_receive(mlab::range<bin_data::iterator> const &buffer, ms timeout) {
        reduce_timeout rt{timeout};
        std::size_t read_length = 0;
        while (read_length < buffer.size() and rt) {
            std::size_t buffer_length = 0;
            if (uart_get_buffered_data_len(_port, &buffer_length) != ESP_OK) {
                PN532_LOGE("Error when getting buffered data at uart %d.", static_cast<int>(_port));
            }
            if (buffer_length == 0) {
                // Wait a bit before retrying
                vTaskDelay(duration_cast(10ms));
            } else {
                buffer_length = std::min(buffer_length, buffer.size() - read_length);
                const auto n_bytes = uart_read_bytes(_port,
                                                     buffer.data() + read_length,
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
        ESP_LOG_BUFFER_HEX_LEVEL(PN532_HSU_RECV_TAG, buffer.data(), read_length, ESP_LOG_VERBOSE);
        if (read_length >= buffer.size()) {
            return mlab::result_success;
        }
        return error::comm_timeout;
    }


}// namespace pn532