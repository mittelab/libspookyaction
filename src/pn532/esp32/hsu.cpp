//
// Created by Pietro Saccardi on 21/12/2020.
//


#include "pn532/esp32/hsu.hpp"
#include "pn532/log.h"

#define PN532_HSU_TAG "PN532-HSU"

namespace pn532::esp32 {

    using namespace std::chrono_literals;

    namespace {
        [[nodiscard]] TickType_t duration_cast(std::chrono::milliseconds ms) {
            return pdMS_TO_TICKS(ms.count());
        }

        constexpr std::size_t uart_driver_buffer_size = 384;
    }// namespace


    hsu_channel::hsu_channel(uart_port_t port, uart_config_t config, int to_device_tx, int to_device_rx) : _port{port} {
        if (const auto res = uart_param_config(port, &config); res != ESP_OK) {
            ESP_LOGE(PN532_HSU_TAG, "uart_param_config failed, return code %d (%s).", res, esp_err_to_name(res));
            _port = UART_NUM_MAX;
            return;
        }
        if (const auto res = uart_driver_install(port, uart_driver_buffer_size, uart_driver_buffer_size, 0, nullptr, 0); res != ESP_OK) {
            ESP_LOGE(PN532_HSU_TAG, "uart_driver_install failed, return code %d (%s).", res, esp_err_to_name(res));
            _port = UART_NUM_MAX;
            return;
        }
        /**
         * @note Yes, the device RX is the "local" TX.
         */
        if (const auto res = uart_set_pin(port, to_device_rx, to_device_tx, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE); res != ESP_OK) {
            ESP_LOGE(PN532_HSU_TAG, "uart_set_pin failed, return code %d (%s).", res, esp_err_to_name(res));
            _port = UART_NUM_MAX;
            return;
        }
    }

    hsu_channel::~hsu_channel() {
        if (_port != UART_NUM_MAX) {
            if (const auto res = uart_driver_delete(_port); res != ESP_OK) {
                ESP_LOGW(PN532_HSU_TAG, "uart_driver_delete failed, return code %d (%s).", res, esp_err_to_name(res));
            }
        }
    }

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

    channel::result<> hsu_channel::raw_send(mlab::range<bin_data::const_iterator> buffer, ms timeout) {
        if (_port == UART_NUM_MAX) {
            return error::comm_error;
        }
        reduce_timeout rt{timeout};
        ESP_LOG_BUFFER_HEX_LEVEL(PN532_HSU_TAG " >>", buffer.data(), buffer.size(), ESP_LOG_VERBOSE);
        // Send and block until transmission is finished (or timeout time expired)
        if (uart_write_bytes(_port, reinterpret_cast<const char *>(buffer.data()), buffer.size()) != buffer.size()) {
            ESP_LOGE(PN532_HSU_TAG, "Failure to send data via HSU, parameter error at at uart_write_bytes (port = %d).", static_cast<int>(_port));
            return error::comm_error;
        }
        const auto result = uart_wait_tx_done(_port, duration_cast(rt.remaining()));
        if (result == ESP_OK) {
            return mlab::result_success;
        } else if (result == ESP_ERR_TIMEOUT) {
            ESP_LOGE(PN532_HSU_TAG, "Failure to send data via HSU, timeout at uart_wait_tx_done (port = %d).", static_cast<int>(_port));
            return error::comm_timeout;
        }
        if (result == ESP_FAIL) {
            ESP_LOGE(PN532_HSU_TAG, "Failure to send data via HSU, parameter error (port = %d).", static_cast<int>(_port));
        } else {
            ESP_LOGE(PN532_HSU_TAG, "Unexpected result from uart_wait_tx_done: %d.", static_cast<int>(result));
        }
        return error::comm_error;
    }

    channel::result<> hsu_channel::raw_receive(mlab::range<bin_data::iterator> buffer, ms timeout) {
        if (_port == UART_NUM_MAX) {
            return error::comm_error;
        }
        reduce_timeout rt{timeout};
        std::size_t read_length = 0;
        while (read_length < buffer.size() and rt) {
            std::size_t buffer_length = 0;
            if (const auto res = uart_get_buffered_data_len(_port, &buffer_length); res != ESP_OK) {
                ESP_LOGE(PN532_HSU_TAG, "uart_get_buffered_data_len failed with status %d (%s).", res, esp_err_to_name(res));
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
                    ESP_LOGE(PN532_HSU_TAG, "Failed to read %u bytes from uart %d.", buffer_length, static_cast<int>(_port));
                } else {
                    read_length += n_bytes;
                    if (n_bytes != buffer_length) {
                        ESP_LOGW(PN532_HSU_TAG, "Read only %u bytes out of %u in uart %d.", n_bytes, buffer_length,
                                 static_cast<int>(_port));
                    }
                }
            }
        }
        ESP_LOG_BUFFER_HEX_LEVEL(PN532_HSU_TAG " <<", buffer.data(), read_length, ESP_LOG_VERBOSE);
        if (read_length >= buffer.size()) {
            return mlab::result_success;
        }
        return error::comm_timeout;
    }


}// namespace pn532::esp32