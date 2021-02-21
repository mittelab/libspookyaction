//
// Created by spak on 2/19/21.
//


#include "pn532/i2c.hpp"
#include <esp_log.h>
#include <memory>
#include <mlab/result.hpp>

#define PN532_I2C_TAG "PN532-I2C"

namespace pn532 {


    namespace {
        using mlab::prealloc;

        TickType_t duration_cast(std::chrono::milliseconds ms) {
            return ms.count() / portTICK_PERIOD_MS;
        }

    }// namespace

    namespace i2c {

        enum struct error : std::int16_t {
            parameter_error = ESP_ERR_INVALID_ARG,
            fail = ESP_FAIL,
            invalid_state = ESP_ERR_INVALID_STATE,
            timeout = ESP_ERR_TIMEOUT
        };

        const char *to_string(error e) {
            switch (e) {
                case error::parameter_error:
                    return "parameter error";
                case error::fail:
                    return "fail";
                case error::invalid_state:
                    return "invalid state";
                case error::timeout:
                    return "timeout";
                default:
                    return "UNKNOWN";
            }
        }

        class command {
            i2c_cmd_handle_t _handle;
            std::vector<bin_data> _buffers;
            bool _sealed;

            bool assert_not_sealed() const {
                if (_sealed) {
                    ESP_LOGE(PN532_I2C_TAG, "This command was already run and cannot be changed.");
                    return false;
                }
                return true;
            }

        public:
            command() : _handle{i2c_cmd_link_create()}, _buffers{}, _sealed{false} {
                i2c_master_start(_handle);
            }

            ~command() {
                i2c_cmd_link_delete(_handle);
            }
            command(command const &) = delete;
            command(command &&) noexcept = default;
            command &operator=(command const &) = delete;
            command &operator=(command &&) noexcept = default;

            void write_byte(std::uint8_t b, bool enable_ack_check) {
                if (assert_not_sealed()) {
                    if (i2c_master_write_byte(_handle, b, enable_ack_check) != ESP_OK) {
                        ESP_LOGE(PN532_I2C_TAG, "i2c_master_write_byte failed.");
                    }
                }
            }

            void write(bin_data const &data, bool enable_ack_check) {
                if (assert_not_sealed()) {
                    if (i2c_master_write(_handle, const_cast<std::uint8_t *>(data.data()), data.size(), enable_ack_check) != ESP_OK) {
                        ESP_LOGE(PN532_I2C_TAG, "i2c_master_write failed.");
                    }
                }
            }

            void read_into(bin_data &bd, i2c_ack_type_t ack) {
                if (assert_not_sealed()) {
                    if (i2c_master_read(_handle, bd.data(), bd.size(), ack) != ESP_OK) {
                        ESP_LOGE(PN532_I2C_TAG, "i2c_master_read failed.");
                    }
                }
            }

            void read_into(std::uint8_t &b, i2c_ack_type_t ack) {
                if (assert_not_sealed()) {
                    if (i2c_master_read_byte(_handle, &b, ack) != ESP_OK) {
                        ESP_LOGE(PN532_I2C_TAG, "i2c_master_read_byte failed.");
                    }
                }
            }

            void stop() {
                if (assert_not_sealed()) {
                    if (i2c_master_stop(_handle) != ESP_OK) {
                        ESP_LOGE(PN532_I2C_TAG, "i2c_master_stop failed.");
                    }
                }
            }

            mlab::result<error, void> operator()(i2c_port_t port, std::chrono::milliseconds timeout) {
                _sealed = true;
                const auto result_code = i2c_master_cmd_begin(port, _handle, duration_cast(timeout));
                if (result_code != ESP_OK) {
                    return static_cast<error>(result_code);
                }
                return mlab::result_success;
            }
        };
    }// namespace i2c

    bool i2c_channel::wake() {
        reduce_timeout rt{ms{100}};
        // pn532 should be waken up when it hears its address on the I2C bus
        i2c::command cmd;
        cmd.write_byte(slave_address_to_write(), true);
        cmd.stop();
        return bool(cmd(_port, rt.remaining()));
    }

    bool i2c_channel::prepare_receive(std::chrono::milliseconds timeout) {
        reduce_timeout rt{timeout};

        std::uint8_t status = 0x00;
        i2c::command cmd;
        cmd.write_byte(slave_address_to_read(), true);
        cmd.read_into(status, I2C_MASTER_LAST_NACK);
        cmd.stop();

        while (rt) {
            const auto res_resp = cmd(_port, rt.remaining());
            if (not res_resp) {
                ESP_LOGE(PN532_I2C_TAG, "Await receive failed: %s", i2c::to_string(res_resp.error()));
                return false;
            } else if (status != 0x00) {
                return true;
            }
            // Retry after 10 ms
            vTaskDelay(duration_cast(std::chrono::milliseconds{10}));
        };
        return false;// Timeout
    }

    bool i2c_channel::send_raw(const bin_data &data, std::chrono::milliseconds timeout) {
        reduce_timeout rt{timeout};
        i2c::command cmd;
        cmd.write_byte(slave_address_to_write(), true);
        cmd.write(data, true);
        cmd.stop();
        return bool(cmd(_port, rt.remaining()));
    }

    bool i2c_channel::receive_raw(bin_data &data, const std::size_t length, std::chrono::milliseconds timeout) {
        reduce_timeout rt{timeout};
        data.clear();
        data.resize(length);

        i2c::command cmd;
        cmd.read_into(data, I2C_MASTER_ACK);
        cmd.stop();
        return bool(cmd(_port, rt.remaining()));
    }
}// namespace pn532
