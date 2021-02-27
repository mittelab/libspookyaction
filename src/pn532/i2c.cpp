//
// Created by spak on 2/19/21.
//


#include "pn532/i2c.hpp"
#include <memory>

#define PN532_I2C_TAG "PN532-I2C"

namespace pn532 {


    namespace {
        using mlab::prealloc;

        [[nodiscard]] TickType_t duration_cast(std::chrono::milliseconds ms) {
            return pdMS_TO_TICKS(ms.count());
        }

    }// namespace

    namespace i2c {
        [[nodiscard]] const char *to_string(error e) {
            switch (e) {
                case error::parameter_error:
                    return "parameter error";
                case error::fail:
                    return "fail";
                case error::invalid_state:
                    return "invalid state";
                case error::timeout:
                    return "timeout";
            }
            return "UNKNOWN";
        }

        bool command::assert_unused() const {
            if (_used) {
                ESP_LOGE(PN532_I2C_TAG, "This command was already run and cannot be reused.");
                return false;
            }
            return true;
        }

        command::command() : _handle{i2c_cmd_link_create()}, _used{false} {
            i2c_master_start(_handle);
        }

        command::~command() {
            i2c_cmd_link_delete(_handle);
        }

        void command::write_byte(std::uint8_t b, bool enable_ack_check) {
            if (assert_unused()) {
                if (i2c_master_write_byte(_handle, b, enable_ack_check) != ESP_OK) {
                    ESP_LOGE(PN532_I2C_TAG, "i2c_master_write_byte failed.");
                }
            }
        }

        void command::write(bin_data const &data, bool enable_ack_check) {
            if (assert_unused()) {
                if (i2c_master_write(_handle, const_cast<std::uint8_t *>(data.data()), data.size(), enable_ack_check) != ESP_OK) {
                    ESP_LOGE(PN532_I2C_TAG, "i2c_master_write failed.");
                }
            }
        }

        void command::read_into(bin_data &bd, i2c_ack_type_t ack) {
            if (assert_unused()) {
                if (i2c_master_read(_handle, bd.data(), bd.size(), ack) != ESP_OK) {
                    ESP_LOGE(PN532_I2C_TAG, "i2c_master_read failed.");
                }
            }
        }

        void command::read_into(std::uint8_t &b, i2c_ack_type_t ack) {
            if (assert_unused()) {
                if (i2c_master_read_byte(_handle, &b, ack) != ESP_OK) {
                    ESP_LOGE(PN532_I2C_TAG, "i2c_master_read_byte failed.");
                }
            }
        }

        void command::stop() {
            if (assert_unused()) {
                if (i2c_master_stop(_handle) != ESP_OK) {
                    ESP_LOGE(PN532_I2C_TAG, "i2c_master_stop failed.");
                }
            }
        }

        mlab::result<error> command::operator()(i2c_port_t port, std::chrono::milliseconds timeout) {
            _used = true;
            if (const auto result_code = i2c_master_cmd_begin(port, _handle, duration_cast(timeout)); result_code != ESP_OK) {
                return static_cast<error>(result_code);
            }
            return mlab::result_success;
        }
    }// namespace i2c

    bool i2c_channel::wake() {
        reduce_timeout rt{ms{100}};
        // pn532 should be waken up when it hears its address on the I2C bus
        i2c::command cmd;
        std::uint8_t status = 0xff;
        cmd.write_byte(slave_address_to_read(), true);
        cmd.read_into(status, I2C_MASTER_LAST_NACK);
        cmd.stop();

        if (const auto res_cmd = cmd(_port, rt.remaining()); not res_cmd) {
            ESP_LOGE(PN532_I2C_TAG, "Wake failed: %s", i2c::to_string(res_cmd.error()));
            return false;
        }
        return true;
    }

    bool i2c_channel::prepare_receive(std::chrono::milliseconds timeout) {
        reduce_timeout rt{timeout};

        std::uint8_t status = 0x00;
        i2c::command cmd;
        cmd.write_byte(slave_address_to_read(), true);
        cmd.read_into(status, I2C_MASTER_LAST_NACK);
        cmd.stop();

        while (rt) {
            if (const auto res_cmd = cmd(_port, rt.remaining()); not res_cmd) {
                ESP_LOGE(PN532_I2C_TAG, "Prepare receive failed: %s", i2c::to_string(res_cmd.error()));
                return false;
            } else if (status != 0x00) {
                return true;
            }
            // Retry after 10 ms
            vTaskDelay(duration_cast(std::chrono::milliseconds{10}));
        }
        return false;// Timeout
    }

    bool i2c_channel::send_raw(const bin_data &data, std::chrono::milliseconds timeout) {
        reduce_timeout rt{timeout};
        i2c::command cmd;
        cmd.write_byte(slave_address_to_write(), true);
        cmd.write(data, true);
        cmd.stop();

        if (const auto res_cmd = cmd(_port, rt.remaining()); not res_cmd) {
            ESP_LOGE(PN532_I2C_TAG, "Send failed: %s", i2c::to_string(res_cmd.error()));
            return false;
        }
        return true;
    }

    bool i2c_channel::receive_raw(bin_data &data, const std::size_t length, std::chrono::milliseconds timeout) {
        reduce_timeout rt{timeout};
        data.clear();
        data.resize(length);

        i2c::command cmd;
        cmd.write_byte(slave_address_to_read(), true);
        cmd.read_into(data, I2C_MASTER_ACK);
        cmd.stop();

        if (const auto res_cmd = cmd(_port, rt.remaining()); not res_cmd) {
            ESP_LOGE(PN532_I2C_TAG, "Receive failed: %s", i2c::to_string(res_cmd.error()));
            return false;
        }
        return true;
    }
}// namespace pn532
