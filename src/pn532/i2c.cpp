//
// Created by spak on 2/19/21.
//


#include "pn532/i2c.hpp"
#include <memory>

#define PN532_I2C_TAG "PN532-I2C"

namespace pn532 {
    using namespace std::chrono_literals;


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

        void command::write(std::uint8_t b, bool enable_ack_check) {
            if (assert_unused()) {
                if (i2c_master_write_byte(_handle, b, enable_ack_check) != ESP_OK) {
                    ESP_LOGE(PN532_I2C_TAG, "i2c_master_write_byte failed.");
                }
            }
        }


        void command::write(mlab::range<bin_data::const_iterator> const &data, bool enable_ack_check) {
            if (assert_unused()) {
                if (i2c_master_write(_handle, const_cast<std::uint8_t *>(data.data()), data.size(), enable_ack_check) != ESP_OK) {
                    ESP_LOGE(PN532_I2C_TAG, "i2c_master_write failed.");
                }
            }
        }

        void command::read(mlab::range<bin_data::iterator> const &buffer, i2c_ack_type_t ack) {
            if (assert_unused()) {
                if (i2c_master_read(_handle, buffer.data(), buffer.size(), ack) != ESP_OK) {
                    ESP_LOGE(PN532_I2C_TAG, "i2c_master_read failed.");
                }
            }
        }

        void command::read(std::uint8_t &b, i2c_ack_type_t ack) {
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


    i2c::command i2c_channel::raw_prepare_command(comm_mode mode) const {
        i2c::command cmd;
        switch (mode) {
            case comm_mode::receive:
                cmd.write(slave_address_to_read(), true);
                break;
            case comm_mode::send:
                cmd.write(slave_address_to_write(), true);
                break;
            default:
                break;
        }
        return cmd;
    }

    channel::r<> i2c_channel::raw_send(mlab::range<bin_data::const_iterator> const &buffer, ms timeout) {
        auto cmd = raw_prepare_command(comm_mode::send);
        if (buffer.size() > 0) {
            cmd.write(buffer, true);
        }
        cmd.stop();
        if (const auto res_cmd = cmd(_port, timeout); not res_cmd) {
            ESP_LOGE(PN532_I2C_TAG, "Send failed: %s", i2c::to_string(res_cmd.error()));
            return error_from_i2c_error(res_cmd.error());
        }
        return mlab::result_success;
    }

    channel::r<> i2c_channel::raw_receive(mlab::range<bin_data::iterator> const &buffer, ms timeout) {
        std::uint8_t ready_byte = 0x00;
        auto cmd = raw_prepare_command(comm_mode::receive);
        if (buffer.size() > 0) {
            cmd.read(ready_byte, I2C_MASTER_ACK);
            cmd.read(buffer, I2C_MASTER_LAST_NACK);
        } else {
            // Read the ready byte only
            cmd.read(ready_byte, I2C_MASTER_LAST_NACK);
        }
        cmd.stop();
        if (const auto res_cmd = cmd(_port, timeout); not res_cmd) {
            ESP_LOGE(PN532_I2C_TAG, "Receive failed: %s", i2c::to_string(res_cmd.error()));
            return error_from_i2c_error(res_cmd.error());
        } else if (ready_byte == 0x00) {
            // The command is not yet ready
            ESP_LOGE(PN532_I2C_TAG, "Response not yet ready.");
            return error::comm_error;
        }
        return mlab::result_success;
    }

    bool i2c_channel::wake() {
        if (comm_operation op{*this, comm_mode::receive, 100ms}; op.ok()) {
            return bool(op.update(raw_receive({}, 10ms)));
        } else {
            return false;
        }
    }


    bool i2c_channel::on_receive_prepare(ms timeout) {
        // Poll the status byte
        reduce_timeout rt{timeout};
        std::uint8_t ready_byte = 0x00;
        // Poll the ready byte only, once it's ready, send a application-level nack to request resending
        while (rt and ready_byte == 0x00) {
            auto poll_cmd = raw_prepare_command(comm_mode::receive);
            // Read the ready byte only
            poll_cmd.read(ready_byte, I2C_MASTER_LAST_NACK);
            poll_cmd.stop();
            if (const auto res_poll = poll_cmd(_port, rt.remaining()); not res_poll) {
                ESP_LOGE(PN532_I2C_TAG, "Poll status failed: %s", i2c::to_string(res_poll.error()));
                return false;
            } else if (ready_byte == 0x00) {
                // Wait a bit before retrying
                vTaskDelay(duration_cast(10ms));
            }
        }
        if (ready_byte != 0x00) {
            // It's ready now, send an application level NACK to have the PN532 repeat the response
            static const bin_data nack_data = bin_data::chain(frame<frame_type::nack>{});
            auto nack_cmd = raw_prepare_command(comm_mode::send);
            nack_cmd.write(nack_data.view(), true);
            nack_cmd.stop();
            if (const auto res_nack = nack_cmd(_port, rt.remaining()); not res_nack) {
                ESP_LOGE(PN532_I2C_TAG, "Application-level NACK failed: %s", i2c::to_string(res_nack.error()));
                return false;
            }
            // Wait a bit
            vTaskDelay(duration_cast(10ms));
            // Ready to go
            return true;
        }
        return false;
    }

}// namespace pn532
