//
// Created by spak on 2/19/21.
//


#include <memory>
#include <pn532/esp32/i2c.hpp>

#define PN532_I2C_TAG "PN532-I2C"

namespace pn532::esp32 {
    using namespace std::chrono_literals;


    namespace {
        using mlab::prealloc;

        [[nodiscard]] TickType_t duration_cast(std::chrono::milliseconds ms) {
            return pdMS_TO_TICKS(ms.count());
        }

        constexpr std::size_t i2c_driver_buffer_size = 384;
        constexpr std::size_t i2c_driver_timeout = 200000 /* apx 2.5ms */;
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
                ESP_ERROR_CHECK_WITHOUT_ABORT(i2c_master_write_byte(_handle, b, enable_ack_check));
            }
        }


        void command::write(mlab::range<const uint8_t *> data, bool enable_ack_check) {
            if (assert_unused()) {
                ESP_ERROR_CHECK_WITHOUT_ABORT(i2c_master_write(_handle, const_cast<std::uint8_t *>(&*std::begin(data)), data.size(), enable_ack_check));
            }
        }

        void command::read(mlab::range<uint8_t *> buffer, i2c_ack_type_t ack) {
            if (assert_unused()) {
                ESP_ERROR_CHECK_WITHOUT_ABORT(i2c_master_read(_handle, &*std::begin(buffer), buffer.size(), ack));
            }
        }

        void command::read(std::uint8_t &b, i2c_ack_type_t ack) {
            if (assert_unused()) {
                ESP_ERROR_CHECK_WITHOUT_ABORT(i2c_master_read_byte(_handle, &b, ack));
            }
        }

        void command::stop() {
            if (assert_unused()) {
                ESP_ERROR_CHECK_WITHOUT_ABORT(i2c_master_stop(_handle));
            }
        }

        mlab::result<error> command::operator()(i2c_port_t port, std::chrono::milliseconds timeout) {
            _used = true;
            if (const auto res = i2c_master_cmd_begin(port, _handle, duration_cast(timeout)); res != ESP_OK) {
                ESP_LOGE(PN532_I2C_TAG, "i2c_master_cmd_begin failed with status %d (%s).", res, esp_err_to_name(res));
                return static_cast<error>(res);
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

    channel::result<> i2c_channel::raw_send(mlab::range<bin_data::const_iterator> buffer, ms timeout) {
        if (_port == I2C_NUM_MAX) {
            return error::comm_error;
        }
        ESP_LOG_BUFFER_HEX_LEVEL(PN532_I2C_TAG " >>", buffer.data(), buffer.size(), ESP_LOG_VERBOSE);
        auto cmd = raw_prepare_command(comm_mode::send);
        if (buffer.size() > 0) {
            cmd.write({&*std::begin(buffer), &*std::begin(buffer) + buffer.size()}, true);
        }
        cmd.stop();
        if (const auto res_cmd = cmd(_port, timeout); not res_cmd) {
            ESP_LOGE(PN532_I2C_TAG, "Send failed: %s", i2c::to_string(res_cmd.error()));
            return error_from_i2c_error(res_cmd.error());
        }
        return mlab::result_success;
    }

    channel::result<> i2c_channel::raw_receive(mlab::range<bin_data::iterator> buffer, ms timeout) {
        if (_port == I2C_NUM_MAX) {
            return error::comm_error;
        }
        reduce_timeout rt{timeout};
        std::uint8_t ready_byte = 0x00;
        while (rt and (ready_byte & 0b1) == 0) {
            auto cmd = raw_prepare_command(comm_mode::receive);
            if (buffer.size() > 0) {
                cmd.read(ready_byte, I2C_MASTER_ACK);
                cmd.read({&*std::begin(buffer), &*std::begin(buffer) + buffer.size()}, I2C_MASTER_LAST_NACK);
            } else {
                // Read the ready byte only
                cmd.read(ready_byte, I2C_MASTER_LAST_NACK);
            }
            cmd.stop();
            if (const auto res_cmd = cmd(_port, timeout); not res_cmd) {
                ESP_LOGE(PN532_I2C_TAG, "Receive failed: %s", i2c::to_string(res_cmd.error()));
                return error_from_i2c_error(res_cmd.error());
            } else if ((ready_byte & 0b1) != 0) {
                // Everything alright
                ESP_LOG_BUFFER_HEX_LEVEL(PN532_I2C_TAG " <<", buffer.data(), buffer.size(), ESP_LOG_VERBOSE);
                return mlab::result_success;
            }
            // Wait a bit
            vTaskDelay(duration_cast(10ms));
        }
        return error::comm_timeout;
    }


    i2c_channel::i2c_channel(i2c_port_t port, i2c_config_t config, std::uint8_t slave_address, mlab::shared_buffer_pool buffer_pool)
        : channel{std::move(buffer_pool)}, _port{port}, _slave_addr{slave_address}, _irq_assert{} {
        if (const auto res = i2c_param_config(port, &config); res != ESP_OK) {
            ESP_LOGE(PN532_I2C_TAG, "i2c_param_config failed, return code %d (%s).", res, esp_err_to_name(res));
            _port = I2C_NUM_MAX;
            return;
        }
        if (const auto res = i2c_driver_install(port, I2C_MODE_MASTER, i2c_driver_buffer_size, i2c_driver_buffer_size, 0); res != ESP_OK) {
            ESP_LOGE(PN532_I2C_TAG, "i2c_driver_install failed, return code %d (%s).", res, esp_err_to_name(res));
            _port = I2C_NUM_MAX;
            return;
        }
        ESP_ERROR_CHECK_WITHOUT_ABORT(i2c_set_timeout(port, i2c_driver_timeout));
    }

    i2c_channel::i2c_channel(i2c_port_t port, i2c_config_t config, gpio_num_t response_irq_line, bool manage_isr_service,
                             std::uint8_t slave_address, mlab::shared_buffer_pool buffer_pool)
        : i2c_channel{port, config, slave_address, std::move(buffer_pool)} {
        // Prepare the IRQ assertion too
        _irq_assert = irq_assert{manage_isr_service, response_irq_line, GPIO_INTR_NEGEDGE};
    }

    i2c_channel::~i2c_channel() {
        if (_port != I2C_NUM_MAX) {
            ESP_ERROR_CHECK_WITHOUT_ABORT(i2c_driver_delete(_port));
        }
    }

    bool i2c_channel::wake() {
        if (comm_operation op{*this, comm_mode::send, 100ms}; op.ok()) {
            return bool(op.update(raw_send({}, 10ms)));
        } else {
            return false;
        }
    }


    bool i2c_channel::on_receive_prepare(ms timeout) {
        return _irq_assert(timeout);
    }

}// namespace pn532::esp32
