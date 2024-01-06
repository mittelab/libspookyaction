//
// Created by spak on 06/01/24.
//

#include <pn532/esp32/i2c.hpp>
#include <thread>

#define PN532_I2C_TAG "PN532-I2C"

namespace pn532::esp32 {
    namespace {

        using namespace std::chrono_literals;

        [[nodiscard]] result<> from_esp_error(esp_err_t err) {
            switch (err) {
                case ESP_OK:
                    return mlab::result_success;
                case ESP_ERR_TIMEOUT:
                    return channel_error::timeout;
                case ESP_ERR_INVALID_ARG:
                    return channel_error::malformed;
                default:
                    return channel_error::hw_error;
            }
        }

    }// namespace

    i2c_channel::i2c_channel(i2c_master_bus_config_t bus_config, i2c_device_config_t dev_config)
        : i2c_channel{} {
        ESP_ERROR_CHECK_WITHOUT_ABORT(i2c_new_master_bus(&bus_config, &_bus_handle));
        if (not _bus_handle) {
            return;
        }

        if (const auto res = i2c_master_bus_add_device(_bus_handle, &dev_config, &_dev_handle); res != ESP_OK) {
            ESP_LOGE(PN532_I2C_TAG, "i2c_master_bus_add_device failed, return code %d (%s).", res, esp_err_to_name(res));
            ESP_ERROR_CHECK_WITHOUT_ABORT(i2c_del_master_bus(_bus_handle));
            _bus_handle = nullptr;
            return;
        }
    }

    i2c_channel::i2c_channel(i2c_master_bus_config_t bus_config, gpio_num_t response_irq_line, bool manage_isr_service, i2c_device_config_t dev_config)
        : i2c_channel{bus_config, dev_config} {
        if (not _dev_handle) {
            return;
        }
        // Prepare the IRQ assertion too
        _irq_assert = irq_assert{manage_isr_service, response_irq_line, GPIO_INTR_NEGEDGE};
    }

    i2c_channel::~i2c_channel() {
        if (_dev_handle) {
            ESP_ERROR_CHECK_WITHOUT_ABORT(i2c_master_bus_rm_device(_dev_handle));
        }
        if (_bus_handle) {
            ESP_ERROR_CHECK_WITHOUT_ABORT(i2c_del_master_bus(_bus_handle));
        }
    }

    bool i2c_channel::wake() {
        if (comm_operation op{*this, comm_dir::send, 100ms}; op.ok()) {
            if (not _dev_handle) {
                return false;
            }
            return i2c_master_probe(_bus_handle, _dev_addr, 10) == ESP_OK;
        } else {
            return false;
        }
    }

    result<> i2c_channel::raw_send(mlab::range<bin_data::const_iterator> buffer, ms timeout) {
        if (not _dev_handle) {
            return channel_error::hw_error;
        }
        ESP_LOG_BUFFER_HEX_LEVEL(PN532_I2C_TAG " >>", buffer.data(), buffer.size(), ESP_LOG_DEBUG);
        return from_esp_error(i2c_master_transmit(_dev_handle, buffer.data(), buffer.size(), int(timeout.count())));
    }

    result<> i2c_channel::raw_receive(mlab::range<bin_data::iterator> buffer, ms timeout) {
        if (not _dev_handle) {
            return channel_error::hw_error;
        }
        mlab::reduce_timeout rt{timeout};
        // PN532 protocol prepends a ready byte, so we need a buffer that is 1 byte larger.
        _buffer.clear();
        _buffer.resize(1 + buffer.size(), 0x0);
        while (rt and (_buffer[0] & 0b1) == 0) {
            // Read the full buffer + 1 byte
            const auto res = i2c_master_receive(_dev_handle, _buffer.data(), _buffer.size(), int(rt.remaining().count()));
            if (res != ESP_OK) {
                ESP_LOGE(PN532_I2C_TAG, "Receive failed: %s", esp_err_to_name(res));
                _buffer.clear();
                return from_esp_error(res);
            }
            // Is the result ready?
            if ((_buffer[0] & 0b1) == 1) {
                // Ready! Copy the rest to the buffer and return
                std::copy(std::begin(_buffer) + 1, std::end(_buffer), std::begin(buffer));
                ESP_LOG_BUFFER_HEX_LEVEL(PN532_I2C_TAG " <<", buffer.data(), buffer.size(), ESP_LOG_DEBUG);
                return mlab::result_success;
            }
            // Not yet, wait
            std::this_thread::sleep_for(10ms);
        }
        return channel_error::timeout;
    }

    bool i2c_channel::on_receive_prepare(pn532::ms timeout) {
        return _irq_assert(timeout);
    }
}// namespace pn532::esp32