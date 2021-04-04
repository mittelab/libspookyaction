//
// Created by spak on 3/25/21.
//

#include "pn532/spi.hpp"

#define PN532_SPI_TAG "PN532-SPI"

namespace pn532 {

    namespace {
        constexpr std::uint8_t spi_dw = 0b01;
        constexpr std::uint8_t spi_dr = 0b11;
        constexpr std::uint8_t spi_sr = 0b10;
        constexpr std::uint8_t spi_mask = 0b11;

        channel::error error_from_esp_err(esp_err_t e) {
            switch (e) {
                case ESP_ERR_TIMEOUT:
                    return channel::error::comm_timeout;
                case ESP_ERR_INVALID_ARG:
                    return channel::error::comm_malformed;
                default:
                    return channel::error::comm_error;
            }
        }
    }

    spi_transaction_t spi_channel::make_transaction(channel::comm_mode mode) const {
        return spi_transaction_t{
                .flags = 0,
                .cmd = 0,
                .addr = 0,
                .length = _dma_buffer.size(),
                .rxlength = 0,
                .user = const_cast<spi_channel *>(this),
                .tx_buffer = mode == comm_mode::send ? const_cast<std::uint8_t *>(_dma_buffer.data()) : nullptr,
                .rx_buffer = mode == comm_mode::receive ? const_cast<std::uint8_t *>(_dma_buffer.data()) : nullptr
        };
    }

    channel::receive_mode spi_channel::raw_receive_mode() const {
        return channel::receive_mode::buffered;
    }

    channel::r<> spi_channel::perform_transaction(channel::comm_mode mode, ms timeout) {
        reduce_timeout rt{timeout};
        auto transaction = make_transaction(mode);
        if (const auto res = spi_device_queue_trans(_device, &transaction, pdMS_TO_TICKS(rt.remaining().count())); res != ESP_OK) {
            ESP_LOGE(PN532_SPI_TAG, "spi_device_queue_trans failed, return code %d (%s).", res, esp_err_to_name(res));
            return error_from_esp_err(res);
        }
        spi_transaction_t *transaction_ptr = nullptr;
        if (const auto res = spi_device_get_trans_result(_device, &transaction_ptr, pdMS_TO_TICKS(rt.remaining().count())); res != ESP_OK) {
            ESP_LOGE(PN532_SPI_TAG, "spi_device_get_trans_result failed, return code %d (%s).", res, esp_err_to_name(res));
            return error_from_esp_err(res);
        } else if (transaction_ptr != &transaction) {
            ESP_LOGE(PN532_SPI_TAG, "Received incorrect transaction.");
            return error::comm_error;
        }
        return mlab::result_success;
    }

    channel::r<> spi_channel::raw_send(mlab::range<bin_data::const_iterator> const &buffer, ms timeout) {
        if (_device == nullptr) {
            return error::comm_error;
        }
        reduce_timeout rt{timeout};
        _dma_buffer.resize(buffer.size() + 1);
        _dma_buffer.front() = spi_dw;
        std::copy(std::begin(buffer) + 1, std::end(buffer), std::begin(_dma_buffer));
        return perform_transaction(comm_mode::send, rt.remaining());
    }

    channel::r<> spi_channel::raw_receive(mlab::range<bin_data::iterator> const &buffer, ms timeout) {
        if (_device == nullptr) {
            return error::comm_error;
        }
        reduce_timeout rt{timeout};
        _dma_buffer.clear();
        _dma_buffer.resize(2, 0x00);
        while (rt and (_dma_buffer.back() & 0b1) == 0) {
            // Perform a status read check
            if (const auto res = perform_transaction(comm_mode::receive, rt.remaining()); not res) {
                return res.error();
            }
            // Is it a valid status read?
            if ((_dma_buffer.front() & spi_mask) != spi_sr) {
                ESP_LOGE(PN532_SPI_TAG, "Received incorrect SR byte.");
                return error::comm_malformed;
            }
        }
        // Nice, we now have a response to read
        _dma_buffer.clear();
        _dma_buffer.resize(buffer.size() + 1 /* DR */, 0x00);
        if (auto res = perform_transaction(comm_mode::receive, rt.remaining()); res) {
            // Is the DR byte set?
            if ((_dma_buffer.front() & spi_mask) != spi_dr) {
                ESP_LOGE(PN532_SPI_TAG, "Received incorrect DR byte.");
                return error::comm_malformed;
            }
            // Copy back to buffer
            std::copy(std::begin(_dma_buffer) + 1, std::end(_dma_buffer), std::begin(buffer));
            return mlab::result_success;
        } else {
            return res.error();
        }
    }

    bool spi_channel::on_receive_prepare(ms timeout) {
        if (_cs_pin != GPIO_NUM_NC) {
            return gpio_set_level(_cs_pin, 0) == ESP_OK;
        }
    }

    void spi_channel::on_receive_complete(r<> const &outcome) {
        if (_cs_pin != GPIO_NUM_NC) {
            gpio_set_level(_cs_pin, 1);
        }
    }

    bool spi_channel::on_send_prepare(ms timeout) {
        if (_cs_pin != GPIO_NUM_NC) {
            return gpio_set_level(_cs_pin, 0) == ESP_OK;
        }
    }

    void spi_channel::on_send_complete(r<> const &outcome) {
        if (_cs_pin != GPIO_NUM_NC) {
            gpio_set_level(_cs_pin, 1);
        }
    }

    spi_channel::spi_channel(spi_host_device_t host, spi_bus_config_t const &bus_config, spi_device_interface_config_t device_cfg, int dma_chan)
        : _dma_buffer{mlab::capable_allocator<std::uint8_t>{MALLOC_CAP_DMA}},
          _host{std::nullopt},
          _device{nullptr},
          _cs_pin{GPIO_NUM_NC}
    {
        if (dma_chan == 0) {
            ESP_LOGE(PN532_SPI_TAG, "To use SPI with PN532, a DMA channel must be specified (either 0 or 1).");
            return;
        }
        if (const auto res = spi_bus_initialize(host, &bus_config, dma_chan); res != ESP_OK) {
            ESP_LOGE(PN532_SPI_TAG, "spi_bus_initialize failed, return code %d (%s).", res, esp_err_to_name(res));
            return;
        }
        // Save the host so we know we have to free it
        _host = host;
        // Patch the device options
        device_cfg.address_bits = 0;
        device_cfg.command_bits = 0;
        device_cfg.dummy_bits = 0;
        device_cfg.flags |= SPI_DEVICE_BIT_LSBFIRST;
        // We will control the CS manually. We do this so that we can continue polling as much as needed instead of having
        // the SPI driver release CS for us. When that happens, the PN532 releases the buffer, so we do not want that to happen.
        _cs_pin = static_cast<gpio_num_t>(device_cfg.spics_io_num);
        device_cfg.spics_io_num = GPIO_NUM_NC;
        if (const auto res = spi_bus_add_device(host, &device_cfg, &_device); res != ESP_OK) {
            ESP_LOGE(PN532_SPI_TAG, "spi_bus_add_device failed, return code %d (%s).", res, esp_err_to_name(res));
            _device = nullptr;
        }
        if (_cs_pin != GPIO_NUM_NC) {
            if (const auto res = gpio_set_direction(_cs_pin, GPIO_MODE_OUTPUT); res != ESP_OK) {
                ESP_LOGE(PN532_SPI_TAG, "gpio_set_direction failed, return code %d (%s).", res, esp_err_to_name(res));
                _cs_pin = GPIO_NUM_NC;
            }
            if (const auto res = gpio_set_level(_cs_pin, 1); res != ESP_OK) {
                ESP_LOGE(PN532_SPI_TAG, "gpio_set_level failed, return code %d (%s).", res, esp_err_to_name(res));
                _cs_pin = GPIO_NUM_NC;
            }
        }
    }

    spi_channel::~spi_channel() {
        if (_device != nullptr) {
            if (const auto res = spi_bus_remove_device(_device); res != ESP_OK) {
                ESP_LOGW(PN532_SPI_TAG, "spi_bus_remove_device failed, return code %d (%s).", res, esp_err_to_name(res));
            }
            _device = nullptr;
        }
        if (_host) {
            if (const auto res = spi_bus_free(_host.value()); res != ESP_OK) {
                ESP_LOGW(PN532_SPI_TAG, "spi_bus_free failed, return code %d (%s).", res, esp_err_to_name(res));
            }
            _host = std::nullopt;
        }
    }

}// namespace pn532