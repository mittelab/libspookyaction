//
// Created by spak on 3/25/21.
//

#include "pn532/spi.hpp"

#define PN532_SPI_TAG "PN532-SPI"

namespace pn532 {

    namespace {
        constexpr std::uint8_t spi_dw = 0b01;

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
        _dma_buffer.resize(buffer.size() + 3 /* sr, status, dr */, 0x00);
        /**
         * @todo Perform status read check, ensure CS is kept down
         */
        if (auto res = perform_transaction(comm_mode::receive, rt.remaining()); res) {
            // Copy back
            std::copy(std::begin(_dma_buffer) + 3, std::end(_dma_buffer), std::begin(buffer));
            return mlab::result_success;
        } else {
            return res;
        }
    }

    spi_channel::spi_channel(spi_host_device_t host, spi_bus_config_t const &bus_config, spi_device_interface_config_t device_cfg, int dma_chan)
        : _dma_buffer{mlab::capable_allocator<std::uint8_t>{MALLOC_CAP_DMA}},
          _host{std::nullopt},
          _device{nullptr}
    {
        /**
         * @todo Make sure we control the CS pin
         */
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
        if (const auto res = spi_bus_add_device(host, &device_cfg, &_device); res != ESP_OK) {
            ESP_LOGE(PN532_SPI_TAG, "spi_bus_add_device failed, return code %d (%s).", res, esp_err_to_name(res));
            _device = nullptr;
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