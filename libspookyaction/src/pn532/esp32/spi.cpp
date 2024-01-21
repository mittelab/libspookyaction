//
// Created by spak on 3/25/21.
//

#include <pn532/esp32/spi.hpp>
#include <thread>

#define PN532_SPI_TAG "PN532-SPI"

namespace pn532::esp32 {
    using namespace std::chrono_literals;
    using mlab::reduce_timeout;

    namespace {
        channel_error error_from_esp_err(esp_err_t e) {
            switch (e) {
                case ESP_ERR_TIMEOUT:
                    return channel_error::timeout;
                case ESP_ERR_INVALID_ARG:
                    return channel_error::malformed;
                default:
                    return channel_error::hw_error;
            }
        }
    }// namespace

    bool spi_channel::wake() {
        if (comm_operation op{*this, comm_dir::send, 10ms}; op.ok()) {
            // Send some dummy data to wake up
            _dma_buffer = {0x55, 0x55, 0x55};
            return bool(op.update(perform_transaction(_dma_buffer, spi_command::data_write, comm_dir::send, 10ms)));
        } else {
            return false;
        }
    }

    comm_rx_mode spi_channel::raw_receive_mode() const {
        return comm_rx_mode::stream;
    }


    result<> spi_channel::perform_transaction(capable_buffer &buffer, spi_command cmd, comm_dir mode, ms timeout) {
        reduce_timeout rt{timeout};

        uint32_t transaction_flags = 0;
        if (cmd == spi_command::none)
            transaction_flags |= SPI_TRANS_VARIABLE_CMD;
        if (_recv_op_status == recv_op_status::data_read) {
            if ((cmd == spi_command::data_read) || (cmd == spi_command::none))
                transaction_flags |= SPI_TRANS_CS_KEEP_ACTIVE;
        }

        spi_transaction_ext_t transaction{
                .base = {
                        .flags = transaction_flags,
                        .cmd = static_cast<std::uint8_t>(cmd),
                        .addr = 0,
                        .length = buffer.size() * 8,
                        .rxlength = 0,
                        .user = const_cast<spi_channel *>(this),
                        .tx_buffer = mode == comm_dir::send ? const_cast<std::uint8_t *>(buffer.data()) : nullptr,
                        .rx_buffer = mode == comm_dir::receive ? const_cast<std::uint8_t *>(buffer.data()) : nullptr},
                .command_bits = 0,
                .address_bits = 0,
                .dummy_bits = 0};
        if (const auto res = spi_device_transmit(_device, reinterpret_cast<spi_transaction_t *>(&transaction)); res != ESP_OK) {
            ESP_LOGE(PN532_SPI_TAG, "spi_device_transmit failed, return code %d (%s).", res, esp_err_to_name(res));
            return error_from_esp_err(res);
        }
        return mlab::result_success;
    }

    result<> spi_channel::raw_send(mlab::range<bin_data::const_iterator> buffer, ms timeout) {
        if (_device == nullptr) {
            return channel_error::hw_error;
        }
        ESP_LOG_BUFFER_HEX_LEVEL(PN532_SPI_TAG " >>", buffer.data(), buffer.size(), ESP_LOG_VERBOSE);
        reduce_timeout rt{timeout};
        _dma_buffer.resize(buffer.size());
        if (buffer.size() > 0) {
            std::copy(std::begin(buffer), std::end(buffer), std::begin(_dma_buffer));
        }
        return perform_transaction(_dma_buffer, spi_command::data_write, comm_dir::send, rt.remaining());
    }

    result<> spi_channel::raw_poll_status(ms timeout) {
        if (_recv_op_status != recv_op_status::init) {
            return mlab::result_success;
        }
        reduce_timeout rt{timeout};
        _dma_buffer.clear();
        _dma_buffer.resize(1, 0x00);
        while (rt) {
            // Perform a status read check
            if (const auto res = perform_transaction(_dma_buffer, spi_command::status_read, comm_dir::receive, rt.remaining()); not res) {
                return res.error();
            } else if ((_dma_buffer.back() & 0b1) == 0) {
                // Wait a bit
                std::this_thread::sleep_for(10ms);
            } else {
                // Successful
                _recv_op_status = recv_op_status::did_poll;
                return mlab::result_success;
            }
        }
        return channel_error::timeout;
    }

    result<> spi_channel::raw_receive(mlab::range<bin_data::iterator> buffer, ms timeout) {
        if (_device == nullptr) {
            return channel_error::hw_error;
        }
        reduce_timeout rt{timeout};
        if (const auto res = raw_poll_status(rt.remaining()); not res) {
            return res.error();
        }
        // Nice, we now have a response to read
        _dma_buffer.clear();
        _dma_buffer.resize(buffer.size(), 0x00);
        // Issue the "data_read" command only once
        const spi_command cmd = _recv_op_status == recv_op_status::data_read ? spi_command::none : spi_command::data_read;
        // Bump the status
        _recv_op_status = recv_op_status::data_read;
        if (auto res = perform_transaction(_dma_buffer, cmd, comm_dir::receive, rt.remaining()); res) {
            // Copy back to buffer
            std::copy(std::begin(_dma_buffer), std::end(_dma_buffer), std::begin(buffer));
            ESP_LOG_BUFFER_HEX_LEVEL(PN532_SPI_TAG " <<", buffer.data(), buffer.size(), ESP_LOG_VERBOSE);
            return mlab::result_success;
        } else {
            return res.error();
        }
    }

    bool spi_channel::on_receive_prepare(ms timeout) {
        spi_device_acquire_bus(_device, portMAX_DELAY);
        if (_irq_assert.pin() == GPIO_NUM_NC) {
            // This is a dummy IRQ assert, so we will need to poll
            _recv_op_status = recv_op_status::init;
        } else {
            // We will poll via IRQ assert
            if (not _irq_assert(timeout)) {
                return false;
            }
            _recv_op_status = recv_op_status::did_poll;
        }
        return true;
    }

    void spi_channel::on_receive_complete(result<> const &outcome) {
        // Read a dummy byte so we can unassert the CS pin
        spi_transaction_ext_t transaction{
                .base = {
                        .flags = SPI_TRANS_VARIABLE_CMD | SPI_TRANS_USE_RXDATA,
                        .cmd = 0,
                        .addr = 0,
                        .length = 8,
                        .rxlength = 8,
                        .user = const_cast<spi_channel *>(this),
                        .tx_buffer = nullptr,
                        .rx_buffer = nullptr},
                .command_bits = 0,
                .address_bits = 0,
                .dummy_bits = 0};

        spi_device_transmit(_device, reinterpret_cast<spi_transaction_t *>(&transaction));
        spi_device_release_bus(_device);
    }

    spi_channel::spi_channel(spi_host_device_t host, spi_bus_config_t const &bus_config, spi_device_interface_config_t device_cfg, spi_dma_chan_t dma_chan)
        : _dma_buffer{capable_allocator<std::uint8_t>{MALLOC_CAP_DMA}},
          _host{std::nullopt},
          _device{nullptr},
          _irq_assert{},
          _recv_op_status{recv_op_status::init} {
        if (dma_chan == 0) {
            ESP_LOGE(PN532_SPI_TAG, "To use SPI with PN532, a DMA channel must be specified (either 1 or 2).");
            return;
        }
        if (const auto res = spi_bus_initialize(host, &bus_config, dma_chan); res != ESP_OK) {
            ESP_LOGE(PN532_SPI_TAG, "spi_bus_initialize failed, return code %d (%s).", res, esp_err_to_name(res));
            return;
        }
        // Save the host, so we know we have to free it
        _host = host;
        // Patch the device options
        device_cfg.address_bits = 0;
        device_cfg.command_bits = 8;// 1 byte indicating status read, data read, data write
        device_cfg.dummy_bits = 0;
        device_cfg.flags |= SPI_DEVICE_BIT_LSBFIRST;
        if (device_cfg.clock_speed_hz > 5'000'000) {
            ESP_LOGW(PN532_SPI_TAG, "Clk speed (%d) above 5MHz: PN532 supports up to 5MHz.", device_cfg.clock_speed_hz);
        } else if (device_cfg.clock_speed_hz > 1'000'000) {
            ESP_LOGW(PN532_SPI_TAG, "Clk speed (%d) above 1MHz. PN532 supports up to 5MHz, but it may still fail comm line diagnose self-test.", device_cfg.clock_speed_hz);
        }
        if (const auto res = spi_bus_add_device(host, &device_cfg, &_device); res != ESP_OK) {
            ESP_LOGE(PN532_SPI_TAG, "spi_bus_add_device failed, return code %d (%s).", res, esp_err_to_name(res));
            // Make sure we will not try to do anything with _device:
            _device = nullptr;
        }
    }

    spi_channel::spi_channel(spi_host_device_t host, spi_bus_config_t const &bus_config, spi_device_interface_config_t device_cfg, int dma_chan,
                             gpio_num_t response_irq_line, bool manage_isr_service)
        : spi_channel{host, bus_config, device_cfg, dma_chan} {
        _irq_assert = irq_assert{manage_isr_service, response_irq_line};
    }

    spi_channel::~spi_channel() {
        if (_device != nullptr) {
            ESP_ERROR_CHECK_WITHOUT_ABORT(spi_bus_remove_device(_device));
            _device = nullptr;
        }
        if (_host) {
            ESP_ERROR_CHECK_WITHOUT_ABORT(spi_bus_free(_host.value()));
            _host = std::nullopt;
        }
    }

}// namespace pn532::esp32