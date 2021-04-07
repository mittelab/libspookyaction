//
// Created by spak on 3/25/21.
//

#ifndef PN532_SPI_HPP
#define PN532_SPI_HPP

#include <driver/gpio.h>
#include <driver/spi_master.h>
#include <mlab/capable_mem.hpp>
#include <mlab/irq_assert.hpp>
#include <optional>
#include <pn532/channel.hpp>

namespace pn532 {

    class spi_channel final : public channel {
        std::vector<std::uint8_t, mlab::capable_allocator<std::uint8_t>> _dma_buffer;
        std::optional<spi_host_device_t> _host;
        spi_device_handle_t _device;
        gpio_num_t _cs_pin;
        mlab::irq_assert _irq_assert;

        enum struct recv_op_status {
            init,
            did_poll,
            data_read
        };
        recv_op_status _recv_op_status;

        enum struct spi_command : std::uint8_t {
            data_write = 0b01,
            status_read = 0b10,
            data_read = 0b11,
            none
        };

        r<> perform_transaction(spi_command cmd, channel::comm_mode mode, ms timeout);

        bool set_cs(bool high);

    protected:
        r<> raw_send(mlab::range<bin_data::const_iterator> const &buffer, ms timeout) override;
        r<> raw_receive(mlab::range<bin_data::iterator> const &buffer, ms timeout) override;
        r<> raw_poll_status(ms timeout);

        bool on_receive_prepare(ms timeout) override;
        void on_receive_complete(r<> const &outcome) override;
        bool on_send_prepare(ms timeout) override;
        void on_send_complete(r<> const &outcome) override;

        [[nodiscard]] receive_mode raw_receive_mode() const override;

    public:
        bool wake() override;

        /**
         *
         * @param host
         * @param bus_config
         * @param device_cfg
         * @param dma_chan Must specify a valid DMA channel, e.g. 1 or 2. 0 is invalid.
         */
        spi_channel(spi_host_device_t host, spi_bus_config_t const &bus_config, spi_device_interface_config_t device_cfg, int dma_chan);
        /**
         *
         * @param host
         * @param bus_config
         * @param device_cfg
         * @param dma_chan Must specify a valid DMA channel, e.g. 1 or 2. 0 is invalid.
         * @param response_irq_line
         * @param manage_isr_service
         * @see mlab::irq_assert::irq_assert
         */
        spi_channel(spi_host_device_t host, spi_bus_config_t const &bus_config, spi_device_interface_config_t device_cfg, int dma_chan,
                    gpio_num_t response_irq_line, bool manage_isr_service);
        ~spi_channel() override;
    };

}// namespace pn532

#endif//PN532_SPI_HPP
