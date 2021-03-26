//
// Created by spak on 3/25/21.
//

#ifndef PN532_SPI_HPP
#define PN532_SPI_HPP

#include <mlab/capable_mem.hpp>
#include <pn532/channel.hpp>
#include <driver/spi_master.h>
#include <optional>

namespace pn532 {

    class spi_channel final : public channel {
        std::vector<std::uint8_t, mlab::capable_allocator<std::uint8_t>> _dma_buffer;
        std::optional<spi_host_device_t> _host;
        spi_device_handle_t _device;

        [[nodiscard]] spi_transaction_t make_transaction(channel::comm_mode mode) const;
        r<> perform_transaction(channel::comm_mode mode, ms timeout);
    protected:

        r<> raw_send(mlab::range<bin_data::const_iterator> const &buffer, ms timeout) override;
        r<> raw_receive(mlab::range<bin_data::iterator> const &buffer, ms timeout) override;

        [[nodiscard]] receive_mode raw_receive_mode() const override;

    public:
        /**
         *
         * @param host
         * @param bus_config
         * @param device_cfg
         * @param dma_chan Must specify a valid DMA channel, e.g. 1 or 2. 0 is invalid.
         */
        spi_channel(spi_host_device_t host, spi_bus_config_t const &bus_config, spi_device_interface_config_t device_cfg, int dma_chan);
        ~spi_channel() override;
    };

}// namespace pn532

#endif//PN532_SPI_HPP
