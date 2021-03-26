//
// Created by spak on 3/25/21.
//

#ifndef PN532_SPI_HPP
#define PN532_SPI_HPP

#include <mlab/capable_mem.hpp>
#include <pn532/channel.hpp>

namespace pn532 {

    class spi_channel final : public channel {
        std::vector<std::uint8_t, mlab::capable_allocator<std::uint8_t>> _tx_buffer;
        std::vector<std::uint8_t, mlab::capable_allocator<std::uint8_t>> _rx_buffer;

    protected:
    public:
        spi_channel();
    };

}// namespace pn532

#endif//PN532_SPI_HPP
