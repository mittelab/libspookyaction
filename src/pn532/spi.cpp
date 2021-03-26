//
// Created by spak on 3/25/21.
//

#include "pn532/spi.hpp"

namespace pn532 {

    spi_channel::spi_channel()
        : _tx_buffer{mlab::capable_allocator<std::uint8_t>{MALLOC_CAP_DMA}},
          _rx_buffer{mlab::capable_allocator<std::uint8_t>{MALLOC_CAP_DMA}} {}

}// namespace pn532