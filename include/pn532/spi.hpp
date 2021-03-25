//
// Created by spak on 3/25/21.
//

#ifndef PN532_SPI_HPP
#define PN532_SPI_HPP

#include <pn532/channel.hpp>
#include <mlab/irq_assert.hpp>

namespace pn532 {

    class spi_channel final : public channel {
        mlab::irq_assert _irq_assert;

    protected:
    public:
    };

}

#endif//PN532_SPI_HPP
