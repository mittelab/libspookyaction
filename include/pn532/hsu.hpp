//
// Created by Pietro Saccardi on 21/12/2020.
//

#ifndef PN532_HSU_HPP
#define PN532_HSU_HPP

#include <mbcontroller.h>
#include "channel.hpp"

namespace pn532 {

    class hsu final : public channel {
        uart_port_t _port;
    protected:
        bool prepare_receive(std::chrono::milliseconds timeout) override;

        bool send_raw(bin_data const &data, std::chrono::milliseconds timeout) override;

        bool receive_raw(bin_data &data, std::size_t length, std::chrono::milliseconds timeout) override;

    public:
        bool wake() override;

        inline explicit hsu(uart_port_t port);
    };
}

namespace pn532 {

    hsu::hsu(uart_port_t port) : _port{port} {}

}

#endif //PN532_HSU_HPP
