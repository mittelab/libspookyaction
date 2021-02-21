//
// Created by Pietro Saccardi on 21/12/2020.
//

#ifndef PN532_HSU_HPP
#define PN532_HSU_HPP

#include "channel.hpp"
#include <mbcontroller.h>

namespace pn532 {

    class hsu_channel final : public channel {
        uart_port_t _port;

    protected:
        bool prepare_receive(std::chrono::milliseconds timeout) override;

        bool send_raw(bin_data const &data, std::chrono::milliseconds timeout) override;

        bool receive_raw(bin_data &data, std::size_t length, std::chrono::milliseconds timeout) override;

    public:
        bool wake() override;

        inline explicit hsu_channel(uart_port_t port);
    };
}// namespace pn532

namespace pn532 {

    hsu_channel::hsu_channel(uart_port_t port) : _port{port} {}

}// namespace pn532

#endif//PN532_HSU_HPP
