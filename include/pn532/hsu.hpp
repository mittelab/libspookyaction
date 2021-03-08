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
        r<> raw_send(mlab::range<bin_data::const_iterator> const &buffer, ms timeout) override;
        r<> raw_receive(mlab::range<bin_data::iterator> const &buffer, ms timeout) override;

        [[nodiscard]] inline bool supports_streaming() const override;

        bool on_send_prepare(ms timeout) override;

    public:
        bool wake() override;
        inline explicit hsu_channel(uart_port_t port);
    };
}// namespace pn532

namespace pn532 {

    hsu_channel::hsu_channel(uart_port_t port) : _port{port} {}


    bool hsu_channel::supports_streaming() const {
        return true;
    }
}// namespace pn532

#endif//PN532_HSU_HPP
