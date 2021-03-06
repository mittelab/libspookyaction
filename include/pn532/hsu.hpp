//
// Created by Pietro Saccardi on 21/12/2020.
//

#ifndef PN532_HSU_HPP
#define PN532_HSU_HPP

#include "channel.hpp"
#include "channel_repl.hpp"
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

    class hsu_channel_repl final : public repl::channel {
        uart_port_t _port;

    protected:
        r<> raw_send(mlab::range<bin_data::const_iterator> const &buffer, ms timeout) override;
        r<> raw_receive(mlab::range<bin_data::iterator> const &buffer, ms timeout) override;

        [[nodiscard]] inline bool supports_multiple_raw_receive() const override;

        bool on_send_prepare(ms timeout) override;

    public:
        bool wake() override;
        inline explicit hsu_channel_repl(uart_port_t port);
    };
}// namespace pn532

namespace pn532 {

    hsu_channel::hsu_channel(uart_port_t port) : _port{port} {}

    hsu_channel_repl::hsu_channel_repl(uart_port_t port) : _port{port} {}


    bool hsu_channel_repl::supports_multiple_raw_receive() const {
        return true;
    }
}// namespace pn532

#endif//PN532_HSU_HPP
