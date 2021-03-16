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

        [[nodiscard]] inline receive_mode raw_receive_mode() const override;

        bool on_send_prepare(ms timeout) override;

    public:
        bool wake() override;
        /**
         *
         * @param port
         * @param config
         * @param to_device_tx The pin connected to the TX line on the PN532
         * @param to_device_rx The pin connected to the RX line on the PN532
         */
        hsu_channel(uart_port_t port, uart_config_t config, int to_device_tx, int to_device_rx);
        ~hsu_channel() override;
    };
}// namespace pn532

namespace pn532 {
    channel::receive_mode hsu_channel::raw_receive_mode() const {
        return receive_mode::stream;
    }
}// namespace pn532

#endif//PN532_HSU_HPP
