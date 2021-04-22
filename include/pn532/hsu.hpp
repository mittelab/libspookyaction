//
// Created by Pietro Saccardi on 21/12/2020.
//

#ifndef PN532_HSU_HPP
#define PN532_HSU_HPP

#include "channel.hpp"
#include <mbcontroller.h>

namespace pn532 {

    /**
     * @brief Implementation of HSU channel protocol for PN532 over ESP32's I2C driver.
     */
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
         * @brief Construct an HSU channel for a PN532 with the given settings.
         * @param port Communication port for the HSU channel. This is passed as-is to the UART driver.
         * @param config Configuration for the HSU channel. This is passed as-is to the UART driver.
         * @param to_device_tx The pin connected to the TX line on the PN532
         * @param to_device_rx The pin connected to the RX line on the PN532
         * @note In case of invalid port or configuration, an error message is printed, but the class is correctly constructed. It will simply
         *  always fail to send and receive anything (and may clog your output with error messages).
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
