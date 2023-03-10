//
// Created by Pietro Saccardi on 21/12/2020.
//

#ifndef PN532_ESP32_HSU_HPP
#define PN532_ESP32_HSU_HPP

#include <driver/gpio.h>
#include <driver/uart.h>
#include <pn532/channel.hpp>

namespace pn532::esp32 {

    /**
     * @brief Implementation of HSU channel protocol for PN532 over ESP32's I2C driver (UM0701-02 §6.2.3).
     */
    class hsu_channel final : public channel {
        uart_port_t _port;

    protected:
        /**
         * @brief Wraps around `uart_write_bytes`.
         */
        result<> raw_send(mlab::range<bin_data::const_iterator> buffer, ms timeout) override;

        /**
         * @brief Wraps around `uart_read_bytes`.
         */
        result<> raw_receive(mlab::range<bin_data::iterator> buffer, ms timeout) override;

        /**
         * @return For @ref hsu_channel, this is always @ref comm_rx_mode::stream.
         */
        [[nodiscard]] inline comm_rx_mode raw_receive_mode() const override;

        /**
         * @brief Flushes the RX buffer via `uart_flush_input`.
         */
        bool on_send_prepare(ms timeout) override;

    public:
        /**
         * @brief Sends the byte sequence `55 55 55`.
         */
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
        hsu_channel(uart_port_t port, uart_config_t config, gpio_num_t to_device_tx, gpio_num_t to_device_rx);

        /**
         * Deletes the allocated UART driver.
         */
        ~hsu_channel() override;
    };
}// namespace pn532::esp32

namespace pn532::esp32 {
    comm_rx_mode hsu_channel::raw_receive_mode() const {
        return comm_rx_mode::stream;
    }
}// namespace pn532::esp32

#endif//PN532_ESP32_HSU_HPP
