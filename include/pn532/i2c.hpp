//
// Created by spak on 2/19/21.
//

#ifndef PN532_I2C_HPP
#define PN532_I2C_HPP

#include "channel.hpp"
#include <driver/i2c.h>

namespace pn532 {

    class i2c_channel final : public channel {
        i2c_port_t _port;
        std::uint8_t _slave_addr;

    protected:
        bool prepare_receive(std::chrono::milliseconds timeout) override;

        bool send_raw(bin_data const &data, std::chrono::milliseconds timeout) override;

        bool receive_raw(bin_data &data, std::size_t length, std::chrono::milliseconds timeout) override;

    public:
        static constexpr std::uint8_t default_slave_address = 0x48;

        bool wake() override;

        inline explicit i2c_channel(i2c_port_t port, std::uint8_t slave_address = default_slave_address);

        [[nodiscard]] inline std::uint8_t slave_address_to_write() const;
        [[nodiscard]] inline std::uint8_t slave_address_to_read() const;
    };
}// namespace pn532

namespace pn532 {

    i2c_channel::i2c_channel(i2c_port_t port, std::uint8_t slave_addr) : _port{port}, _slave_addr{slave_addr} {}

    std::uint8_t i2c_channel::slave_address_to_write() const {
        return _slave_addr;
    }
    std::uint8_t i2c_channel::slave_address_to_read() const {
        return _slave_addr + 1;
    }

}// namespace pn532

#endif//PN532_HSU_HPP
