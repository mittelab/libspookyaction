//
// Created by spak on 2/19/21.
//

#ifndef PN532_I2C_HPP
#define PN532_I2C_HPP

#include "channel.hpp"
#include <driver/i2c.h>
#include <memory>
#include <mlab/result.hpp>

namespace pn532 {

    namespace i2c {

        enum struct error : std::int16_t {
            parameter_error = ESP_ERR_INVALID_ARG,
            fail = ESP_FAIL,
            invalid_state = ESP_ERR_INVALID_STATE,
            timeout = ESP_ERR_TIMEOUT
        };

        [[nodiscard]] const char *to_string(error e);

        class command {
            i2c_cmd_handle_t _handle;
            bool _used;

            [[nodiscard]] bool assert_unused() const;

        public:
            command();
            ~command();
            command(command const &) = delete;
            command(command &&) noexcept = default;
            command &operator=(command const &) = delete;
            command &operator=(command &&) noexcept = default;

            void write(std::uint8_t b, bool enable_ack_check);

            void write(mlab::range<bin_data::const_iterator> const &data, bool enable_ack_check);

            void read(mlab::range<bin_data::iterator> const &buffer, i2c_ack_type_t ack);

            void read(std::uint8_t &b, i2c_ack_type_t ack);

            void stop();

            mlab::result<error> operator()(i2c_port_t port, std::chrono::milliseconds timeout);
        };
    }// namespace i2c


    class i2c_channel final : public channel {
        i2c_port_t _port;
        std::uint8_t _slave_addr;

    protected:
        /**
         * Prepares a command with the correct mode (write, read) depending on @ref _mode;
         * @return
         */
        [[nodiscard]] i2c::command raw_prepare_command(comm_mode mode) const;

        r<> raw_send(mlab::range<bin_data::const_iterator> const &buffer, ms timeout) override;
        r<> raw_receive(mlab::range<bin_data::iterator> const &buffer, ms timeout) override;

        [[nodiscard]] inline receive_mode raw_receive_mode() const override;

        bool on_receive_prepare(ms timeout) override;

    public:
        static constexpr std::uint8_t default_slave_address = 0x48;

        [[nodiscard]] inline static error error_from_i2c_error(i2c::error e);

        bool wake() override;

        i2c_channel(i2c_port_t port, i2c_config_t config, std::uint8_t slave_address = default_slave_address);
        ~i2c_channel();

        [[nodiscard]] inline std::uint8_t slave_address_to_write() const;
        [[nodiscard]] inline std::uint8_t slave_address_to_read() const;
    };


}// namespace pn532

namespace pn532 {

    channel::error i2c_channel::error_from_i2c_error(i2c::error e) {
        switch (e) {
            case i2c::error::parameter_error:
                return error::comm_malformed;
            case i2c::error::timeout:
                return error::comm_timeout;
            case i2c::error::fail:
                [[fallthrough]];
            case i2c::error::invalid_state:
                return error::comm_error;
        }
        return error::comm_error;
    }

    std::uint8_t i2c_channel::slave_address_to_write() const {
        return _slave_addr;
    }
    std::uint8_t i2c_channel::slave_address_to_read() const {
        return _slave_addr + 1;
    }

    channel::receive_mode i2c_channel::raw_receive_mode() const {
        return receive_mode::buffered;
    }

}// namespace pn532

#endif//PN532_HSU_HPP
