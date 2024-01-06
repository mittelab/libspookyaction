//
// Created by spak on 2/19/21.
//

#ifndef PN532_ESP32_I2C_HPP
#define PN532_ESP32_I2C_HPP

#include <driver/i2c_master.h>
#include <pn532/channel.hpp>
#include <pn532/esp32/irq_assert.hpp>


namespace pn532::esp32 {
    class i2c_channel final : public channel {
        i2c_master_bus_handle_t _bus_handle = nullptr;
        i2c_master_dev_handle_t _dev_handle = nullptr;
        std::uint16_t _dev_addr = 0x0;
        mlab::bin_data _buffer = {};
        irq_assert _irq_assert = {};

        i2c_channel() = default;

    protected:
        /**
         * Wraps around `i2c_master_transmit`.
         */
        result<> raw_send(mlab::range<bin_data::const_iterator> buffer, ms timeout) override;

        /**
         * Wraps around `i2c_master_receive`. It will fetch one byte more than @p buffer, the bool expressing
         * whether the answer is ready.
         */
        result<> raw_receive(mlab::range<bin_data::iterator> buffer, ms timeout) override;

        /**
         * @return For @ref i2c_channel, this is always @ref comm_rx_mode::buffered.
         */
        [[nodiscard]] inline comm_rx_mode raw_receive_mode() const override;

        /**
         * @brief Asserts that that data is available to receive.
         *
         * When using an IRQ line, it waits until the the IRQ line is triggered.
         * When not using an IRQ line, it will poll the PN532 every 10ms to know whether a response is ready or not.
         * This is done directly in @ref raw_receive.
         */
        bool on_receive_prepare(pn532::ms timeout) override;

    public:
        /**
         * @brief Default PN532 slave device configuration.
         */
        static constexpr i2c_device_config_t default_device_config{
                .dev_addr_length = I2C_ADDR_BIT_LEN_7,
                .device_address = 0x48,
                .scl_speed_hz = 400'000};

        i2c_channel(i2c_channel const &) = delete;
        i2c_channel &operator=(i2c_channel const &) = delete;

        /**
         * @brief Construct an I2C channel for a PN532 with the given settings.
         * @param bus_config I2C bus configuration for the I2C channel. This is passed as-is to the I2C driver.
         * @param dev_config Override for the slave device configuration, defaults to @ref default_device_config.
         * @note In case of invalid port or configuration, an error message is printed, but the class is correctly constructed. It will simply
         *  always fail to send and receive anything (and may clog your output with error messages).
         */
        explicit i2c_channel(i2c_master_bus_config_t bus_config, i2c_device_config_t dev_config = default_device_config);

        /**
         * @brief Construct an I2C channel for a PN532 with the given settings, using GPIO pin to signal when the answer is ready.
         *
         * This reduces the amount of I2C noise on the line because it will only read the answer once it's available.
         * @param bus_config I2C bus configuration for the I2C channel. This is passed as-is to the I2C driver.
         * @param response_irq_line The GPIO pin connected to the IRQ line on the PN532. The PN532 signals when the responses are available
         *  by setting this line to low; an interrupt triggers then a semaphore that allows this class to read the answer only once it's ready.
         * @param manage_isr_service If set to true, the class will call `gpio_install_isr_service` and the corresponding uninstall command
         *  at destruction. Unless the caller manages the ISR service by themselves, this parm should be set to true.
         * @param dev_config Override for the slave device configuration, defaults to @ref default_device_config.
         * @note In case of invalid port or configuration, an error message is printed, but the class is correctly constructed. It will simply
         *  always fail to send and receive anything (and may clog your output with error messages).
         * @see irq_assert
         */
        i2c_channel(i2c_master_bus_config_t bus_config, gpio_num_t response_irq_line, bool manage_isr_service, i2c_device_config_t dev_config = default_device_config);

        /**
         * Releases the I2C driver.
         */
        ~i2c_channel() override;

        /**
         * Sends an empty I2C command to wake the PN532.
         */
        bool wake() override;
    };
}// namespace pn532::esp32

namespace pn532::esp32 {
    comm_rx_mode i2c_channel::raw_receive_mode() const {
        return comm_rx_mode::buffered;
    }
}// namespace pn532::esp32

#endif//PN532_ESP32_I2C_HPP
