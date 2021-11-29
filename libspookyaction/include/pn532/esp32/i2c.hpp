//
// Created by spak on 2/19/21.
//

#ifndef PN532_ESP32_I2C_HPP
#define PN532_ESP32_I2C_HPP

#include <driver/i2c.h>
#include <memory>
#include <mlab/result.hpp>
#include <pn532/channel.hpp>
#include <pn532/esp32/irq_assert.hpp>

namespace pn532::esp32 {

    namespace i2c {

        /**
         * Wrapper for the possible error code from ESP32's I2C driver. This is I2C specific and used only in @ref command.
         * Refer to @ref esp_err.h for documentation.
         */
        enum struct error : std::int16_t {
            parameter_error = ESP_ERR_INVALID_ARG,
            fail = ESP_FAIL,
            invalid_state = ESP_ERR_INVALID_STATE,
            timeout = ESP_ERR_TIMEOUT
        };

        /**
         * Convert a @ref error into the corresponding string message representation.
         * @param e Error code
         * @return A C string.
         */
        [[nodiscard]] const char *to_string(error e);

        /**
         * @brief Class that wraps an I2C ESP32's command.
         *
         * ESP32's I2C driver does not allow direct control of the bus; it rather packs all the operations into a prebuild command
         * (repesented by a `i2c_cmd_handle_t`) which is single use. This class is a wrapper for it. Since there is a resource
         * associated to this command, this class is moveable but not copiable.
         * The command can be invoked via @ref operator(), but once that method is called, it's unusable and any attempt to further
         * use it or append read/write operation will fail.
         *
         * @code
         *  using namespace std::chrono_literals;
         *  constexpr std::uint8_t slave_addr = 0x26;
         *
         *  // Implement a command that reads 1 byte status and 4 bytes data
         *  std::uint8_t slave_status = 0x00;
         *  mlab::bin_data slave_payload{mlab::prealloc(4)};
         *
         *  pn532::i2c::command cmd;
         *  cmd.write(slave_addr, true);
         *  cmd.read(slave_status, I2C_MASTER_ACK);
         *  cmd.read(slave_payload.view(), I2C_MASTER_LAST_NACK); // Send a final NACK
         *  cmd.stop();
         *
         *  if (const auto result = cmd(I2C_NUM_0, 100ms); result) {
         *      std::cout << "Successfully trasmitted via I2C." << std::endl;
         *      // Parse the 4 bytes into an unsigned integer
         *      std::uint32_t payload_data = 0;
         *      mlab::bin_stream s{slave_payload};
         *      s >> mlab::msb32 >> payload_data;
         *      std::cout << "Slave status: " << status << " payload: " << payload_data << std::endl;
         *  } else {
         *      std::cout << "I2C command failed with status: " << pn532::i2c::to_string(result.error()) << std::endl;
         *  }
         * @endcode
         */
        class command {
            i2c_cmd_handle_t _handle;
            bool _used;

            [[nodiscard]] bool assert_unused() const;

        public:
            /**
             * Construts a new, empty, I2C command.
             */
            command();
            ~command();

            command(command const &) = delete;
            command(command &&) noexcept = default;

            command &operator=(command const &) = delete;
            command &operator=(command &&) noexcept = default;

            /**
             * @brief Append a new write operation to the command, writing a unique byte.
             * @param b Byte to write.
             * @param enable_ack_check If true, the driver will check for a corresponding ACK from the slave. If that is not received,
             *  the command as a whole will fail with a @ref error status.
             */
            void write(std::uint8_t b, bool enable_ack_check);

            /**
             * @brief Append a new write operation to the command, writing a sequence of bytes.
             * @param data A range of bytes to write. The caller is responsible for keeping this memory in scope and valid until this
             *  command object is destroyed. This is passed directly down to the driver, so beware: it is not documented what happens
             *  if you pass an empty range.
             * @param enable_ack_check If true, the driver will check for a corresponding ACK from the slave. If that is not received,
             *  the command as a whole will fail with a @ref error status.
             */
            void write(mlab::range<const uint8_t *> data, bool enable_ack_check);

            /**
             * @brief Append a new read operation to the command, reading a sequence of bytes.
             * @param buffer A preallocated buffer of bytes to fill. The caller is responsible for preallocating this memory to exactly
             *  the length of the read operation, and keep it in scope and valid until this command object is destroyed. This is passed
             *  directly down to the driver, so beware: it is not documented what happens if you pass an empty range.
             * @param ack The type of ACK to send. See @ref i2c_types.h for further documentation.
             */
            void read(mlab::range<uint8_t *> buffer, i2c_ack_type_t ack);

            /**
             * Append a new read operation to the command, reading a single byte.
             * @param b A non-constant reference to the byte to fill. Of course the caller is responsible of making sure that the reference
             *  is in scope until when this command object is destroyed.
             * @param ack The type of ACK to send. See @ref i2c_types.h for further documentation.
             */
            void read(std::uint8_t &b, i2c_ack_type_t ack);

            /**
             * @brief Append a stop to the command.
             * @note A stop is a specific I2C command, so in principle after a stop you can further append write and read operations.
             */
            void stop();

            /**
             * @brief Executes the buffered command as is it, and invalidates it.
             * @param port The I2C port on which to run the command.
             * @param timeout The maximum time the driver is allowed to take to execute before it fails with a @ref error::timeout
             * @return A result which is either @ref mlab::result_success, or carries one of the possible @ref error statuses.
             */
            mlab::result<error> operator()(i2c_port_t port, std::chrono::milliseconds timeout);
        };
    }// namespace i2c


    /**
     * @brief Implementation of I2C channel protocol for PN532 over ESP32's I2C driver.
     *
     * This class supports, when specified, the possibility of using a GPIO pin for the PN532's IRQ line; in that case, the
     * class does not have to poll the controller until the answers are ready, but it will instead idle and wait for the IRQ
     * line to become active, and read the answer only then once it's ready. That is done through a semaphore and an interrupt
     * installed on the GPIO.
     * @warning Due to ESP32's "buffered" type of I2C commands, it is not possible to easily read variable length data. This
     *  channel is relatively slow because in order to read a full PN532 packet, it has to issue several I2C commands. The
     *  reason is that we need to build the I2C command in beforehand, so we need to know already the read length. To work
     *  around this limitation, we request the packet several times using an PN532-level NACK message until we have enough
     *  information to read the full extent of the message. Attempts at "tricking" the ESP32's driver by not issueing the
     *  necessary stop failed, as they put the PN532 in an invalid state.
     */
    class i2c_channel final : public channel {
        i2c_port_t _port;
        std::uint8_t _slave_addr;
        irq_assert _irq_assert;

    protected:
        /**
         * Prepares a command with the correct mode (write, read) depending on @ref _mode;
         * @return
         */
        [[nodiscard]] i2c::command raw_prepare_command(comm_mode mode) const;

        result<> raw_send(mlab::range<bin_data::const_iterator> buffer, ms timeout) override;
        result<> raw_receive(mlab::range<bin_data::iterator> buffer, ms timeout) override;

        [[nodiscard]] inline receive_mode raw_receive_mode() const override;

        bool on_receive_prepare(ms timeout) override;

    public:
        /**
         * @brief Default PN532 slave address
         */
        static constexpr std::uint8_t default_slave_address = 0x48;

        /**
         * @brief Converts a @ref i2c::error into a @ref pn532::channel::error status code
         * @param e I2C protocol-level error.
         * @return Channel-level error.
         */
        [[nodiscard]] inline static error error_from_i2c_error(i2c::error e);

        bool wake() override;

        /**
         * @brief Construct an I2C channel for a PN532 with the given settings.
         * @param port Communication port for the I2C channel. This is passed as-is to the I2C driver.
         * @param config Configuration for the I2C channel. This is passed as-is to the I2C driver.
         * @param slave_address Override for the slave address, defaults to @ref default_slave_address.
         * @note In case of invalid port or configuration, an error message is printed, but the class is correctly constructed. It will simply
         *  always fail to send and receive anything (and may clog your output with error messages).
         */
        i2c_channel(i2c_port_t port, i2c_config_t config, std::uint8_t slave_address = default_slave_address);

        /**
         * @brief Construct an I2C channel for a PN532 with the given settings, using GPIO pin to signal when the answer is ready.
         *
         * This reduces the amount of I2C noise on the line because it will only read the answer once it's available.
         * @param port Communication port for the I2C channel. This is passed as-is to the I2C driver.
         * @param config Configuration for the I2C channel. This is passed as-is to the I2C driver.
         * @param response_irq_line The GPIO pin connected to the IRQ line on the PN532. The PN532 signals when the responses are available
         *  by setting this line to low; an interrupt triggers then a semaphore that allows this class to read the answer only once it's ready.
         * @param manage_isr_service If set to true, the class will call @ref gpio_install_isr_service and the corresponding uninstall command
         *  at destruction. Unless the caller manages the ISR service by themselves, this parm should be set to true.
         * @param slave_address Override for the slave address, defaults to @ref default_slave_address.
         * @note In case of invalid port or configuration, an error message is printed, but the class is correctly constructed. It will simply
         *  always fail to send and receive anything (and may clog your output with error messages).
         * @see mlab::irq_assert
         */
        i2c_channel(i2c_port_t port, i2c_config_t config, gpio_num_t response_irq_line, bool manage_isr_service, std::uint8_t slave_address = default_slave_address);

        ~i2c_channel() override;

        /**
         * @return Slave address for sending commands to the PN532.
         */
        [[nodiscard]] inline std::uint8_t slave_address_to_write() const;

        /**
         *
         * @return  Slave address for reading data from the PN532.
         */
        [[nodiscard]] inline std::uint8_t slave_address_to_read() const;
    };


}// namespace pn532::esp32

namespace pn532::esp32 {

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

}// namespace pn532::esp32

#endif//PN532_ESP32_I2C_HPP
