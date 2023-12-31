//
// Created by spak on 3/25/21.
//

#ifndef PN532_ESP32_SPI_HPP
#define PN532_ESP32_SPI_HPP

#include <driver/gpio.h>
#include <driver/spi_master.h>
#include <optional>
#include <pn532/channel.hpp>
#include <pn532/esp32/capable_mem.hpp>
#include <pn532/esp32/irq_assert.hpp>

namespace pn532::esp32 {

    using capable_buffer = std::vector<std::uint8_t, capable_allocator<std::uint8_t>>;

    /**
     * @brief Implementation of SPI channel protocol for PN532 over ESP32's SPI driver.
     *
     * This class supports, when specified, the possibility of using a GPIO pin for the PN532's IRQ line; in that case, the
     * class does not have to poll the controller until the answers are ready, but it will instead idle and wait for the IRQ
     * line to become active, and read the answer only then once it's ready. That is done through a semaphore and an interrupt
     * installed on the GPIO.
     * @warning Experiments have shown that the SPI channel is often unstable, especially at high clocks (> 1MHz). It is not
     *  clear why this occurs, but it looks like at high speeds it fails when transmitting extended info frames. Even at low
     *  speeds, it seldom fails after long exchanges. The PN532 enters an invalid state in which it never returns an answer.
     *  Therefore it's recommended to stay within 1MHz of speed.
     * @note This class supports a "stream-like" usage, i.e. it can progressively read pieces of an incoming info frame in order
     *  to determine its length. To achieve that, it is stateful (during a receive operation), as any receive operation other
     *  than the first has to omit specifying the data read prefix.
     */
    class spi_channel final : public channel {
        /**
         * SPI uses DMA. DMA data must be allocated with special capabilities, therefore it is necessary to have this intermediate buffer.
         * This is shared among all send/receive methods.
         */
        capable_buffer _dma_buffer;

        std::optional<spi_host_device_t> _host;
        spi_device_handle_t _device;
        irq_assert _irq_assert;

        /**
         * @brief State of a receive operation.
         */
        enum struct recv_op_status {
            init,    ///< The communication has not yet begun.
            did_poll,///< A response is ready to be received; this has been assessed either via IRQ or polling.
            data_read///< The response is being read.
        };
        recv_op_status _recv_op_status;

        /**
         * @brief SPI-specific prefixes.
         *
         * This is directly from the PN532's manual. Further, we define a @ref spi_command::none prefix which is used
         * when a single logical receive operation is split into multiple operations to determine the appropriate data
         * buffer size.
         */
        enum struct spi_command : std::uint8_t {
            data_write = 0b01, ///< Data is begin sent from the device to the PN532
            status_read = 0b10,///< Polling status from the PN532
            data_read = 0b11,  ///< Data is being read from the PN532
            none               ///< An SPI command code has already been sent, send none and continue with the current command.
        };

        /**
         * Performs an SPI transaction, trasmitting or filling @ref _dma_buffer.
         * In case of a @ref channel::comm_mode::send operation, @p buffer will be sent.
         * In case of a @ref channel::comm_mode::receive operation, @p buffer has to be preallocated at the expected
         * size and will be filled entirely by the SPI driver.
         * @param buffer The buffer to either send (if @p mode is @ref channel::comm_mode::send) or fill with data (for
         *  @ref channel::comm_mode::receive). Note that in the first case, the buffer is not going to be modified (we
         *  do not take it as `const &` because the driver expects a non-const data pointer); in the second case instead
         *  it's responsibility of the caller to preallocate the buffer at the right size.
         * @param cmd SPI command to prefix to this transaction (or none if @ref spi_command::none)
         * @param mode Send or receive (at an PN532 level).
         * @param timeout Timeout before failure
         * @return @ref mlab::result_success or the corresponding @ref error code.
         */
        result<> perform_transaction(capable_buffer &buffer, spi_command cmd, channel::comm_mode mode, ms timeout);

    protected:
        result<> raw_send(mlab::range<bin_data::const_iterator> buffer, ms timeout) override;
        result<> raw_receive(mlab::range<bin_data::iterator> buffer, ms timeout) override;
        result<> raw_poll_status(ms timeout);

        bool on_receive_prepare(ms timeout) override;

        [[nodiscard]] receive_mode raw_receive_mode() const override;

    public:
        bool wake() override;

        /**
         * @brief Construct an SPI channel for a PN532 with the given settings
         * @param host SPI Host to use. Note that on ESP32-S2 `SPI1_HOST` is not supported (as per ESP32's documentation).
         * @param bus_config SPI bus configuration.
         * @param device_cfg SPI device configuration. Note that despite PN532 supporting up to 5MHz speed, the channel may be unstable
         *  and a lower speed (1MHz) is recommended.
         * @param dma_chan The DMA channel to use for transmitting data. Note that DMA channel 0 is not supported (as per ESP32's documentation),
         *  therefore it must be either DMA channel 1 or DMA channel 2.
         * @param buffer_pool Buffer pool to use for MAC. If `nullptr`, it uses @ref default_buffer_pool. This class
         *  retains a pointer to the buffer pool, so it cannot be changed after construction.
         * @note In case of invalid host, device or bus configuration, an error message is printed, but the class is correctly constructed. It will
         *  simply always fail to send and receive anything (and may clog your output with error messages).
         */
        spi_channel(spi_host_device_t host, spi_bus_config_t const &bus_config, spi_device_interface_config_t device_cfg,
                    spi_dma_chan_t dma_chan, mlab::shared_buffer_pool buffer_pool = nullptr);

        /**
         * @brief Construct an SPI channel for a PN532 with the given settings, using GPIO pin to signal when the answer is ready.
         *
         * This reduces the amount of noise on the line because it will only read the answer once it's available.
         * @param host SPI Host to use. Note that on ESP32-S2 `SPI1_HOST` is not supported (as per ESP32's documentation).
         * @param bus_config SPI bus configuration.
         * @param device_cfg SPI device configuration. Note that despite PN532 supporting up to 5MHz speed, the channel may be unstable
         *  and a lower speed (1MHz) is recommended.
         * @param dma_chan The DMA channel to use for transmitting data. Note that DMA channel 0 is not supported (as per ESP32's documentation),
         *  therefore it must be either DMA channel 1 or DMA channel 2.
         * @param response_irq_line The GPIO pin connected to the IRQ line on the PN532. The PN532 signals when the responses are available
         *  by setting this line to low; an interrupt triggers then a semaphore that allows this class to read the answer only once it's ready.
         * @param manage_isr_service If set to true, the class will call @ref gpio_install_isr_service and the corresponding uninstall command
         *  at destruction. Unless the caller manages the ISR service by themselves, this parm should be set to true.
         * @param buffer_pool Buffer pool to use for MAC. If `nullptr`, it uses @ref default_buffer_pool. This class
         *  retains a pointer to the buffer pool, so it cannot be changed after construction.
         * @see mlab::irq_assert
         * @note In case of invalid host, device or bus configuration, an error message is printed, but the class is correctly constructed. It will
         *  simply always fail to send and receive anything (and may clog your output with error messages).
         */
        spi_channel(spi_host_device_t host, spi_bus_config_t const &bus_config, spi_device_interface_config_t device_cfg, int dma_chan,
                    gpio_num_t response_irq_line, bool manage_isr_service, mlab::shared_buffer_pool buffer_pool = nullptr);

        ~spi_channel() override;
    };

}// namespace pn532::esp32

#endif//PN532_ESP32_SPI_HPP
