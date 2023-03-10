//
// Created by spak on 3/14/21.
//

#ifndef PN532_ESP32_IRQ_ASSERT_HPP
#define PN532_ESP32_IRQ_ASSERT_HPP

#include <driver/gpio.h>
#include <memory>
#include <mlab/time.hpp>

namespace pn532::esp32 {
    /**
     * @brief Semaphore-like class which responds to a ESP32 GPIO interrupt.
     * You can invoke @ref operator()() of this class, and the current task will stay suspended until
     * the selected interrupt triggers on the given GPIO. Internally, it uses the ESP32's interrupt system,
     * so that the CPU is effectively available for other tasks.
     * @note This class currently only supports one type of trigger.
     */
    class irq_assert {
        struct impl;
        std::unique_ptr<impl> _pimpl;

    public:
        /**
         * Default constructor: always asserts `true` when calling @ref operator()().
         */
        irq_assert();

        /**
         * @name Enforced move semantics
         * @{
         */
        irq_assert(irq_assert &&) noexcept;
        irq_assert &operator=(irq_assert &&) noexcept;

        irq_assert(irq_assert const &) noexcept = delete;
        irq_assert &operator=(irq_assert const &) noexcept = delete;
        /**
         * @}
         */

        /**
         * Constructs a new class that is able to wait for a GPIO interrupt.
         * @param manage_isr_service If true, this class will call `gpio_install_isr_service` and the corresponding
         *  `gpio_uninstall_isr_service` upon construction and destruction, respectively.
         * @param pin GPIO pin where to listen for an interrupt.
         * @param interrupt_type Type of interrupt to receive, by default negative edge.
         */
        explicit irq_assert(bool manage_isr_service, gpio_num_t pin, gpio_int_type_t interrupt_type = GPIO_INTR_NEGEDGE);

        /**
         * @brief The pin on which this instance has set up an interrupt.
         * @return A pin number or `GPIO_NUM_NC`, if this instance was default-constructed.
         */
        [[nodiscard]] gpio_num_t pin() const;

        /**
         * @brief Hangs until the interrupt triggers.
         * Waits at most @p timeout and returns true if and only if @ref pin asserts the interrupt.
         * @param timeout Maximum timeout before returning false.
         * @return True if the interrupt specified at runtime has been triggered on the given pin.
         * @note Always asserts true if @ref irq_assert was default constructed.
         */
        bool operator()(mlab::ms timeout);

        /**
         * Releases all resources, and, if specified, calls `gpio_uninstall_isr_service`.
         */
        ~irq_assert();
    };

}// namespace pn532::esp32

#endif//PN532_ESP32_IRQ_ASSERT_HPP
