//
// Created by spak on 3/14/21.
//

#ifndef MLAB_IRQ_ASSERT_HPP
#define MLAB_IRQ_ASSERT_HPP

#include "time.hpp"
#include <driver/gpio.h>
#include <memory>

namespace mlab {
    class irq_assert {
        struct impl;
        std::unique_ptr<impl> _pimpl;

    public:
        /**
         * Default constructor: always asserts `true` at @ref ::operator()
         */
        irq_assert();

        irq_assert(irq_assert &&) noexcept;
        irq_assert &operator=(irq_assert &&) noexcept;

        irq_assert(irq_assert const &) noexcept = delete;
        irq_assert &operator=(irq_assert const &) noexcept = delete;

        explicit irq_assert(bool manage_isr_service, gpio_num_t pin, gpio_int_type_t interrupt_type = GPIO_INTR_NEGEDGE);

        /**
         * @return `GPIO_NUM_NC` (indicating this @ref irq_assert object asserts no pin and always returns true), or the corresponding pin number.
         */
        [[nodiscard]] gpio_num_t pin() const;
        /**
         * Waits at most @p timeout and returns true if and only if the given pin asserts the interrupt.
         * @param timeout Maximum timeout before returning `false`.
         * @return True if the interrupt specified at runtime has been triggered on the given pin.
         * @note Always asserts true if @ref irq_assert was default constructed.
         */
        bool operator()(ms timeout);

        ~irq_assert();
    };

}// namespace mlab

#endif//MLAB_IRQ_ASSERT_HPP
