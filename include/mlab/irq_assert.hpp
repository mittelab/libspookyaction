//
// Created by spak on 3/14/21.
//

#ifndef MLAB_IRQ_ASSERT_HPP
#define MLAB_IRQ_ASSERT_HPP

#include <driver/gpio.h>
#include <memory>
#include "time.hpp"

namespace mlab {
    class irq_assert {
        struct impl;
        std::unique_ptr<impl> _pimpl;
    public:
        explicit irq_assert(bool manage_isr_service, gpio_num_t pin, gpio_int_type_t interrupt_type = GPIO_INTR_NEGEDGE);
        bool operator()(ms timeout);
        ~irq_assert();
    };

}

#endif//MLAB_IRQ_ASSERT_HPP
