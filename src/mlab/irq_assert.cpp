//
// Created by spak on 3/14/21.
//

#include "mlab/irq_assert.hpp"
#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>


namespace mlab {

    namespace {
        void IRAM_ATTR _irq_to_semaphore(void *semaphore_hdl) {
            xSemaphoreGiveFromISR(reinterpret_cast<SemaphoreHandle_t>(semaphore_hdl), nullptr);
        }
    }// namespace

    struct irq_assert::impl {
        SemaphoreHandle_t semaphore = nullptr;
        bool manage_isr_service = false;
        gpio_num_t pin = GPIO_NUM_MAX;
    };

    /**
     * @addtogroup PIMPL
     * These implementations, despite being default, must appear after @ref irq_assert::impl is complete, because
     * they require the corresponding operators/constructors from `unique_ptr`, and those are only defined once
     * the type is complete. As a workaround, the `unique_ptr` could be created with an erased deleter (e.g.
     * some `std::default_delete<irq_assert::impl>` erased as `std::function<void(void *)>`, but is not worth it.
     * @{
     */
    irq_assert::irq_assert() = default;

    irq_assert::irq_assert(irq_assert &&) noexcept = default;

    irq_assert &irq_assert::operator=(irq_assert &&) noexcept = default;
    /**
     * @}
     */

    gpio_num_t irq_assert::pin() const {
        if (_pimpl) {
            return _pimpl->pin;
        }
        return GPIO_NUM_MAX;
    }

    irq_assert::irq_assert(bool manage_isr_service, gpio_num_t pin, gpio_int_type_t interrupt_type) : _pimpl{std::make_unique<impl>()} {
        if (manage_isr_service) {
            if (const auto res = gpio_install_isr_service(0); res != ESP_OK) {
                ESP_LOGE("MLAB", "gpio_install_isr_service failed with status %d (%s).", res, esp_err_to_name(res));
                return;
            }
            _pimpl->manage_isr_service = true;
        }
        if (const auto res = gpio_set_intr_type(pin, interrupt_type); res != ESP_OK) {
            ESP_LOGE("MLAB", "gpio_set_intr_type failed with status %d (%s).", res, esp_err_to_name(res));
            return;
        }
        // Create finally the semaphore
        _pimpl->semaphore = xSemaphoreCreateBinary();
        configASSERT(_pimpl->semaphore);
        if (const auto res = gpio_isr_handler_add(pin, &_irq_to_semaphore, _pimpl->semaphore); res != ESP_OK) {
            ESP_LOGE("MLAB", "gpio_isr_handler_add failed with status %d (%s).", res, esp_err_to_name(res));
        }
        // Save the pin to flag that the handler must be removed
        _pimpl->pin = pin;
    }

    bool irq_assert::operator()(ms timeout) {
        if (_pimpl == nullptr) {
            return true;
        } else if (not _pimpl->semaphore) {
            ESP_LOGE("MLAB", "Attempt at taking invalid semaphore.");
            return false;
        }
        return xSemaphoreTake(_pimpl->semaphore, pdMS_TO_TICKS(timeout.count())) == pdTRUE;
    }

    irq_assert::~irq_assert() {
        if (_pimpl != nullptr) {
            if (_pimpl->pin != GPIO_NUM_MAX) {
                if (const auto res = gpio_isr_handler_remove(_pimpl->pin); res != ESP_OK) {
                    ESP_LOGW("MLAB", "gpio_isr_handler_remove failed with status %d (%s).", res, esp_err_to_name(res));
                }
                _pimpl->pin = GPIO_NUM_MAX;
            }
            if (_pimpl->semaphore) {
                vPortFree(_pimpl->semaphore);
                _pimpl->semaphore = nullptr;
            }
            if (_pimpl->manage_isr_service) {
                gpio_uninstall_isr_service();
            }
        }
    }
}// namespace mlab
