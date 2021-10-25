//
// Created by spak on 3/14/21.
//

#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <pn532/esp32/irq_assert.hpp>

#define PN532_IRQ_TAG "PN532-IRQ"

namespace pn532::esp32 {

    namespace {
        void IRAM_ATTR _irq_to_semaphore(void *semaphore_hdl) {
            xSemaphoreGiveFromISR(reinterpret_cast<SemaphoreHandle_t>(semaphore_hdl), nullptr);
        }
    }// namespace

    struct irq_assert::impl {
        SemaphoreHandle_t semaphore = nullptr;
        bool manage_isr_service = false;
        gpio_num_t pin = GPIO_NUM_NC;
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
        return GPIO_NUM_NC;
    }

    irq_assert::irq_assert(bool manage_isr_service, gpio_num_t pin, gpio_int_type_t interrupt_type) : _pimpl{std::make_unique<impl>()} {
        if (manage_isr_service) {
            if (const auto res = gpio_install_isr_service(0); res != ESP_OK) {
                ESP_LOGE(PN532_IRQ_TAG, "gpio_install_isr_service failed with status %d (%s).", res, esp_err_to_name(res));
                return;
            }
            _pimpl->manage_isr_service = true;
        }
        if (const auto res = gpio_set_intr_type(pin, interrupt_type); res != ESP_OK) {
            ESP_LOGE(PN532_IRQ_TAG, "gpio_set_intr_type failed with status %d (%s).", res, esp_err_to_name(res));
            return;
        }
        // Create finally the semaphore
        _pimpl->semaphore = xSemaphoreCreateBinary();
        if (_pimpl->semaphore == nullptr) {
            // We always assert whether semaphore is nullptr, so we just log
            ESP_LOGE(PN532_IRQ_TAG, "Failed to allocate semaphore with xSemaphoreCreateBinary.");
        } else {
            // Do not do anything special in case of failure: we will simply not handle anything
            ESP_ERROR_CHECK_WITHOUT_ABORT(gpio_isr_handler_add(pin, &_irq_to_semaphore, _pimpl->semaphore));
        }
        // Save the pin to flag that the handler must be removed
        _pimpl->pin = pin;
    }

    bool irq_assert::operator()(mlab::ms timeout) {
        if (_pimpl == nullptr) {
            return true;
        } else if (not _pimpl->semaphore) {
            ESP_LOGE(PN532_IRQ_TAG, "Attempt at taking invalid semaphore.");
            return false;
        }
        return xSemaphoreTake(_pimpl->semaphore, pdMS_TO_TICKS(timeout.count())) == pdTRUE;
    }

    irq_assert::~irq_assert() {
        if (_pimpl != nullptr) {
            if (_pimpl->pin != GPIO_NUM_NC) {
                ESP_ERROR_CHECK_WITHOUT_ABORT(gpio_isr_handler_remove(_pimpl->pin));
                _pimpl->pin = GPIO_NUM_NC;
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
}// namespace pn532::esp32
