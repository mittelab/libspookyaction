//
// Created by spak on 3/14/21.
//

#include <desfire/esp32/mem_monitor.hpp>
#include <esp_log.h>
#include <sdkconfig.h>

#if defined(CONFIG_HEAP_TRACING) or defined(HEAP_TRACE_SRCFILE)
#include <esp_heap_trace.h>

namespace desfire::esp32 {

    namespace trace {
        static constexpr std::size_t num_records = 100;
        /**
         * @note This buffer must be in internal RAM
         */
        static heap_trace_record_t records[num_records];
    }// namespace trace

    mem_monitor::mem_monitor() {
        ESP_LOGI("MEM", "Begin heap monitoring");
        ESP_ERROR_CHECK(heap_trace_init_standalone(trace::records, trace::num_records));
        ESP_ERROR_CHECK(heap_trace_start(HEAP_TRACE_LEAKS));
    }

    mem_monitor::~mem_monitor() {
        ESP_ERROR_CHECK(heap_trace_stop());
        if (const auto leaked = count_leaked_memory(); leaked > 0) {
            ESP_LOGW("MEM", "End heap monitoring, leak: %d", leaked);
            heap_trace_dump();
        } else {
            ESP_LOGI("MEM", "End heap monitoring, no leak.");
        }
        ESP_ERROR_CHECK(heap_trace_init_standalone(nullptr, 0));
    }

    std::size_t mem_monitor::count_leaked_memory() const {
        std::size_t leaked = 0;
        for (std::size_t i = 0; i < heap_trace_get_count(); ++i) {
            heap_trace_record_t record{};
            heap_trace_get(i, &record);
            leaked += record.size;
        }
        return leaked;
    }
}// namespace desfire::esp32

#else

namespace desfire::esp32 {

    namespace {
        void log_cannot_monitor_mem() {
            ESP_LOGE("MEM", "To trace memory you must define CONFIG_HEAP_TRACING or HEAP_TRACE_SRCFILE.");
        }
    }// namespace

    mem_monitor::mem_monitor() {
        log_cannot_monitor_mem();
    }

    mem_monitor::~mem_monitor() = default;

    std::size_t mem_monitor::count_leaked_memory() const {
        return 0;
    }
}// namespace desfire::esp32
#endif
