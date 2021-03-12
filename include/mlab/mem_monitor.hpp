//
// Created by spak on 3/10/21.
//

#ifndef MLAB_MEM_MONITOR_HPP
#define MLAB_MEM_MONITOR_HPP

#include <esp_heap_trace.h>

namespace mlab {
    namespace trace {
        static constexpr std::size_t num_records = 100;
        static heap_trace_record_t records[num_records]; // This buffer must be in internal RAM
    }

    struct mem_monitor {
        inline mem_monitor();
        inline ~mem_monitor();
        mem_monitor(mem_monitor &&) noexcept = delete;
        mem_monitor(mem_monitor const &) = delete;
        mem_monitor & operator=(mem_monitor &&) noexcept = delete;
        mem_monitor & operator=(mem_monitor const &) = delete;
        [[nodiscard]] inline std::size_t count_leaked_memory() const;
    };

}

namespace mlab {

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

}

#endif//MLAB_MEM_MONITOR_HPP
