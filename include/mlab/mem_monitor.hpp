//
// Created by spak on 3/10/21.
//

#ifndef MLAB_MEM_MONITOR_HPP
#define MLAB_MEM_MONITOR_HPP

#include <esp_heap_trace.h>

namespace mlab {
    namespace trace {
        static constexpr std::size_t num_records = 100;
        static heap_trace_record_t records[num_records];// This buffer must be in internal RAM
    }                                                   // namespace trace

    struct mem_monitor {
        mem_monitor();
        ~mem_monitor();
        mem_monitor(mem_monitor &&) noexcept = delete;
        mem_monitor(mem_monitor const &) = delete;
        mem_monitor &operator=(mem_monitor &&) noexcept = delete;
        mem_monitor &operator=(mem_monitor const &) = delete;
        [[nodiscard]] std::size_t count_leaked_memory() const;
    };

}// namespace mlab

#endif//MLAB_MEM_MONITOR_HPP
