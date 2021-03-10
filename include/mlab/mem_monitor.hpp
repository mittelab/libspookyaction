//
// Created by spak on 3/10/21.
//

#ifndef _GUARD_MLAB_MEM_MONITOR_HPP
#define _GUARD_MLAB_MEM_MONITOR_HPP
#include <esp_system.h>

namespace mlab {

    struct mem_monitor {
        const char *msg;
        std::int_least64_t expected_mem;
        inline void reduce(std::size_t expected_leak);
        inline explicit mem_monitor(const char *msg_);
        inline ~mem_monitor();
    };

}

namespace mlab {

    void mem_monitor::reduce(std::size_t expected_leak) {
        expected_mem -= expected_leak;
    }

    mem_monitor::mem_monitor(const char *msg_) : msg{msg_}, expected_mem{esp_get_free_heap_size()} {}

    mem_monitor::~mem_monitor() {
        const std::int_least64_t actual_mem = esp_get_free_heap_size();
        if (actual_mem != expected_mem) {
            ESP_LOGW("MEM", "%s: %+lld", msg, actual_mem - std::int_least64_t(expected_mem));
        }
    }
}

#endif//_GUARD_MLAB_MEM_MONITOR_HPP
