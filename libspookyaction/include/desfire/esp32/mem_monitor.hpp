//
// Created by spak on 3/10/21.
//

#ifndef DESFIRE_ESP32_MEM_MONITOR_HPP
#define DESFIRE_ESP32_MEM_MONITOR_HPP

#include <cstdint>

namespace desfire::esp32 {
    struct mem_monitor {
        mem_monitor();
        ~mem_monitor();
        mem_monitor(mem_monitor &&) noexcept = delete;
        mem_monitor(mem_monitor const &) = delete;
        mem_monitor &operator=(mem_monitor &&) noexcept = delete;
        mem_monitor &operator=(mem_monitor const &) = delete;
        [[nodiscard]] std::size_t count_leaked_memory() const;
    };

}// namespace desfire::esp32

#endif//DESFIRE_ESP32_MEM_MONITOR_HPP
