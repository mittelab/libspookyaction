//
// Created by spak on 3/10/21.
//

#ifndef DESFIRE_ESP32_MEM_MONITOR_HPP
#define DESFIRE_ESP32_MEM_MONITOR_HPP

#include <cstdint>

namespace desfire::esp32 {
    /**
     * Utility class that snapshots heap memory and checks if there is any leak.
     * @note You must have `CONFIG_HEAP_TRACING` defined in your ESP32 configuration for this to work.
     */
    struct mem_monitor {
        /**
         * Initializes the memory monitor with `heap_trace_init_standalone` and `heap_trace_start`.
         */
        mem_monitor();
        /**
         * Stops heap tracing with `heap_trace_stop` and unhooks this class from ESP32's heap tracing system.
         */
        ~mem_monitor();
        /**
         * @name Non-copiable, non-moveable
         * @{
         */
        mem_monitor(mem_monitor &&) noexcept = delete;
        mem_monitor(mem_monitor const &) = delete;
        mem_monitor &operator=(mem_monitor &&) noexcept = delete;
        mem_monitor &operator=(mem_monitor const &) = delete;
        /**
         * @}
         */

        /**
         * Returns the amount of memory leaked in bytes.
         * @return A number, always 0 if `CONFIG_HEAP_TRACING` is disabled.
         */
        [[nodiscard]] std::size_t count_leaked_memory() const;
    };

}// namespace desfire::esp32

#endif//DESFIRE_ESP32_MEM_MONITOR_HPP
