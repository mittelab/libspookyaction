//
// Created by spak on 1/10/23.
//

#ifndef DESFIRE_ESP32_UTILS_HPP
#define DESFIRE_ESP32_UTILS_HPP

#include <esp_log.h>
#include <initializer_list>
#include <vector>

namespace desfire::esp32 {
    /**
     * @brief A utility class to contextually enable/disable some of ESP32 log levels.
     * This class is RAII, so it will restore the original logging level when destroyed.
     * @note We can only *reduce* the log level, not increase it. Log levels that are not enabled
     *  at ESP32 configuration level are not available, as the statements are simply not compiled.
     */
    struct suppress_log {
        /**
         * A list of the log tags and their original log level.
         */
        std::vector<std::pair<const char *, esp_log_level_t>> tag_log_lev{};

        /**
         * The minimum level that is echoed.
         */
        esp_log_level_t min_level = ESP_LOG_NONE;

        /**
         * A boolean representing whether the suppression is active at the current moment in time.
         */
        bool is_suppressed = false;

        /**
         * Default-constructor, does nothing.
         */
        suppress_log() = default;

        /**
         * Suppresses instantly and entirely all the specified @p tags
         * @param tags List of log tags, e.g. `{"DESFIRE", "PN532"}`.
         */
        suppress_log(std::initializer_list<const char *> tags);

        /**
         * Suppresses all the specified @p tags, allowing only logging at @p min_level and above.
         * @param min_level Minimum level that is echoed.
         * @param tags List of log tags, e.g. `{"DESFIRE", "PN532"}`.
         */
        suppress_log(esp_log_level_t min_level, std::initializer_list<const char *> tags);

        /**
         * @name Move semantics
         * @{
         */
        suppress_log(suppress_log const &) = delete;
        suppress_log(suppress_log &&other) noexcept;

        suppress_log &operator=(suppress_log const &other) = delete;
        suppress_log &operator=(suppress_log &&other) noexcept;
        /**
         * @}
         */

        /**
         * Manually suppresses all the tags in @ref tag_log_lev to the minimum echoed level @ref min_level.
         */
        void suppress();

        /**
         * Manually restores all teh tags in @ref tag_log_lev to the level they had at the constrution of the object.
         */
        void restore();

        /**
         * Calls @ref restore before exiting.
         */
        ~suppress_log();
    };
}// namespace desfire::esp32

#endif//DESFIRE_ESP32_UTILS_HPP
