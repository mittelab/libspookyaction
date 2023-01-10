//
// Created by spak on 1/10/23.
//

#ifndef DESFIRE_ESP32_UTILS_HPP
#define DESFIRE_ESP32_UTILS_HPP

#include <vector>
#include <initializer_list>
#include <esp_log.h>

namespace desfire::esp32 {
    struct suppress_log {
        std::vector<std::pair<const char *, esp_log_level_t>> tag_log_lev{};
        bool is_suppressed = false;

        suppress_log() = default;
        suppress_log(std::initializer_list<const char *> tags);
        suppress_log(suppress_log const &) = delete;
        suppress_log(suppress_log &&other) noexcept;

        suppress_log &operator=(suppress_log const &other) = delete;
        suppress_log &operator=(suppress_log &&other) noexcept;

        void suppress();
        void restore();

        ~suppress_log();
    };
}

#endif//DESFIRE_ESP32_UTILS_HPP
