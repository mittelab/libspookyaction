//
// Created by spak on 1/10/23.
//

#include <desfire/esp32/utils.hpp>

namespace desfire::esp32 {

    suppress_log::suppress_log(esp_log_level_t min_level, std::initializer_list<const char *> tags) : tag_log_lev{}, min_level{min_level}
    {
        tag_log_lev.reserve(tags.size());
        for (const char *tag : tags) {
            tag_log_lev.emplace_back(tag, esp_log_level_get(tag));
        }
        suppress();
    }

    suppress_log::suppress_log(std::initializer_list<const char *> tags) : suppress_log{ESP_LOG_NONE, tags} {}

    suppress_log::suppress_log(suppress_log &&other) noexcept : tag_log_lev{}
    {
        this->operator=(std::move(other));
    }

    suppress_log &suppress_log::operator=(suppress_log &&other) noexcept {
        std::swap(tag_log_lev, other.tag_log_lev);
        std::swap(is_suppressed, other.is_suppressed);
        return *this;
    }

    void suppress_log::suppress() {
        if (not is_suppressed) {
            is_suppressed = true;
            for (auto const &tag_lev : tag_log_lev) {
                esp_log_level_set(tag_lev.first, min_level);
            }
        }
    }

    void suppress_log::restore() {
        if (is_suppressed) {
            is_suppressed = false;
            for (auto const &[tag, lev] : tag_log_lev) {
                esp_log_level_set(tag, lev);
            }
        }
    }

    suppress_log::~suppress_log() {
        restore();
    }
}// namespace desfire::esp32
