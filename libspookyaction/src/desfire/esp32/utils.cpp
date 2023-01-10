//
// Created by spak on 1/10/23.
//

#include <desfire/esp32/utils.hpp>

namespace desfire::esp32 {

    suppress_log::suppress_log(std::initializer_list<const char *> tags) {
        tag_log_lev.reserve(tags.size());
        for (const char *tag : tags) {
            tag_log_lev.emplace_back(tag, esp_log_level_get(tag));
        }
        suppress();
    }

    suppress_log::suppress_log(suppress_log &&other) noexcept : tag_log_lev{}
    {
        this->operator=(std::move(other));
    }

    suppress_log &suppress_log::operator=(suppress_log &&other) noexcept {
        restore();
        tag_log_lev.clear();
        std::swap(tag_log_lev, other.tag_log_lev);
        return *this;
    }

    void suppress_log::suppress() {
        for (auto const &tag_lev : tag_log_lev) {
            esp_log_level_set(tag_lev.first, ESP_LOG_NONE);
        }
    }

    void suppress_log::restore() {
        for (auto const &[tag, lev] : tag_log_lev) {
            esp_log_level_set(tag, lev);
        }
    }

    suppress_log::~suppress_log() {
        restore();
    }
}// namespace desfire::esp32
