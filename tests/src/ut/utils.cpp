//
// Created by spak on 2/7/21.
//


#include "utils.hpp"
#include <desfire/log.h>

namespace ut {


    suppress_log::suppress_log(const char *tag_) : tag{tag_}, previous_log_level{esp_log_level_get(tag)} {
        suppress();
    }

    void suppress_log::suppress() {
        esp_log_level_set(tag, ESP_LOG_NONE);
    }

    void suppress_log::restore() {
        esp_log_level_set(tag, previous_log_level);
    }

    suppress_log::~suppress_log() {
        restore();
    }

    [[maybe_unused]] void enable_debug_log(log_options options) {
        if (options.generic) {
            esp_log_level_set(DESFIRE_TAG, ESP_LOG_DEBUG);
        }
        if (options.mac_cmac) {
            esp_log_level_set(DESFIRE_TAG " TX MAC", ESP_LOG_DEBUG);
            esp_log_level_set(DESFIRE_TAG " RX MAC", ESP_LOG_DEBUG);
            esp_log_level_set(DESFIRE_TAG " != MAC", ESP_LOG_DEBUG);
        }
        if (options.crypto_operations) {
            esp_log_level_set(DESFIRE_TAG " CRYPTO", ESP_LOG_DEBUG);
            esp_log_level_set(DESFIRE_TAG " DATA", ESP_LOG_DEBUG);
            esp_log_level_set(DESFIRE_TAG " BLOB", ESP_LOG_DEBUG);
            esp_log_level_set(DESFIRE_TAG "   IV", ESP_LOG_DEBUG);
        }
        if (options.plain_data) {
            esp_log_level_set(DESFIRE_TAG " >>", ESP_LOG_DEBUG);
            esp_log_level_set(DESFIRE_TAG " <<", ESP_LOG_DEBUG);
        }
        if (options.raw_data) {
            esp_log_level_set(DESFIRE_TAG " RAW >>", ESP_LOG_DEBUG);
            esp_log_level_set(DESFIRE_TAG " RAW <<", ESP_LOG_DEBUG);
        }
        if (options.reveal_keys) {
            esp_log_level_set(DESFIRE_TAG " KEY", ESP_LOG_DEBUG);
            esp_log_level_set(DESFIRE_TAG " KEY", ESP_LOG_DEBUG);
        }
    }


}// namespace ut