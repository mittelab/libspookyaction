//
// Created by spak on 2/7/21.
//


#include "utils.hpp"
#include <desfire/log.h>

namespace ut {


    suppress_log::suppress_log(std::initializer_list<const char *> tags) {
        tag_log_lev.reserve(tags.size());
        for (const char *tag : tags) {
            tag_log_lev.emplace_back(tag, esp_log_level_get(tag));
        }
        suppress();
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

    unity_patch_test_file::unity_patch_test_file(const char *new_file) : prev_test_file{Unity.TestFile} {
        Unity.TestFile = new_file;
    }

    unity_patch_test_file::~unity_patch_test_file() {
        Unity.TestFile = prev_test_file;
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