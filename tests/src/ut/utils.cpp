//
// Created by spak on 2/7/21.
//


#include "utils.hpp"
#include <desfire/log.h>

namespace ut {

    unity_patch_test_file::unity_patch_test_file(const char *new_file) : prev_test_file{Unity.TestFile} {
        Unity.TestFile = new_file;
    }

    unity_patch_test_file::~unity_patch_test_file() {
        Unity.TestFile = prev_test_file;
    }

    [[maybe_unused]] void enable_debug_log(log_options options) {
        if (options.generic) {
            esp_log_level_set(DESFIRE_LOG_PREFIX, ESP_LOG_DEBUG);
        }
        if (options.mac_cmac) {
            esp_log_level_set(DESFIRE_LOG_PREFIX " TX MAC", ESP_LOG_DEBUG);
            esp_log_level_set(DESFIRE_LOG_PREFIX " RX MAC", ESP_LOG_DEBUG);
            esp_log_level_set(DESFIRE_LOG_PREFIX " != MAC", ESP_LOG_DEBUG);
        }
        if (options.crypto_operations) {
            esp_log_level_set(DESFIRE_LOG_PREFIX " CRYPTO", ESP_LOG_DEBUG);
            esp_log_level_set(DESFIRE_LOG_PREFIX " DATA", ESP_LOG_DEBUG);
            esp_log_level_set(DESFIRE_LOG_PREFIX " BLOB", ESP_LOG_DEBUG);
            esp_log_level_set(DESFIRE_LOG_PREFIX "   IV", ESP_LOG_DEBUG);
        }
        if (options.plain_data) {
            esp_log_level_set(DESFIRE_LOG_PREFIX " >>", ESP_LOG_DEBUG);
            esp_log_level_set(DESFIRE_LOG_PREFIX " <<", ESP_LOG_DEBUG);
        }
        if (options.raw_data) {
            esp_log_level_set(DESFIRE_LOG_PREFIX " RAW >>", ESP_LOG_DEBUG);
            esp_log_level_set(DESFIRE_LOG_PREFIX " RAW <<", ESP_LOG_DEBUG);
        }
        if (options.reveal_keys) {
            esp_log_level_set(DESFIRE_LOG_PREFIX " KEY", ESP_LOG_DEBUG);
            esp_log_level_set(DESFIRE_LOG_PREFIX " KEY", ESP_LOG_DEBUG);
        }
    }


}// namespace ut