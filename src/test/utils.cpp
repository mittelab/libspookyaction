//
// Created by spak on 2/7/21.
//


#include "utils.hpp"
#include <desfire/log.h>

namespace ut {

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