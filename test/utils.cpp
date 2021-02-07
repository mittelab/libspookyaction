//
// Created by spak on 2/7/21.
//

#include <unity.h>
#include "utils.hpp"

namespace ut {
    std::pair<mlab::bin_data, bool> assert_comm_controller::communicate(const mlab::bin_data &data) {
        auto txrx_pair = std::move(txrx_fifo.front());
        txrx_fifo.pop_front();
        TEST_ASSERT_EQUAL_HEX8_ARRAY(txrx_pair.first.data(), data.data(), std::min(txrx_pair.first.size(), data.size()));
        TEST_ASSERT_EQUAL(txrx_pair.first.size(), data.size());
        return {std::move(txrx_pair.second), true};
    }

    void assert_comm_controller::append(std::initializer_list<std::uint8_t> tx,
                                        std::initializer_list<std::uint8_t> rx) {
        txrx_fifo.push_back(std::make_pair(mlab::bin_data::chain(tx), mlab::bin_data::chain(rx)));
    }


    void enable_detailed_log() {
        esp_log_level_set(DESFIRE_TAG, ESP_LOG_DEBUG);
        esp_log_level_set(DESFIRE_TAG " >>", ESP_LOG_DEBUG);
        esp_log_level_set(DESFIRE_TAG " <<", ESP_LOG_DEBUG);
        esp_log_level_set(DESFIRE_TAG " RAW >>", ESP_LOG_DEBUG);
        esp_log_level_set(DESFIRE_TAG " RAW <<", ESP_LOG_DEBUG);
        esp_log_level_set(DESFIRE_TAG " TX MAC", ESP_LOG_DEBUG);
        esp_log_level_set(DESFIRE_TAG " RX MAC", ESP_LOG_DEBUG);
        esp_log_level_set(DESFIRE_TAG " != MAC", ESP_LOG_DEBUG);
        esp_log_level_set(DESFIRE_TAG " CRYPTO", ESP_LOG_DEBUG);
        esp_log_level_set(DESFIRE_TAG " DATA", ESP_LOG_DEBUG);
        esp_log_level_set(DESFIRE_TAG " BLOB", ESP_LOG_DEBUG);
        esp_log_level_set(DESFIRE_TAG "   IV", ESP_LOG_DEBUG);
    }
}