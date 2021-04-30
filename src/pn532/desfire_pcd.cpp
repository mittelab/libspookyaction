//
// Created by Pietro Saccardi on 04/01/2021.
//

#include "pn532/desfire_pcd.hpp"

namespace pn532 {
    std::pair<bin_data, bool> desfire_pcd::communicate(bin_data const &data) {
        if (auto res = pcd().initiator_data_exchange(target_logical_index(), data); res) {
            _last_result = nfc::result<rf_status>{res->first};
            if (res->first.error != controller_error::none) {
                PN532_LOGE("PCD/PICC comm failed at protocol level, %s", to_string(res->first.error));
            }
            // Check also the RF status
            return {std::move(res->second), res->first.error == controller_error::none};
        } else {
            PN532_LOGE("PCD/PICC comm failed at NFC level, %s", to_string(res.error()));
            _last_result = nfc::result<rf_status>{res.error()};
            return {bin_data{}, false};
        }
    }
}// namespace pn532