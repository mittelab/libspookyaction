//
// Created by Pietro Saccardi on 04/01/2021.
//

#include <pn532/desfire_pcd.hpp>

namespace pn532 {
    std::optional<bin_data> desfire_pcd::communicate(bin_data const &data) {
        if (auto res = ctrl().initiator_data_exchange(target_logical_index(), data); res) {
            _last_result = result<rf_status>{res->first};
            if (res->first.error != internal_error_code::none) {
                PN532_LOGE("PCD/PICC comm failed at protocol level, %s", to_string(res->first.error));
            }
            // Check also the RF status
            if (res->first.error == internal_error_code::none) {
                return std::move(res->second);
            }
        } else {
            PN532_LOGE("PCD/PICC comm failed at NFC level, %s", to_string(res.error()));
            _last_result = result<rf_status>{res.error()};
        }
        return std::nullopt;
    }
}// namespace pn532