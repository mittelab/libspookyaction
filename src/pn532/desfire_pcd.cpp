//
// Created by Pietro Saccardi on 04/01/2021.
//

#include "pn532/desfire_pcd.hpp"

namespace pn532 {
    std::pair<bin_data, bool> desfire_pcd::communicate(bin_data const &data) {
        auto res = pcd().initiator_data_exchange(target_logical_index(), data);
        if (res) {
            _last_result = nfc::r<rf_status>{res->first};
            // Check also the RF status
            return {std::move(res->second), res->first.error == controller_error::none};
        } else {
            _last_result = nfc::r<rf_status>{res.error()};
            return {bin_data{}, false};
        }
    }
}