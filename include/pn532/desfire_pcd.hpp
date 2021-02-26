//
// Created by Pietro Saccardi on 04/01/2021.
//

#ifndef PN532_DESFIRE_PCD_HPP
#define PN532_DESFIRE_PCD_HPP

#include "desfire/controller.hpp"
#include "nfc.hpp"

namespace pn532 {
    class desfire_pcd final : public desfire::controller {
        nfc *_pcd;
        std::uint8_t _target;
        nfc::r<rf_status> _last_result;

        [[nodiscard]] inline nfc &pcd();

    public:
        inline desfire_pcd(nfc &controller, std::uint8_t target_logical_index);

        [[nodiscard]] inline nfc::r<rf_status> last_result() const;
        [[nodiscard]] inline std::uint8_t target_logical_index() const;

        std::pair<bin_data, bool> communicate(bin_data const &data) override;
    };
}// namespace pn532

namespace pn532 {
    desfire_pcd::desfire_pcd(nfc &controller, std::uint8_t target_logical_index) : _pcd{&controller}, _target{target_logical_index},
                                                                                   _last_result{rf_status{false, false, controller_error::none}} {}

    nfc &desfire_pcd::pcd() { return *_pcd; }

    std::uint8_t desfire_pcd::target_logical_index() const {
        return _target;
    }

    nfc::r<rf_status> desfire_pcd::last_result() const {
        return _last_result;
    }

}// namespace pn532

#endif//PN532_DESFIRE_PCD_HPP
