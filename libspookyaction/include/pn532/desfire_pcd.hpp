//
// Created by Pietro Saccardi on 04/01/2021.
//

#ifndef PN532_DESFIRE_PCD_HPP
#define PN532_DESFIRE_PCD_HPP

#include "controller.hpp"
#include "desfire/pcd.hpp"

namespace pn532 {
    class desfire_pcd final : public desfire::pcd {
        controller *_pcd;
        std::uint8_t _target;
        controller::result<rf_status> _last_result;

        [[nodiscard]] inline controller &ctrl();

    public:
        inline desfire_pcd(controller &controller, std::uint8_t target_logical_index);

        [[nodiscard]] inline controller &tag_reader();
        [[nodiscard]] inline controller const &tag_reader() const;
        [[nodiscard]] inline controller::result<rf_status> last_result() const;
        [[nodiscard]] inline std::uint8_t target_logical_index() const;

        std::pair<bin_data, bool> communicate(bin_data const &data) override;
    };
}// namespace pn532

namespace pn532 {
    desfire_pcd::desfire_pcd(controller &controller, std::uint8_t target_logical_index) : _pcd{&controller}, _target{target_logical_index},
                                                                                          _last_result{rf_status{false, false, controller_error::none}} {
        _pcd->rf_configuration_field(true, true);
        _pcd->initiator_select(target_logical_index);
    }

    controller &desfire_pcd::ctrl() { return *_pcd; }

    std::uint8_t desfire_pcd::target_logical_index() const {
        return _target;
    }

    controller::result<rf_status> desfire_pcd::last_result() const {
        return _last_result;
    }

    controller &desfire_pcd::tag_reader() {
        return *_pcd;
    }
    controller const &desfire_pcd::tag_reader() const {
        return *_pcd;
    }

}// namespace pn532

#endif//PN532_DESFIRE_PCD_HPP
