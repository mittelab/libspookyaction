//
// Created by Pietro Saccardi on 04/01/2021.
//

#ifndef PN532_DESFIRE_PCD_HPP
#define PN532_DESFIRE_PCD_HPP

#include <desfire/pcd.hpp>
#include <pn532/controller.hpp>

namespace pn532 {
    /**
     * @brief Interfaces a PN532 controller as a PCD for operating on Desfire cards.
     *
     * This class is essentially a wrapper around @ref controller::initiator_data_exchange.
     * At this point, much of the PN532 error codes are not echoed through any of @ref desfire::tag result types,
     * since an error at the PN532 level is just @ref desfire::error::controller_error. To debug the behavior, inspect
     * this instance's @ref last_result property.
     */
    class desfire_pcd final : public desfire::pcd {
        controller *_pcd;
        std::uint8_t _target;
        pn532::result<rf_status> _last_result;

        [[nodiscard]] inline controller &ctrl();

    public:
        /**
         * Initializes the PCD around @p controller.
         * @param controller The PN532 controller instance which is going to communicate with the Desfire card.
         *  The reference must be valid throughout the whole lifetime of this object.
         * @param target_logical_index The logical index of the Desfire NFC target; can be obtained with
         *  @ref controller::initiator_list_passive_kbps106_typea.
         * @todo Consider using a shared pointer for @p controller.
         */
        inline desfire_pcd(controller &controller, std::uint8_t target_logical_index);

        /**
         * The original logical index with which this class was constructed.
         */
        [[nodiscard]] inline std::uint8_t target_logical_index() const;
        /**
         * The original @ref controller reference with which this class was constructed.
         */
        [[nodiscard]] inline controller &tag_reader();
        /**
         * @copydoc tag_reader()
         */
        [[nodiscard]] inline controller const &tag_reader() const;

        /**
         * The last @ref rf_status result that was obtained through a call to @ref communicate.
         */
        [[nodiscard]] inline pn532::result<rf_status> last_result() const;

        /**
         * @brief Wrapper around @ref controller::initiator_data_exchange.
         * A call to this method will update @ref last_result.
         */
        std::optional<bin_data> communicate(bin_data const &data) override;
    };
}// namespace pn532

namespace pn532 {
    desfire_pcd::desfire_pcd(controller &controller, std::uint8_t target_logical_index) : _pcd{&controller}, _target{target_logical_index},
                                                                                          _last_result{rf_status{false, false, internal_error_code::none}} {
    }

    controller &desfire_pcd::ctrl() { return *_pcd; }

    std::uint8_t desfire_pcd::target_logical_index() const {
        return _target;
    }

    pn532::result<rf_status> desfire_pcd::last_result() const {
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
