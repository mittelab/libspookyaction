//
// Created by spak on 1/19/23.
//

#ifndef DESFIRE_ESP32_TAG_RESPONDER_HPP
#define DESFIRE_ESP32_TAG_RESPONDER_HPP

#include <pn532/scanner.hpp>
#include <desfire/tag.hpp>
#include <pn532/desfire_pcd.hpp>

namespace desfire {
    template <class CipherProvider>
    struct tag_responder : virtual pn532::scanner_responder {
        /**
         * @brief Restricts only to @ref pn532::target_type::generic_passive_106kbps
         * @note The correct value for DesFIRE cards is not @ref pn532::target_type::mifare_classic_ultralight, otherwise
         *  the PN532 will enable syntax checking and prevent more advanced desfire commaands.
         * @param targets
         */
        void get_scan_target_types(pn532::scanner &, std::vector<pn532::target_type> &targets) const override;

        /**
         * @brief Calls @ref interact(tag &tag).
         */
        pn532::post_interaction interact(pn532::scanner &scanner, pn532::scanned_target const &target) override;

        virtual pn532::post_interaction interact_with_tag(desfire::tag &tag) = 0;
    };
}

namespace desfire {

    template <class CipherProvider>
    void tag_responder<CipherProvider>::get_scan_target_types(pn532::scanner &, std::vector<pn532::target_type> &targets) const {
        targets = {pn532::target_type::generic_passive_106kbps};
    }

    template <class CipherProvider>
    pn532::post_interaction tag_responder<CipherProvider>::interact(pn532::scanner &scanner, pn532::scanned_target const &target) {
        auto tag = tag::make<CipherProvider>(scanner.ctrl(), target.index);
        return interact_with_tag(tag);
    }
}

#endif//DESFIRE_ESP32_TAG_RESPONDER_HPP
