//
// Created by spak on 1/19/23.
//

#ifndef DESFIRE_ESP32_TAG_RESPONDER_HPP
#define DESFIRE_ESP32_TAG_RESPONDER_HPP

#include <desfire/tag.hpp>
#include <pn532/desfire_pcd.hpp>
#include <pn532/scanner.hpp>

namespace desfire {
    /**
     * Specialized @ref pn532::scanner_responder that interacts with a @ref tag.
     * @tparam CipherProvider The templated cipher provider class that is used to construct @ref tag::tag
     * @see desfire::esp32::default_cipher_provider
     */
    template <class CipherProvider>
    struct tag_responder : virtual pn532::scanner_responder {
        /**
         * @brief Restricts only to @ref pn532::target_type::passive_106kbps_iso_iec_14443_4_typea
         * @note The correct value for DesFIRE cards is not @ref pn532::target_type::mifare_classic_ultralight, otherwise
         *  the PN532 will enable syntax checking and prevent more advanced desfire commands.
         */
        [[nodiscard]] std::vector<pn532::target_type> get_scan_target_types(pn532::scanner &) const override;

        /**
         * @brief Calls @ref interact
         */
        pn532::post_interaction interact(pn532::scanner &scanner, pn532::scanned_target const &target) override;

        /**
         * Abstract function for interacting with a Desfire tag.
         * @param tag Tag that has been detected by the PN532.
         * @returns One @ref pn532::post_interaction return codes.
         */
        virtual pn532::post_interaction interact_with_tag(tag &tag) = 0;
    };
}// namespace desfire

namespace desfire {

    template <class CipherProvider>
    std::vector<pn532::target_type> tag_responder<CipherProvider>::get_scan_target_types(pn532::scanner &) const {
        return {pn532::target_type::passive_106kbps_iso_iec_14443_4_typea};
    }

    template <class CipherProvider>
    pn532::post_interaction tag_responder<CipherProvider>::interact(pn532::scanner &scanner, pn532::scanned_target const &target) {
        auto tag = tag::make<CipherProvider>(scanner.ctrl(), target.index);
        return interact_with_tag(tag);
    }
}// namespace desfire

#endif//DESFIRE_ESP32_TAG_RESPONDER_HPP
