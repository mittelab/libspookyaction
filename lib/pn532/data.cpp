//
// Created by Pietro Saccardi on 22/12/2020.
//

#include "data.hpp"

namespace pn532 {

    bin_data &operator<<(bin_data &bd, ciu_reg_212_424kbps const &reg) {
        bd.reserve(bd.size() + sizeof(ciu_reg_212_424kbps));
        return bd << reg.rf_cfg << reg.gs_n_on << reg.cw_gs_p << reg.mod_gs_p << reg.demod_own_rf_on
            << reg.rx_threshold << reg.demod_own_rf_off << reg.gs_n_off;
    }

    bin_data &operator<<(bin_data &bd, ciu_reg_106kbps_typea const &reg) {
        bd.reserve(bd.size() + sizeof(ciu_reg_106kbps_typea));
        return bd << reg.rf_cfg << reg.gs_n_on << reg.cw_gs_p << reg.mod_gs_p << reg.demod_own_rf_on << reg.rx_threshold
            << reg.demod_own_rf_off << reg.gs_n_off << reg.mod_width << reg.mif_nfc << reg.tx_bit_phase;
    }

    bin_data &operator<<(bin_data &bd, ciu_reg_typeb const &reg) {
        bd.reserve(bd.size() + sizeof(ciu_reg_typeb));
        return bd << reg.gs_n_on << reg.mod_gs_p << reg.rx_threshold;
    }

    bin_data &operator<<(bin_data &bd, ciu_reg_iso_iec_14443_4_at_baudrate const &reg) {
        bd.reserve(bd.size() + sizeof(ciu_reg_iso_iec_14443_4_at_baudrate));
        return bd << reg.rx_threshold << reg.mod_width << reg.mif_nfc;
    }

    bin_data &operator<<(bin_data &bd, ciu_reg_iso_iec_14443_4 const &reg) {
        bd.reserve(bd.size() + sizeof(ciu_reg_iso_iec_14443_4));
        return bd << reg.kbps212 << reg.kbps424 << reg.kbps848;
    }

    bin_data &operator<<(bin_data &bd, uid_cascade_l1 const &uid) {
        bd.push_back(std::begin(uid), std::end(uid));
        return bd;
    }

    bin_data &operator<<(bin_data &bd, uid_cascade_l2 const &uid) {
        bd.reserve(bd.size() + 8);
        bd << bits::uid_cascade_tag;
        bd.push_back(std::begin(uid), std::end(uid));
        return bd;
    }

    bin_data &operator<<(bin_data &bd, uid_cascade_l3 const &uid) {
        bd.reserve(bd.size() + 12);
        bd << bits::uid_cascade_tag;
        bd.push_back(std::begin(uid), std::begin(uid) + 3);
        bd << bits::uid_cascade_tag;
        bd.push_back(std::begin(uid) + 3, std::end(uid));
        return bd;
    }

    bin_data const &operator>>(bin_data const &bd, std::pair<target_kbps106_typea, bool> &target_success) {
        auto &target = target_success.first;
        auto &success = target_success.second;
        success = false;

        if (bd.size() < 5) {
            LOGW("Unable to parse kbps106_iso_iec_14443_typea target info, too little data.");
            return bd;
        }

        target.logical_index = bd[0];
        target.info.sens_res = (std::uint16_t(bd[1]) << 8) | bd[2];
        target.info.sel_res = bd[3];

        const auto expected_nfcid_length = bd[4];
        if (bd.size() < 5 + expected_nfcid_length) {
            LOGW("Unable to parse kbps106_iso_iec_14443_typea target info, missing NFC ID data.");
            return bd;
        }
        target.info.nfcid = std::vector<std::uint8_t>{std::begin(bd) + 5, std::begin(bd) + 5 + expected_nfcid_length};
        target.info.ats = {};
        if (bd.size() > 5 + expected_nfcid_length) {
            const auto expected_ats_length = bd[5 + expected_nfcid_length];
            if (bd.size() != 5 + expected_nfcid_length + expected_ats_length) {
                LOGW("Unable to parse kbps106_iso_iec_14443_typea target info, incorrect ATS length.");
                return bd;
            }
            target.info.ats = std::vector<std::uint8_t>{std::begin(bd) + expected_nfcid_length + 6, std::end(bd)};
        }

        success = true;
        return bd;
    }

    bin_data const &operator>>(bin_data const &bd, std::pair<target_kbps424_felica, bool> &target_success) {
        auto &target = target_success.first;
        auto &success = target_success.second;
        success = false;

        if (bd.size() != 19 and bd.size() != 21) {
            LOGW("Unable to parse target_kbps212/424_felica target info, incorrect length.");
            return bd;
        }
        target.logical_index = bd[0];

        if (bd[1] + 1 != bd.size()) {
            LOGW("Unable to parse target_kbps212/424_felica target info, mismatch POL_RES length.");
            return bd;
        }

        if (bd[2] != 0x01) {
            LOGW("Incorrect response code (%u)  parsing target_kbps212/424_felica target info; continuing...", bd[2]);
        }

        const auto nfc_view = bd.view(3, 8);
        std::copy(std::begin(nfc_view), std::end(nfc_view), std::begin(target.info.nfcid_2t));

        if (bd.size() == 21) {
            // Copy also SYST_CODE
            target.info.syst_code = {bd[19], bd[20]};
        }

        success = true;
        return bd;
    }

    bin_data const &operator>>(bin_data const &bd, std::pair<target_kbps212_felica, bool> &target_success) {
        std::pair<target_kbps424_felica, bool> identical_base{};
        bd >> identical_base;
        target_success.first.logical_index = identical_base.first.logical_index;
        target_success.first.info = identical_base.first.info;
        target_success.second = identical_base.second;
        return bd;
    }

    bin_data const &operator>>(bin_data const &bd, std::pair<target_kbps106_typeb, bool> &target_success) {
        auto &target = target_success.first;
        auto &success = target_success.second;
        success = false;

        if (bd.size() < 14) {
            LOGW("Unable to parse target_kbps106_typeb target info, too little data.");
            return bd;
        }

        target.logical_index = bd[0];

        const auto atqb_response_view = bd.view(1, 12);
        std::copy(std::begin(atqb_response_view), std::end(atqb_response_view), std::begin(target.info.atqb_response));

        const auto expected_attrib_res_length = bd[13];
        if (bd.size() < 14 + expected_attrib_res_length) {
            LOGW("Unable to parse target_kbps106_typeb target info, incorrect ATTRIB_RES length.");
            return bd;
        }

        target.info.attrib_res = std::vector<std::uint8_t>{std::begin(bd) + 14, std::end(bd)};

        success = true;
        return bd;
    }

    bin_data const &operator>>(bin_data const &bd, std::pair<target_kbps106_jewel_tag, bool> &target_success) {
        auto &target = target_success.first;
        auto &success = target_success.second;
        success = false;

        if (bd.size() != 7) {
            LOGW("Unable to parse target_kbps106_jewel_tag target info, incorrect data length.");
            return bd;
        }

        target.logical_index = bd[0];
        target.info.sens_res = (std::uint16_t(bd[1]) << 8) | bd[2];

        std::copy(std::begin(bd) + 3, std::end(bd), std::begin(target.info.jewel_id));

        success = true;
        return bd;
    }



}