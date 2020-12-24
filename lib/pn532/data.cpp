//
// Created by Pietro Saccardi on 22/12/2020.
//

#include "data.hpp"
#include "msg.hpp"

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
        return bd << uid.data;
    }

    bin_data &operator<<(bin_data &bd, uid_cascade_l2 const &uid) {
        bd.reserve(bd.size() + 8);
        return bd << bits::uid_cascade_tag << uid.data;
    }

    bin_data &operator<<(bin_data &bd, uid_cascade_l3 const &uid) {
        bd.reserve(bd.size() + 12);
        return bd << bits::uid_cascade_tag << make_range(std::begin(uid.data), std::begin(uid.data) + 3)
            << bits::uid_cascade_tag << make_range(std::begin(uid.data) + 3, std::end(uid.data));
    }

    bin_stream &operator>>(bin_stream &s, target_status &ts) {
        if (s.remaining() < 4) {
            LOGE("%s: Insufficient data (%ull) to populate a target status structure.",
                 to_string(command_code::get_general_status), s.remaining());
            s.set_bad();
            return s;
        }
        return s >> ts.logical_index >> ts.bitrate_rx >> ts.bitrate_tx >> ts.modulation_type;
    }

    bin_stream &operator>>(bin_stream &s, general_status &gs) {
        if (s.remaining() < 4) {
            LOGE("%s: expected at least 4 bytes of data, not %ul.",
                 to_string(command_code::get_general_status), s.remaining());
            s.set_bad();
            return s;
        }

        gs.last_error = static_cast<controller_error>(s.pop() & bits::status_error_mask);
        s >> gs.rf_field_present;

        const auto num_targets = s.pop();
        if (num_targets > bits::max_num_targets) {
            LOGW("%s: detected %u targets, more than %u targets handled by PN532, most likely an error.",
                 to_string(command_code::get_general_status), num_targets, bits::max_num_targets);
        }
        gs.targets.resize(num_targets, target_status{});
        for (target_status &ts : gs.targets) {
            s >> ts;
        }
        s >> gs.sam_status;

        return s;
    }

    bin_stream &operator>>(bin_stream &s, target_kbps106_typea &target) {
        if (s.remaining() < 5) {
            LOGW("Unable to parse kbps106_iso_iec_14443_typea target info, too little data.");
            s.set_bad();
            return s;
        }

        s >> target.logical_index >> target.info.sens_res >> target.info.sel_res;

        const auto expected_nfcid_length = s.pop();
        if (s.remaining() < expected_nfcid_length) {
            LOGW("Unable to parse kbps106_iso_iec_14443_typea target info, missing NFC ID data.");
            s.set_bad();
            return s;
        }
        target.info.nfcid.resize(expected_nfcid_length);
        s.read(std::begin(target.info.nfcid), expected_nfcid_length);
        target.info.ats.clear();
        if (s.good()) {
            const auto expected_ats_length = s.pop() - 1; // ATS length includes the ats bit
            if (s.remaining() < expected_ats_length) {
                LOGW("Unable to parse kbps106_iso_iec_14443_typea target info, not enough data.");
                s.set_bad();
                return s;
            }
            target.info.ats.resize(expected_ats_length);
            s.read(std::begin(target.info.ats), expected_ats_length);
        }

        return s;
    }

    bin_stream &operator>>(bin_stream &s, target_kbps424_felica &target) {
        if (s.remaining() < 19) {
            LOGW("Unable to parse target_kbps212/424_felica target info, insufficient length.");
            s.set_bad();
            return s;
        }
        s >> target.logical_index;

        const auto pol_length = s.pop();
        if (pol_length != 18 and pol_length != 20) {
            LOGW("Unable to parse target_kbps212/424_felica target info, mismatch POL_RES length.");
            s.set_bad();
            return s;
        }

        const auto response_code = s.pop();
        if (response_code != 0x01) {
            LOGW("Incorrect response code (%u)  parsing target_kbps212/424_felica target info; continuing...",
                 response_code);
        }

        s >> target.info.nfcid_2t;
        if (pol_length == 20) {
            // Copy also SYST_CODE
            s >> target.info.syst_code;
        }
        return s;
    }

    bin_stream &operator>>(bin_stream &s, target_kbps212_felica &target) {
        target_kbps424_felica identical{};
        s >> identical;
        target = {.logical_index = identical.logical_index, .info = identical.info};
        return s;
    }

    bin_stream &operator>>(bin_stream &s, target_kbps106_typeb &target) {
        if (s.remaining() < 14) {
            LOGW("Unable to parse target_kbps106_typeb target info, too little data.");
            s.set_bad();
            return s;
        }

        s >> target.logical_index >> target.info.atqb_response;

        const auto expected_attrib_res_length = s.pop();
        if (s.remaining() < expected_attrib_res_length) {
            LOGW("Unable to parse target_kbps106_typeb target info, incorrect ATTRIB_RES length.");
            s.set_bad();
            return s;
        }

        target.info.attrib_res.resize(expected_attrib_res_length);
        s.read(std::begin(target.info.attrib_res), expected_attrib_res_length);

        return s;
    }

    bin_stream &operator>>(bin_stream &s, target_kbps106_jewel_tag &target) {
        if (s.remaining() < 7) {
            LOGW("Unable to parse target_kbps106_jewel_tag target info, incorrect data length.");
            s.set_bad();
            return s;
        }

        s >> target.logical_index >> target.info.sens_res >> target.info.jewel_id;
        return s;
    }



}