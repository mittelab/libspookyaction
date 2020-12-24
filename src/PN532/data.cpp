//
// Created by Pietro Saccardi on 22/12/2020.
//

#include "data.hpp"
#include "msg.hpp"

namespace pn532 {

    bin_data &operator<<(bin_data &bd, ciu_reg_212_424kbps const &reg) {
        return bd << prealloc(sizeof(ciu_reg_212_424kbps)) << reg.rf_cfg << reg.gs_n_on << reg.cw_gs_p
            << reg.mod_gs_p << reg.demod_own_rf_on << reg.rx_threshold << reg.demod_own_rf_off << reg.gs_n_off;
    }

    bin_data &operator<<(bin_data &bd, ciu_reg_106kbps_typea const &reg) {
        return bd << prealloc(sizeof(ciu_reg_106kbps_typea)) << reg.rf_cfg << reg.gs_n_on << reg.cw_gs_p
            << reg.mod_gs_p << reg.demod_own_rf_on << reg.rx_threshold << reg.demod_own_rf_off << reg.gs_n_off
            << reg.mod_width << reg.mif_nfc << reg.tx_bit_phase;
    }

    bin_data &operator<<(bin_data &bd, ciu_reg_typeb const &reg) {
        return bd << prealloc(sizeof(ciu_reg_typeb)) << reg.gs_n_on << reg.mod_gs_p << reg.rx_threshold;
    }

    bin_data &operator<<(bin_data &bd, ciu_reg_iso_iec_14443_4_at_baudrate const &reg) {
        return bd << prealloc(sizeof(ciu_reg_iso_iec_14443_4_at_baudrate)) << reg.rx_threshold << reg.mod_width
            << reg.mif_nfc;
    }

    bin_data &operator<<(bin_data &bd, ciu_reg_iso_iec_14443_4 const &reg) {
        return bd << prealloc(sizeof(ciu_reg_iso_iec_14443_4)) << reg.kbps212 << reg.kbps424 << reg.kbps848;
    }

    bin_data &operator<<(bin_data &bd, uid_cascade_l2 const &uid) {
        return bd << prealloc(8) << bits::uid_cascade_tag << static_cast<std::array<std::uint8_t, 7> const &>(uid);
    }

    bin_data &operator<<(bin_data &bd, uid_cascade_l3 const &uid) {
        return bd << prealloc(12) << bits::uid_cascade_tag << make_range(std::begin(uid), std::begin(uid) + 3)
            << bits::uid_cascade_tag << make_range(std::begin(uid) + 3, std::end(uid));
    }

    bin_stream &operator>>(bin_stream &s, firmware_version &fw) {
        if (s.remaining() < 4) {
            LOGE("Parsing firmware_version: expected at least 4 bytes of data, got %ul.", s.remaining());
            s.set_bad();
            return s;
        }
        s >> fw.ic >> fw.version >> fw.revision;
        const auto flag_byte = s.pop();
        fw.iso_18092 = 0 != (flag_byte & bits::firmware_iso_18092_mask);
        fw.iso_iec_14443_typea = 0 != (flag_byte & bits::firmware_iso_iec_14443_typea_mask);
        fw.iso_iec_14443_typeb = 0 != (flag_byte & bits::firmware_iso_iec_14443_typeb_mask);
        return s;
    }

    bin_stream &operator>>(bin_stream &s, gpio_status &gpio) {
        if (s.remaining() < 3) {
            LOGE("Parsing gpio_status: expected at least 3 bytes of data, got %ul.", s.remaining());
            s.set_bad();
            return s;
        }
        const std::uint8_t p3_mask = s.pop();
        const std::uint8_t p7_mask = s.pop();
        const std::uint8_t i0i1_mask = s.pop();
        gpio = gpio_status{p3_mask, p7_mask, i0i1_mask};
        return s;
    }

    bin_stream &operator>>(bin_stream &s, status &status) {
        if (s.remaining() < 1) {
            LOGE("Parsing status: expected at least 3 bytes of data, got %ul.", s.remaining());
            s.set_bad();
            return s;
        }
        const auto flag_byte = s.pop();
        status.nad_present = 0 != (flag_byte & bits::status_nad_mask);
        status.expect_more_info = 0 != (flag_byte & bits::status_more_info_mask);
        status.error = static_cast<controller_error>(flag_byte & bits::status_error_mask);
        return s;
    }

    bin_stream &operator>>(bin_stream &s, std::pair<status, bin_data> &status_data_pair) {
        s >> status_data_pair.first;
        if (s.good()) {
            status_data_pair.second.resize(s.remaining());
            s.read(std::begin(status_data_pair.second), s.remaining());
        } else {
            status_data_pair.second.clear();
        }
        return s;
    }

    bin_stream &operator>>(bin_stream &s, target_status &ts) {
        if (s.remaining() < 4) {
            LOGE("Parsing target_status: expected at least 4 bytes of data, got %ul.", s.remaining());
            s.set_bad();
            return s;
        }
        return s >> ts.logical_index >> ts.bitrate_rx >> ts.bitrate_tx >> ts.modulation_type;
    }

    bin_stream &operator>>(bin_stream &s, general_status &gs) {
        if (s.remaining() < 4) {
            LOGE("Parsing general_stastus: expected at least 4 bytes of data, got %ul.", s.remaining());
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

    bin_stream &operator>>(bin_stream &s, atr_res_info &atr_res) {
        if (s.remaining() < 15) {
            LOGW("Unable to parse atr_res_info, incorrect data length.");
            s.set_bad();
            return s;
        }

        s >> atr_res.nfcid_3t >> atr_res.did_t >> atr_res.b_st >> atr_res.b_rt >> atr_res.to >> atr_res.pp_t;
        atr_res.g_t.resize(s.remaining());
        s.read(std::begin(atr_res.g_t), s.remaining());
        return s;
    }

    bin_stream &operator>>(bin_stream &s, std::pair<status, atr_res_info> &status_atr_res) {
        if (s.remaining() < 16) {
            LOGW("Unable to parse status and atr_res_info, incorrect data length.");
            s.set_bad();
            return s;
        }
        s >> status_atr_res.first >> status_atr_res.second;
        return s;
    }

}