//
// Created by Pietro Saccardi on 22/12/2020.
//

#include <pn532/data.hpp>

namespace mlab {
    using namespace pn532;
    using namespace mlab_literals;

    bin_data &operator<<(bin_data &bd, reg::ciu_212_424kbps const &reg) {
        return bd << prealloc(sizeof(reg::ciu_212_424kbps)) << reg.rf_cfg << reg.gs_n_on << reg.cw_gs_p
                  << reg.mod_gs_p << reg.demod_own_rf_on << reg.rx_threshold << reg.demod_own_rf_off << reg.gs_n_off;
    }

    bin_data &operator<<(bin_data &bd, reg::ciu_106kbps_typea const &reg) {
        return bd << prealloc(sizeof(reg::ciu_106kbps_typea)) << reg.rf_cfg << reg.gs_n_on << reg.cw_gs_p
                  << reg.mod_gs_p << reg.demod_own_rf_on << reg.rx_threshold << reg.demod_own_rf_off << reg.gs_n_off
                  << reg.mod_width << reg.mif_nfc << reg.tx_bit_phase;
    }

    bin_data &operator<<(bin_data &bd, reg::ciu_typeb const &reg) {
        return bd << prealloc(sizeof(reg::ciu_typeb)) << reg.gs_n_on << reg.mod_gs_p << reg.rx_threshold;
    }

    bin_data &operator<<(bin_data &bd, reg::ciu_iso_iec_14443_4_at_baudrate const &reg) {
        return bd << prealloc(sizeof(reg::ciu_iso_iec_14443_4_at_baudrate)) << reg.rx_threshold << reg.mod_width
                  << reg.mif_nfc;
    }

    bin_data &operator<<(bin_data &bd, reg::ciu_iso_iec_14443_4 const &reg) {
        return bd << prealloc(sizeof(reg::ciu_iso_iec_14443_4)) << reg.kbps212 << reg.kbps424 << reg.kbps848;
    }

    bin_data &operator<<(bin_data &bd, nfcid_2t const &uid) {
        return bd << prealloc(8) << bits::uid_cascade_tag << static_cast<std::array<std::uint8_t, 7> const &>(uid);
    }

    bin_data &operator<<(bin_data &bd, nfcid_3t const &uid) {
        return bd << prealloc(12) << bits::uid_cascade_tag << make_range(std::begin(uid), std::begin(uid) + 3)
                  << bits::uid_cascade_tag << make_range(std::begin(uid) + 3, std::end(uid));
    }

    bin_data &operator<<(bin_data &bd, bits::reg_antenna_detector const &r) {
        std::uint8_t bitpack = 0x0;
        bitpack |= static_cast<std::uint8_t>(r.low_current_threshold);
        bitpack |= static_cast<std::uint8_t>(r.high_current_threshold);
        bitpack |= (r.detected_low_pwr ? bits::reg_andet_control_too_low_power_mask : 0x0);
        bitpack |= (r.detected_high_pwr ? bits::reg_andet_control_too_high_power_mask : 0x0);
        bitpack |= (r.enable_detection ? bits::reg_andet_control_antenna_detect_mask : 0x0);
        return bd << bitpack;
    }

    bin_stream &operator>>(bin_stream &s, bits::reg_antenna_detector &r) {
        const std::uint8_t bitpack = s.pop();
        r.enable_detection = 0 != (bitpack & bits::reg_andet_control_antenna_detect_mask);
        r.detected_low_pwr = 0 != (bitpack & bits::reg_andet_control_too_low_power_mask);
        r.detected_high_pwr = 0 != (bitpack & bits::reg_andet_control_too_high_power_mask);
        r.low_current_threshold = static_cast<low_current_thr>(bitpack & bits::reg_andet_control_low_current_mask);
        r.high_current_threshold = static_cast<high_current_thr>(bitpack & bits::reg_andet_control_high_current_mask);
        return s;
    }

    bin_stream &operator>>(bin_stream &s, firmware_version &fw) {
        if (s.remaining() < 4) {
            PN532_LOGE("Parsing firmware_version: expected at least 4 bytes of data, got %u.", s.remaining());
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
            PN532_LOGE("Parsing gpio_status: expected at least 3 bytes of data, got %u.", s.remaining());
            s.set_bad();
            return s;
        }
        const std::uint8_t p3_mask = s.pop();
        const std::uint8_t p7_mask = s.pop();
        const std::uint8_t i0i1_mask = s.pop();
        gpio = gpio_status{p3_mask, p7_mask, i0i1_mask};
        return s;
    }

    bin_stream &operator>>(bin_stream &s, rf_status &status) {
        if (s.remaining() < 1) {
            PN532_LOGE("Parsing rf_status: expected at least 3 bytes of data, got %u.", s.remaining());
            s.set_bad();
            return s;
        }
        const auto flag_byte = s.pop();
        status.nad_present = 0 != (flag_byte & bits::status_nad_mask);
        status.expect_more_info = 0 != (flag_byte & bits::status_more_info_mask);
        status.error = static_cast<internal_error_code>(flag_byte & bits::status_error_mask);
        return s;
    }

    bin_stream &operator>>(bin_stream &s, std::pair<rf_status, bin_data> &status_data_pair) {
        s >> status_data_pair.first;
        if (s.good()) {
            status_data_pair.second.resize(s.remaining());
            s.read(std::begin(status_data_pair.second), s.remaining());
        } else {
            status_data_pair.second.clear();
        }
        return s;
    }

    bin_stream &operator>>(bin_stream &s, general_status_target &ts) {
        if (s.remaining() < 4) {
            PN532_LOGE("Parsing general_status::target_status: expected at least 4 bytes of data, got %u.", s.remaining());
            s.set_bad();
            return s;
        }
        return s >> ts.logical_index >> ts.baudrate_rx >> ts.baudrate_tx >> ts.modulation_type;
    }

    bin_stream &operator>>(bin_stream &s, general_status &gs) {
        if (s.remaining() < 4) {
            PN532_LOGE("Parsing general_status: expected at least 4 bytes of data, got %u.", s.remaining());
            s.set_bad();
            return s;
        }

        gs.last_error = static_cast<internal_error_code>(s.pop() & bits::status_error_mask);
        s >> gs.rf_field_present;

        const auto num_targets = s.pop();
        if (num_targets > bits::max_num_targets) {
            PN532_LOGW("%s: detected %u targets, more than %u targets handled by PN532, most likely an error.",
                       to_string(command_code::get_general_status), num_targets, bits::max_num_targets);
        }
        gs.targets.resize(num_targets, general_status_target{});
        for (general_status_target &ts : gs.targets) {
            s >> ts;
        }
        s >> gs.sam;

        return s;
    }

    bin_stream &operator>>(bin_stream &s, poll_target<target_type::dep_passive_106kbps> &entry) {
        if (s.remaining() < 20) {
            PN532_LOGW("Unable to parse kbps106_iso_iec_14443_typea poll_target_dep_passive, too little data.");
            s.set_bad();
            return s;
        }

        s >> entry.logical_index >> entry.sens_res >> entry.sel_res;

        const auto expected_nfcid_length = s.pop();
        if (s.remaining() < expected_nfcid_length) {
            PN532_LOGW("Unable to parse kbps106_iso_iec_14443_typea entry info, missing NFC ID data.");
            s.set_bad();
            return s;
        }
        entry.nfcid.resize(expected_nfcid_length);
        s.read(std::begin(entry.nfcid), expected_nfcid_length);
        // Different here: it's no ATS bytes
        entry.ats.clear();

        s >> entry.atr_info;
        return s;
    }

    bin_stream &operator>>(bin_stream &s, target_kbps106_typea &target) {
        if (s.remaining() < 5) {
            PN532_LOGW("Unable to parse kbps106_iso_iec_14443_typea target info, too little data.");
            s.set_bad();
            return s;
        }

        s >> target.logical_index >> target.sens_res >> target.sel_res;

        const auto expected_nfcid_length = s.pop();
        if (s.remaining() < expected_nfcid_length) {
            PN532_LOGW("Unable to parse kbps106_iso_iec_14443_typea target info, missing NFC ID data.");
            s.set_bad();
            return s;
        }
        target.nfcid.resize(expected_nfcid_length);
        s.read(std::begin(target.nfcid), expected_nfcid_length);
        target.ats.clear();
        if (s.good()) {
            // ATS length includes the ats bit
            const std::uint8_t expected_ats_length = std::max(1_b, s.pop()) - 1;
            if (s.remaining() < expected_ats_length) {
                PN532_LOGW("Unable to parse kbps106_iso_iec_14443_typea target info, not enough data.");
                s.set_bad();
                return s;
            }
            target.ats.resize(expected_ats_length);
            s.read(std::begin(target.ats), expected_ats_length);
        }

        return s;
    }

    bin_stream &operator>>(bin_stream &s, target_kbps424_felica &target) {
        if (s.remaining() < 19) {
            PN532_LOGW("Unable to parse target_kbps212/424_felica target info, insufficient length.");
            s.set_bad();
            return s;
        }
        s >> target.logical_index;

        const auto pol_length = s.pop();
        if (pol_length != 18 and pol_length != 20) {
            PN532_LOGW("Unable to parse target_kbps212/424_felica target info, mismatch POL_RES length.");
            s.set_bad();
            return s;
        }

        const auto response_code = s.pop();
        if (response_code != 0x01) {
            PN532_LOGW("Incorrect response code (%u)  parsing target_kbps212/424_felica target info; continuing...",
                       response_code);
        }

        s >> target.nfcid_2t;
        s >> target.pad;
        if (pol_length == 20) {
            // Copy also SYST_CODE
            s >> target.syst_code;
        }
        return s;
    }

    bin_stream &operator>>(bin_stream &s, target_kbps212_felica &target) {
        target_kbps424_felica identical{};
        s >> identical;
        target.logical_index = identical.logical_index;
        target.nfcid_2t = identical.nfcid_2t;
        target.pad = identical.pad;
        target.syst_code = identical.syst_code;
        return s;
    }

    bin_stream &operator>>(bin_stream &s, target_kbps106_typeb &target) {
        if (s.remaining() < 14) {
            PN532_LOGW("Unable to parse target_kbps106_typeb target info, too little data.");
            s.set_bad();
            return s;
        }

        s >> target.logical_index >> target.atqb_response;

        const auto expected_attrib_res_length = s.pop();
        if (s.remaining() < expected_attrib_res_length) {
            PN532_LOGW("Unable to parse target_kbps106_typeb target info, incorrect ATTRIB_RES length.");
            s.set_bad();
            return s;
        }

        target.attrib_res.resize(expected_attrib_res_length);
        s.read(std::begin(target.attrib_res), expected_attrib_res_length);

        return s;
    }

    bin_stream &operator>>(bin_stream &s, target_kbps106_jewel_tag &target) {
        if (s.remaining() < 7) {
            PN532_LOGW("Unable to parse target_kbps106_jewel_tag target info, incorrect data length.");
            s.set_bad();
            return s;
        }

        s >> target.logical_index >> target.sens_res >> target.jewel_id;
        return s;
    }

    bin_stream &operator>>(bin_stream &s, atr_res_info &atr_res) {
        if (s.remaining() < 15) {
            PN532_LOGW("Unable to parse atr_res_info, incorrect data length.");
            s.set_bad();
            return s;
        }

        s >> atr_res.nfcid >> atr_res.did_t >> atr_res.b_st >> atr_res.b_rt >> atr_res.to >> atr_res.pp_t;
        atr_res.g_t.resize(s.remaining());
        if (not s.eof()) {
            s.read(std::begin(atr_res.g_t), s.remaining());
        }
        return s;
    }

    bin_stream &operator>>(bin_stream &s, std::pair<rf_status, atr_res_info> &status_atr_res) {
        if (s.remaining() < 16) {
            PN532_LOGW("Unable to parse rf_status and atr_res_info, incorrect data length.");
            s.set_bad();
            return s;
        }
        s >> status_atr_res.first >> status_atr_res.second;
        return s;
    }

    namespace {
        template <target_type Type>
        poll_target<Type> extract_poll_entry(bin_stream &s) {
            poll_target<Type> entry{};
            s >> entry;
            return entry;
        }
    }// namespace

    bin_stream &operator>>(bin_stream &s, any_poll_target &t) {
        if (s.remaining() < 2) {
            PN532_LOGW("Unable to parse any_poll_target, missing target type and data length.");
            s.set_bad();
            return s;
        }
        const auto type = static_cast<target_type>(s.pop());
        const std::uint8_t length = s.pop();
        const auto old_pos = s.tell();
        if (not s.good()) {
            return s;
        }
        // This is an unfortunate but necessary massive switch
        switch (type) {
            case target_type::passive_106kbps_iso_iec_14443_4_typeb:
                t = extract_poll_entry<target_type::passive_106kbps_iso_iec_14443_4_typeb>(s);
                break;
            case target_type::innovision_jewel_tag:
                t = extract_poll_entry<target_type::innovision_jewel_tag>(s);
                break;
            case target_type::mifare_classic_ultralight:
                t = extract_poll_entry<target_type::mifare_classic_ultralight>(s);
                break;
            case target_type::felica_212kbps_card:
                t = extract_poll_entry<target_type::felica_212kbps_card>(s);
                break;
            case target_type::felica_424kbps_card:
                t = extract_poll_entry<target_type::felica_424kbps_card>(s);
                break;
            case target_type::passive_106kbps_iso_iec_14443_4_typea:
                t = extract_poll_entry<target_type::passive_106kbps_iso_iec_14443_4_typea>(s);
                break;
            case target_type::passive_106kbps_iso_iec_14443_4_typeb_alt:
                t = extract_poll_entry<target_type::passive_106kbps_iso_iec_14443_4_typeb_alt>(s);
                break;
            case target_type::dep_passive_106kbps:
                t = extract_poll_entry<target_type::dep_passive_106kbps>(s);
                break;
            case target_type::dep_passive_212kbps:
                t = extract_poll_entry<target_type::dep_passive_212kbps>(s);
                break;
            case target_type::dep_passive_424kbps:
                t = extract_poll_entry<target_type::dep_passive_424kbps>(s);
                break;
            case target_type::dep_active_106kbps:
                t = extract_poll_entry<target_type::dep_active_106kbps>(s);
                break;
            case target_type::dep_active_212kbps:
                t = extract_poll_entry<target_type::dep_active_212kbps>(s);
                break;
            case target_type::dep_active_424kbps:
                t = extract_poll_entry<target_type::dep_active_424kbps>(s);
                break;
            default:
                PN532_LOGW("Unsupported target type %s", to_string(type));
                s.set_bad();
                break;
        }
        if (s.bad()) {
            PN532_LOGW("Unable to parse any_poll_target.");
        } else if (s.tell() - old_pos != length) {
            PN532_LOGW("Parsing any_poll_target: mismatch in declared payload length and read data.");
            s.set_bad();
        }
        return s;
    }

    bin_stream &operator>>(bin_stream &s, std::vector<any_poll_target> &targets) {
        if (s.remaining() < 1) {
            PN532_LOGE("Parsing vector<any_poll_target>: not enough data.");
            s.set_bad();
            return s;
        }
        const auto num_targets = s.pop();
        if (num_targets > bits::max_num_targets) {
            PN532_LOGW("Parsing vector<any_poll_target>: found %u targets, which is more than the number of supported targets %u.",
                       num_targets, bits::max_num_targets);
        }
        targets.resize(num_targets);
        for (auto &target : targets) {
            if (not s.good()) {
                break;
            }
            s >> target;
        }
        return s;
    }

    bin_stream &operator>>(bin_stream &s, jump_dep_psl &r) {
        if (s.remaining() < 17) {
            PN532_LOGE("Parsing jump_dep_psl: not enough data.");
            s.set_bad();
            return s;
        }
        return s >> r.status >> r.target_logical_index >> r.atr_info;
    }

    bin_stream &operator>>(bin_stream &s, general_status_sam &sams) {
        if (s.remaining() < 1) {
            PN532_LOGE("Parsing sam_status: not enough data.");
            s.set_bad();
            return s;
        }
        const std::uint8_t sam_byte = s.pop();
        sams.clad_line_high = 0 != (sam_byte & bits::sam_status_clad_line_high_bit);
        sams.detected_rf_field_off = 0 != (sam_byte & bits::sam_status_detected_rf_field_off_bit);
        sams.neg_pulse_on_clad_line = 0 != (sam_byte & bits::sam_status_neg_pulse_on_clad_line_bit);
        sams.timeout_after_sig_act_irq = 0 != (sam_byte & bits::sam_status_timeout_after_sig_act_irq_bit);
        return s;
    }

    bin_data &operator<<(bin_data &s, parameters const &p) {
        const std::uint8_t parms_byte = (p.use_nad_data ? bits::parameters_use_nad_data_bit : 0x0) |
                                        (p.use_did_data ? bits::parameters_use_did_data_bit : 0x0) |
                                        (p.auto_generate_atr_res ? bits::parameters_auto_generate_atr_res_bit : 0x0) |
                                        (p.auto_generate_rats ? bits::parameters_auto_generate_rats_bit : 0x0) |
                                        (p.enable_iso_14443_4_picc_emulation ? bits::parameters_enable_iso_14443_4_picc_emulation_bit : 0x0) |
                                        (p.remove_pre_post_amble ? bits::parameters_remove_pre_post_amble_bit : 0x0);
        return s << parms_byte;
    }

    bin_data &operator<<(bin_data &s, std::vector<wakeup_source> const &vws) {
        std::uint8_t b = 0x00;
        for (wakeup_source ws : vws) {
            b |= static_cast<std::uint8_t>(ws);
        }
        return s << b;
    }

    bin_stream &operator>>(bin_stream &s, status_as_target &st) {
        if (s.remaining() < 2) {
            PN532_LOGE("Parsing status_as_target: not enough data.");
            s.set_bad();
            return s;
        }
        s >> st.status;
        const std::uint8_t br_it = s.pop();
        st.initiator_speed = static_cast<baudrate>((br_it >> bits::status_as_target_initiator_speed_shift) &
                                                   bits::baudrate_mask);
        st.target_speed = static_cast<baudrate>((br_it >> bits::status_as_target_target_speed_shift) &
                                                bits::baudrate_mask);
        return s;
    }

    bin_stream &operator>>(bin_stream &s, activation_as_target_mode &mt) {
        if (s.remaining() < 1) {
            PN532_LOGE("Parsing activation_as_target: not enough data.");
            s.set_bad();
            return s;
        }
        const std::uint8_t byte = s.pop();
        mt.speed = static_cast<baudrate>((byte >> bits::init_as_target_res_baudrate_shift) & bits::baudrate_mask);
        mt.iso_iec_14443_4_picc = 0 != (byte & bits::init_as_target_res_picc_bit);
        mt.dep = 0 != (byte & bits::init_as_target_res_dep_bit);
        mt.framing_type = static_cast<framing_as_target>(byte & bits::framing_mask);
        return s;
    }

    bin_stream &operator>>(bin_stream &s, activation_as_target &mt) {
        if (s.remaining() < 1) {
            PN532_LOGE("Parsing init_as_target_res: not enough data.");
            s.set_bad();
            return s;
        }
        s >> mt.mode;
        if (s.good()) {
            mt.initiator_command.resize(s.remaining());
            s.read(std::begin(mt.initiator_command), s.remaining());
        }
        return s;
    }

    bin_data &operator<<(bin_data &s, mifare_params const &p) {
        return s << prealloc(6)
                 << p.sens_res
                 << p.nfcid_1t
                 << p.sel_res;
    }

    bin_data &operator<<(bin_data &s, felica_params const &p) {
        return s << prealloc(18)
                 << p.nfcid_2t
                 << p.pad
                 << p.syst_code;
    }
}// namespace mlab