//
// Created by Pietro Saccardi on 20/12/2020.
//

#ifndef APERTURAPORTA_BITS_HPP
#define APERTURAPORTA_BITS_HPP

#include <array>
#include <vector>
#include <cstddef>

namespace pn532 {

    namespace bits {

        template <std::uint8_t MinIdx, std::uint8_t MaxIdx>
        struct bitmask_window {
            static constexpr std::uint8_t value = (0xff >> (7 + MinIdx - MaxIdx)) << MinIdx;
        };

        static constexpr std::uint8_t preamble = 0x00;
        static constexpr std::uint8_t postamble = 0x00;

        enum struct transport : std::uint8_t {
            host_to_pn532 = 0xd4,
            pn532_to_host = 0xd5
        };

        static constexpr std::uint8_t specific_app_level_err_code = 0x7f;
        static constexpr std::array<std::uint8_t, 2> start_of_packet_code = {0x00, 0xff};
        static constexpr std::array<std::uint8_t, 2> ack_packet_code = {0x00, 0xff};
        static constexpr std::array<std::uint8_t, 2> nack_packet_code = {0xff, 0x00};
        static constexpr std::array<std::uint8_t, 2> fixed_extended_packet_length = {0xff, 0xff};

        static constexpr std::size_t max_firmware_data_length = 263;

        static constexpr std::uint8_t firmware_iso_18092_mask = 0x1 << 2;
        static constexpr std::uint8_t firmware_iso_iec_14443_typea_mask = 0x1 << 2;
        static constexpr std::uint8_t firmware_iso_iec_14443_typeb_mask = 0x1 << 2;

        static constexpr unsigned echo_back_reply_delay_steps_per_ms = 2;

        enum struct command : std::uint8_t {
            diagnose = 0x00,
            get_firmware_version = 0x02,
            get_general_status = 0x04,
            read_register = 0x06,
            write_register = 0x08,
            read_gpio = 0x0c,
            write_gpio = 0x0e,
            set_serial_baudrate = 0x10,
            set_parameters = 0x12,
            sam_configuration = 0x14,
            power_down = 0x16,
            rf_configuration = 0x32,
            rf_regulation_test = 0x58,
            in_jump_for_dep = 0x56,
            in_jump_for_psl = 0x46,
            in_list_passive_target = 0x4a,
            in_atr = 0x50,
            in_psl = 0x4e,
            in_data_exchange = 0x40,
            in_communicate_thru = 0x42,
            in_deselect = 0x44,
            in_release = 0x52,
            in_select = 0x54,
            in_autopoll = 0x60,
            tg_init_as_target = 0x8c,
            tg_set_general_bytes = 0x92,
            tg_get_data = 0x86,
            tg_set_data = 0x8e,
            tg_set_metadata = 0x94,
            tg_get_initiator_command = 0x88,
            tg_response_to_initiator = 0x90,
            tg_get_target_status = 0x8a
        };

        enum struct test : std::uint8_t {
            comm_line = 0x0,
            rom = 0x1,
            ram = 0x2,
            poll_target = 0x4,
            echo_back = 0x5,
            attention_req_or_card_presence = 0x6,
            self_antenna = 0x7
        };

        enum struct low_current_thr : std::uint8_t {
            mA_25 = 0b10 << 4,
            mA_35 = 0b11 << 4
        };

        enum struct high_current_thr : std::uint8_t {
            mA_45 = 0b000 << 1,
            mA_60 = 0b001 << 1,
            mA_75 = 0b010 << 1,
            mA_90 = 0b011 << 1,
            mA_105 = 0b100 << 1,
            mA_120 = 0b101 << 1,
            mA_130 = 0b110 << 1,
            mA_150 = 0b111 << 1
        };

        static constexpr std::uint8_t reg_andet_control_low_current_mask = bitmask_window<4, 5>::value;
        static constexpr std::uint8_t reg_andet_control_high_current_mask = bitmask_window<1, 3>::value;

        static constexpr std::uint8_t reg_andet_control_too_low_power_mask = 1 << 7;
        static constexpr std::uint8_t reg_andet_control_too_high_power_mask = 1 << 6;
        static constexpr std::uint8_t reg_andet_control_antenna_detect_mask = 1 << 0;

        enum struct serial_baudrate : std::uint8_t {
            kbaud9_6 = 0x00,
            kbaud19_2 = 0x01,
            kbaud38_4 = 0x02,
            kbaud57_6 = 0x03,
            kbaud115_2 = 0x04,
            kbaud230_4 = 0x05,
            kbaud460_8 = 0x06,
            kbaud921_6 = 0x07,
            kbaud1288 = 0x08
        };

        enum struct tx_mode : std::uint8_t {
            mifare_106kbps = 0b0000000,
            mifare_212kbps = 0b0010000,
            mifare_424kbps = 0b0100000,
            mifare_848kbps = 0b0110000,
            felica_106kbps = 0b0000010,
            felica_212kbps = 0b0010010,
            felica_424kbps = 0b0100010,
            felica_848kbps = 0b0110010
        };

        enum struct rf_timeout : std::uint8_t {
            none = 0x00,
            us_100 = 0x01,
            us_200 = 0x02,
            us_400 = 0x03,
            us_800 = 0x04,
            ms_1_6 = 0x05,
            ms_3_2 = 0x06,
            ms_6_4 = 0x07,
            ms_12_8 = 0x08,
            ms_25_6 = 0x09,
            ms_51_2 = 0x0a,
            ms_102_4 = 0x0b,
            ms_204_8 = 0x0c,
            ms_409_6 = 0x0d,
            ms_819_2 = 0x0e,
            s_1_64 = 0x0f,
            s_3_28 = 0x10
        };

        static constexpr std::uint8_t rf_configuration_field_auto_rfca_mask = 0b10;
        static constexpr std::uint8_t rf_configuration_field_auto_rf_on_mask = 0b01;

        struct ciu_reg_212_424kbps {
            std::uint8_t rf_cfg = 0x69;
            std::uint8_t gs_n_on = 0xff;
            std::uint8_t cw_gs_p = 0x3f;
            std::uint8_t mod_gs_p = 0x11;
            std::uint8_t demod_own_rf_on = 0x41;
            std::uint8_t rx_threshold = 0x85;
            std::uint8_t demod_own_rf_off = 0x61;
            std::uint8_t gs_n_off = 0x6f;
        };

        struct ciu_reg_106kbps_typea {
            std::uint8_t rf_cfg = 0x59;
            std::uint8_t gs_n_on = 0xf4;
            std::uint8_t cw_gs_p = 0x3f;
            std::uint8_t mod_gs_p = 0x11;
            std::uint8_t demod_own_rf_on = 0x4d;
            std::uint8_t rx_threshold = 0x85;
            std::uint8_t demod_own_rf_off = 0x61;
            std::uint8_t gs_n_off = 0x6f;
            std::uint8_t mod_width = 0x26;
            std::uint8_t mif_nfc = 0x62;
            std::uint8_t tx_bit_phase = 0x87;
        };

        struct ciu_reg_typeb {
            std::uint8_t gs_n_on = 0xff;
            std::uint8_t mod_gs_p = 0x17;
            std::uint8_t rx_threshold = 0x85;
        };

        struct ciu_reg_iso_iec_14443_4_at_baudrate {
            std::uint8_t rx_threshold;
            std::uint8_t mod_width;
            std::uint8_t mif_nfc;
        };

        struct ciu_reg_iso_iec_14443_4 {
            ciu_reg_iso_iec_14443_4_at_baudrate kbps212 = {
                    .rx_threshold = 0x85,
                    .mod_width = 0x15,
                    .mif_nfc = 0x8a
            };
            ciu_reg_iso_iec_14443_4_at_baudrate kbps424 = {
                    .rx_threshold = 0x85,
                    .mod_width = 0x08,
                    .mif_nfc = 0xb2
            };
            ciu_reg_iso_iec_14443_4_at_baudrate kbps848 = {
                    .rx_threshold = 0x85,
                    .mod_width = 0x01,
                    .mif_nfc = 0xda
            };
        };


        enum struct rf_config_item : std::uint8_t {
            rf_field = 0x01,
            timings = 0x02,
            max_rty_com = 0x04,
            max_retries = 0x05,
            analog_106kbps_typea = 0x0a,
            analog_212_424kbps = 0x0b,
            analog_typeb = 0x0c,
            analog_iso_iec_14443_4 = 0x0d
        };

        enum struct baudrate : std::uint8_t {
            kbps106 = 0x0,
            kbps212 = 0x1,
            kbps424 = 0x2
        };

        enum struct modulation : std::uint8_t {
            mifare_iso_iec_14443_3_type_ab_iso_iec_18092_passive_kbps106 = 0x00,
            felica_iso_iec_18092_kbps212_424 = 0x10,
            iso_iec_18092_active = 0x01,
            innovision_jewel_tag = 0x02
        };

        enum struct sam_mode : std::uint8_t {
            normal = 0x01,
            virtual_card = 0x02,
            wired_card = 0x03,
            dual_card = 0x04
        };

        enum struct wakeup_source : std::uint8_t {
            i2c = 1 << 7,
            gpio = 1 << 6,
            spi = 1 << 5,
            hsu = 1 << 4,
            rf = 1 << 3,
            int1 = 1 << 1,
            int0 = 1 << 0
        };

        static constexpr unsigned sam_timeout_unit_ms = 50;

        static constexpr std::uint8_t status_nad_mask = 0x1 << 7;
        static constexpr std::uint8_t status_more_info_mask = 0x1 << 6;
        static constexpr std::uint8_t status_error_mask = 0b00111111;

        static constexpr std::uint8_t sam_status_neg_pulse_on_clad_line_bit = 1 << 0;
        static constexpr std::uint8_t sam_status_detected_rf_field_off_bit = 1 << 1;
        static constexpr std::uint8_t sam_status_timeout_after_sig_act_irq_bit = 1 << 2;
        static constexpr std::uint8_t sam_status_clad_line_high_bit = 1 << 7;

        static constexpr std::uint8_t parameters_use_nad_data_bit = 1 << 0;
        static constexpr std::uint8_t parameters_use_did_data_bit = 1 << 1;
        static constexpr std::uint8_t parameters_auto_generate_atr_res_bit = 1 << 2;
        static constexpr std::uint8_t parameters_auto_generate_rats_bit = 1 << 4;
        static constexpr std::uint8_t parameters_enable_iso_14443_4_picc_emulation_bit = 1 << 5;
        static constexpr std::uint8_t parameters_remove_pre_post_amble_bit = 1 << 6;

        static constexpr std::uint8_t max_num_targets = 2;

        enum struct error : std::uint8_t {
            none = 0x00,
            timeout = 0x01,
            crc_error = 0x02,
            parity_error = 0x3,
            erroneous_bit_count = 0x04,
            framing_error = 0x05,
            bit_collision = 0x06,
            buffer_size_insufficient = 0x07,
            rf_buffer_overflow = 0x09,
            counterpart_rf_off = 0x0a,
            rf_protocol_error = 0x0b,
            temperature_error = 0x0d,
            buffer_overflow = 0x0e,
            invalid_parameter = 0x10,
            dep_unsupported_command = 0x12,
            dep_specification_mismatch = 0x13,
            mifare_auth_error = 0x14,
            wrong_uid_check_byte = 0x23,
            dep_invalid_device_state = 0x25,
            operation_not_allowed = 0x26,
            command_not_acceptable = 0x27,
            released_by_initiator = 0x29,
            card_exchanged = 0x2a,
            card_disappeared = 0x2b,
            nfcid3_initiator_target_mismatch = 0x2c,
            overcurrent = 0x2d,
            nad_missing_in_dep_frame = 0x2e
        };

        enum struct sfr_register : std::uint8_t {
            pcon = 0x87,
            rwl = 0x9a,
            twl = 0x9b,
            fifofs = 0x9c,
            fifoff = 0x9d,
            sff = 0x9e,
            fit = 0x9f,
            fiten = 0xa1,
            fdata = 0xa2,
            fsize = 0xa3,
            ie0 = 0xa8,
            spicontrol = 0xa9,
            spistatus = 0xaa,
            hsu_sta = 0xab,
            hsu_ctr = 0xac,
            hsu_pre = 0xad,
            hsu_cnt = 0xae,
            p3 = 0xb0,
            ip0 = 0xb8,
            ciu_command = 0xd1,
            ien1 = 0xe8,
            p7cfga = 0xf4,
            p7cfgb = 0xf5,
            p7 = 0xf7,
            ip1 = 0xf8,
            p3cfga = 0xfc,
            p3cfgb = 0xfd
        };

        static constexpr std::uint8_t uid_cascade_tag = 0x88;

        enum struct polling_method : std::uint8_t {
            timeslot = 0x00,
            probabilistic = 0x01
        };

        /**
         * @note Lowest 3 bits of @ref target_type
         */
        enum struct baudrate_modulation : std::uint8_t {
            kbps106_iso_iec_14443_typea = 0x00,
            kbps212_felica_polling = 0x01,
            kbps424_felica_polling = 0x02,
            kbps106_iso_iec_14443_3_typeb = 0x03,
            kbps106_innovision_jewel_tag = 0x04
        };

        template <baudrate_modulation BrMd>
        struct target_info {
        };

        template <>
        struct target_info<baudrate_modulation::kbps106_iso_iec_14443_typea> {
            std::uint16_t sens_res;
            std::uint8_t sel_res;
            std::vector<std::uint8_t> nfcid;
            std::vector<std::uint8_t> ats;
        };

        template <>
        struct target_info<baudrate_modulation::kbps212_felica_polling> {
            std::array<std::uint8_t, 8> nfcid_2t;
            std::array<std::uint8_t, 2> syst_code;
        };

        template <>
        struct target_info<baudrate_modulation::kbps424_felica_polling> :
                public target_info<baudrate_modulation::kbps212_felica_polling> {
            /* identical */
            using target_info<baudrate_modulation::kbps212_felica_polling>::nfcid_2t;
            using target_info<baudrate_modulation::kbps212_felica_polling>::syst_code;
        };

        template <>
        struct target_info<baudrate_modulation::kbps106_iso_iec_14443_3_typeb> {
            std::array<std::uint8_t, 12> atqb_response;
            std::vector<std::uint8_t> attrib_res;
        };


        template <>
        struct target_info<baudrate_modulation::kbps106_innovision_jewel_tag> {
            std::uint16_t sens_res;
            std::array<std::uint8_t, 4> jewel_id;
        };

        template <baudrate_modulation BrMd>
        struct target {
            std::uint8_t logical_index;
            target_info<BrMd> info;
        };

        enum struct poll_period : std::uint8_t {
            ms_150 = 0x1,
            ms_300 = 0x2,
            ms_450 = 0x3,
            ms_600 = 0x4,
            ms_750 = 0x5,
            ms_900 = 0x6,
            ms_1050 = 0x7,
            ms_1200 = 0x8,
            ms_1350 = 0x9,
            ms_1500 = 0xa,
            ms_1650 = 0xb,
            ms_1800 = 0xc,
            ms_1950 = 0xd,
            ms_2100 = 0xe,
            ms_2250 = 0xf
        };

        static constexpr unsigned autopoll_max_types = 15;

        enum struct target_type : std::uint8_t {
            generic_passive_106kbps = 0x00,
            generic_passive_212kbps = 0x01,
            generic_passive_424kbps = 0x02,
            passive_106kbps_iso_iec_14443_4_typeb = 0x03,
            innovision_jewel_tag = 0x04,
            mifare_card = 0x10,
            felica_212kbps_card = 0x11,
            felica_424kbps_card = 0x12,
            passive_106kbps_iso_iec_14443_4_typea = 0x20,
            passive_106kbps_iso_iec_14443_4_typeb_alt = 0x23,
            dep_passive_106kbps = 0x40,
            dep_passive_212kbps = 0x41,
            dep_passive_424kbps = 0x42,
            dep_active_106kbps = 0x80,
            dep_active_212kbps = 0x81,
            dep_active_424kbps = 0x82
        };

        static constexpr std::uint8_t target_type_baudrate_modulation_mask = 0b111;

        template <target_type Type>
        struct baudrate_modulation_of_target {
            static constexpr baudrate_modulation value =
                    static_cast<baudrate_modulation>(static_cast<std::uint8_t>(Type) &
                                                     target_type_baudrate_modulation_mask);
        };

        struct atr_res_info {
            std::array<std::uint8_t, 10> nfcid_3t;
            std::uint8_t did_t;
            std::uint8_t b_st;
            std::uint8_t b_rt;
            std::uint8_t to;
            std::uint8_t pp_t;
            std::vector<std::uint8_t> g_t;
        };

        static constexpr std::uint8_t in_atr_nfcid_3t_present_mask = 0b01;
        static constexpr std::uint8_t in_atr_general_info_present_mask = 0b10;

        static constexpr std::uint8_t in_jump_for_dep_passive_init_data_present_mask = 0b001;
        static constexpr std::uint8_t in_jump_for_dep_nfcid_3t_present_mask = 0b010;
        static constexpr std::uint8_t in_jump_for_dep_general_info_present_mask = 0b100;

        static constexpr std::size_t general_info_max_length = 48;

        static constexpr std::uint8_t gpio_p3_pin_mask = bitmask_window<0, 5>::value;
        static constexpr std::uint8_t gpio_p7_pin_mask = bitmask_window<1, 2>::value;
        static constexpr std::uint8_t gpio_i0i1_pin_mask = 0x00;  // Cannot set i0i1

        static constexpr std::uint8_t gpio_write_validate_max = 1 << 7;

        static constexpr std::uint8_t sfr_registers_high = 0xff;

    }
}

#endif //APERTURAPORTA_BITS_HPP
