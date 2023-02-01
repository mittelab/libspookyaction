//
// Created by Pietro Saccardi on 20/12/2020.
//
#include <mlab/time.hpp>
#include <pn532/bits_algo.hpp>
#include <pn532/controller.hpp>

namespace pn532 {
    namespace {
        using mlab::ms;
        using mlab::prealloc;
        using mlab::reduce_timeout;
        using namespace mlab_literals;

        template <class It>
        using range = mlab::range<It>;

        using mlab::make_range;
    }// namespace

    const std::vector<bits::target_type> controller::poll_all_targets = {
            target_type::generic_passive_106kbps,
            target_type::generic_passive_212kbps,
            target_type::generic_passive_424kbps,
            target_type::passive_106kbps_iso_iec_14443_4_typeb,
            target_type::innovision_jewel_tag};

    controller::result<bool> controller::diagnose_comm_line(ms timeout) {
        PN532_LOGI("%s: running %s...", to_string(command_code::diagnose), to_string(bits::test::comm_line));
        // Generate 256 bytes of random data to test
        bin_data payload;
        payload.resize(0xff);
        std::iota(std::begin(payload), std::end(payload), 0x00);
        // Set the first byte to be the test number
        payload[0] = static_cast<std::uint8_t>(bits::test::comm_line);
        if (const auto res_cmd = chn().command_response(command_code::diagnose, /* copy */ payload, timeout); res_cmd) {
            // Test that the reurned data coincides
            if (payload.size() == res_cmd->size() and
                std::equal(std::begin(payload), std::end(payload), std::begin(*res_cmd))) {
                PN532_LOGI("%s: %s test succeeded.", to_string(command_code::diagnose), to_string(bits::test::comm_line));
                return true;
            } else {
                PN532_LOGW("%s: %s test failed.", to_string(command_code::diagnose), to_string(bits::test::comm_line));
                return false;
            }
        } else {
            PN532_LOGW("%s: %s test failed with %s.", to_string(command_code::diagnose), to_string(bits::test::comm_line), to_string(res_cmd.error()));
            return res_cmd.error();
        }
    }

    namespace {
        template <class... Args>
        controller::result<bool> nfc_diagnose_simple(
                channel &chn, bits::test test, std::uint8_t expected, ms timeout,
                std::size_t expected_body_size = 0, Args &&...append_to_body) {
            PN532_LOGI("%s: running %s...", to_string(command_code::diagnose), to_string(test));
            bin_data payload = bin_data::chain(prealloc(expected_body_size + 1), test,
                                               std::forward<Args>(append_to_body)...);
            if (const auto res_cmd = chn.command_response(command_code::diagnose, std::move(payload), timeout); res_cmd) {
                // Test that the reurned data coincides
                if (res_cmd->size() != 1) {
                    PN532_LOGW("%s: %s test received %u bytes instead of 1.",
                               to_string(command_code::diagnose), to_string(test), res_cmd->size());
                    return channel::error::comm_malformed;
                }
                if (res_cmd->at(0) == expected) {
                    PN532_LOGI("%s: %s test succeeded.", to_string(command_code::diagnose), to_string(test));
                    return true;
                } else {
                    PN532_LOGW("%s: %s test failed.", to_string(command_code::diagnose), to_string(test));
                    return false;
                }
            } else {
                return res_cmd.error();
            }
        }
    }// namespace

    controller::result<unsigned, unsigned> controller::diagnose_poll_target(bool slow, bool fast, ms timeout) {
        auto get_fails = [&](bool do_test, baudrate speed) -> controller::result<unsigned> {
            if (not do_test) {
                return std::numeric_limits<unsigned>::max();
            }
            const auto res_cmd = chn().command_response(
                    command_code::diagnose,
                    bin_data::chain(prealloc(2), bits::test::poll_target, speed),
                    timeout);
            if (res_cmd) {
                if (res_cmd->size() == 1) {
                    return res_cmd->at(0);
                } else {
                    PN532_LOGW("%s: %s test failed at %s.", to_string(command_code::diagnose),
                               to_string(bits::test::poll_target), to_string(speed));
                }
            }
            return res_cmd.error();
        };

        PN532_LOGI("%s: running %s...", to_string(command_code::diagnose), to_string(bits::test::poll_target));
        const auto slow_fails = get_fails(slow, baudrate::kbps212);
        if (slow_fails) {
            const auto fast_fails = get_fails(fast, baudrate::kbps424);
            if (fast_fails) {
                PN532_LOGI("%s: %s test succeeded.", to_string(command_code::diagnose), to_string(bits::test::poll_target));
                return {*slow_fails, *fast_fails};
            }
            return fast_fails.error();
        }
        return slow_fails.error();
    }

    controller::result<> controller::diagnose_echo_back(ms reply_delay, std::uint8_t tx_mode, std::uint8_t rx_mode, ms timeout) {
        PN532_LOGI("%s: running %s...", to_string(command_code::diagnose), to_string(bits::test::echo_back));
        bin_data payload = bin_data::chain(
                prealloc(4),
                bits::test::echo_back,
                std::uint8_t(reply_delay.count() * bits::echo_back_reply_delay_steps_per_ms),
                tx_mode,
                rx_mode);
        return chn().command(command_code::diagnose, std::move(payload), timeout);
    }

    controller::result<bool> controller::diagnose_rom(ms timeout) {
        return nfc_diagnose_simple(chn(), bits::test::rom, 0x00, timeout);
    }

    controller::result<bool> controller::diagnose_ram(ms timeout) {
        return nfc_diagnose_simple(chn(), bits::test::ram, 0x00, timeout);
    }

    controller::result<bool> controller::diagnose_attention_req_or_card_presence(ms timeout) {
        return nfc_diagnose_simple(chn(), bits::test::attention_req_or_card_presence, 0x00, timeout);
    }

    controller::result<bool> controller::diagnose_self_antenna(
            low_current_thr low_threshold, high_current_thr high_threshold, ms timeout) {
        const reg_antenna_detector r{
                .detected_low_pwr = false,
                .detected_high_pwr = false,
                .low_current_threshold = low_threshold,
                .high_current_threshold = high_threshold,
                .enable_detection = true};
        return nfc_diagnose_simple(chn(), bits::test::self_antenna, 0x00, timeout, 1, r);
    }

    controller::result<firmware_version> controller::get_firmware_version(ms timeout) {
        return chn().command_parse_response<firmware_version>(command_code::get_firmware_version, bin_data{}, timeout);
    }

    controller::result<general_status> controller::get_general_status(ms timeout) {
        return chn().command_parse_response<general_status>(command_code::get_general_status, bin_data{}, timeout);
    }


    controller::result<std::vector<uint8_t>> controller::read_registers(std::vector<reg_addr> const &addresses, ms timeout) {
        static constexpr std::size_t max_addr_count = bits::max_firmware_data_length / 2;
        if (addresses.size() > max_addr_count) {
            PN532_LOGE("%s: requested %u addresses, but can read at most %u in a single batch.",
                       to_string(command_code::read_register), addresses.size(), max_addr_count);
        }
        const std::size_t effective_length = std::min(addresses.size(), max_addr_count);
        bin_data payload{prealloc(effective_length * 2)};
        for (std::size_t i = 0; i < effective_length; ++i) {
            payload << addresses[i];
        }
        if (auto res_cmd = chn().command_response(command_code::read_register, std::move(payload), timeout); res_cmd) {
            if (res_cmd->size() != effective_length) {
                PN532_LOGE("%s: requested %u registers, got %u instead.", to_string(command_code::read_register),
                           addresses.size(), res_cmd->size());
            }
            return std::vector<uint8_t>{std::move(*res_cmd)};
        } else {
            return res_cmd.error();
        }
    }

    controller::result<> controller::write_registers(std::vector<std::pair<reg_addr, std::uint8_t>> const &addr_value_pairs, ms timeout) {
        static constexpr std::size_t max_avp_count = bits::max_firmware_data_length / 3;
        if (addr_value_pairs.size() > max_avp_count) {
            PN532_LOGE("%s: requested %u addresses, but can read at most %u in a single batch.",
                       to_string(command_code::write_register), addr_value_pairs.size(), max_avp_count);
        }
        const std::size_t effective_length = std::min(addr_value_pairs.size(), max_avp_count);
        bin_data payload{prealloc(effective_length * 3)};
        for (std::size_t i = 0; i < effective_length; ++i) {
            payload << addr_value_pairs[i].first << addr_value_pairs[i].second;
        }
        return chn().command_response(command_code::write_register, std::move(payload), timeout);
    }

    controller::result<gpio_status> controller::read_gpio(ms timeout) {
        return chn().command_parse_response<gpio_status>(command_code::read_gpio, bin_data{}, timeout);
    }

    controller::result<> controller::write_gpio(gpio_status const &status, bool write_p3, bool write_p7, ms timeout) {
        if (not write_p3 and not write_p7) {
            PN532_LOGW("Attempt to write nothing on the GPIO, did you miss to pass some parameter?");
            return mlab::result_success;
        }
        bin_data payload{prealloc(2)};
        if (write_p3) {
            payload << std::uint8_t(bits::gpio_write_validate_max | status.mask(gpio_loc::p3));
        } else {
            payload << std::uint8_t{0x00};
        }
        if (write_p7) {
            payload << std::uint8_t(bits::gpio_write_validate_max | status.mask(gpio_loc::p7));
        } else {
            payload << std::uint8_t{0x00};
        }
        return chn().command_response(command_code::write_gpio, std::move(payload), timeout);
    }

    controller::result<> controller::set_gpio_pin(gpio_loc loc, std::uint8_t pin_idx, bool value, ms timeout) {
        reduce_timeout rt{timeout};
        if (auto res_read = read_gpio(rt.remaining()); res_read) {
            (*res_read)[{loc, pin_idx}] = value;
            const bool write_p3 = (loc == gpio_loc::p3);
            const bool write_p7 = (loc == gpio_loc::p7);
            return write_gpio(*res_read, write_p3, write_p7, rt.remaining());
        } else {
            return res_read.error();
        }
    }

    controller::result<> controller::set_serial_baud_rate(serial_baudrate br, ms timeout) {
        return chn().command_response(command_code::set_serial_baudrate, bin_data::chain(br), timeout);
    }

    controller::result<> controller::sam_configuration(sam_mode mode, ms sam_timeout, bool controller_drives_irq, ms timeout) {
        // Make sure a wake command is sent before
        chn().wake();
        const std::uint8_t sam_timeout_byte = std::min(0xffll, sam_timeout.count() / bits::sam_timeout_unit_ms);
        bin_data payload = bin_data::chain(
                prealloc(3),
                mode,
                sam_timeout_byte,
                controller_drives_irq);
        return chn().command_response(command_code::sam_configuration, std::move(payload), timeout);
    }

    controller::result<> controller::rf_configuration_field(bool auto_rfca, bool rf_on, ms timeout) {
        const std::uint8_t config_data =
                (auto_rfca ? bits::rf_configuration_field_auto_rfca_mask : 0x00) |
                (rf_on ? bits::rf_configuration_field_auto_rf_on_mask : 0x00);
        bin_data payload = bin_data::chain(
                prealloc(2),
                bits::rf_config_item::rf_field,
                config_data);
        return chn().command_response(command_code::rf_configuration, std::move(payload), timeout);
    }

    controller::result<> controller::rf_configuration_timings(
            rf_timeout atr_res_timeout, rf_timeout retry_timeout,
            ms timeout) {
        bin_data payload = bin_data::chain(
                prealloc(4),
                bits::rf_config_item::timings,
                0_b,
                atr_res_timeout,
                retry_timeout);
        return chn().command_response(command_code::rf_configuration, std::move(payload), timeout);
    }

    controller::result<> controller::rf_configuration_retries(infbyte comm_retries, ms timeout) {
        bin_data payload = bin_data::chain(
                prealloc(2),
                bits::rf_config_item::max_rty_com,
                comm_retries);
        return chn().command_response(command_code::rf_configuration, std::move(payload), timeout);
    }

    controller::result<> controller::rf_configuration_retries(
            infbyte atr_retries, infbyte psl_retries,
            infbyte passive_activation_retries, ms timeout) {
        bin_data payload = bin_data::chain(
                prealloc(4),
                bits::rf_config_item::max_retries,
                atr_retries,
                psl_retries,
                passive_activation_retries);
        return chn().command_response(command_code::rf_configuration, std::move(payload), timeout);
    }

    controller::result<> controller::rf_configuration_analog_106kbps_typea(ciu_reg_106kbps_typea const &config, ms timeout) {
        bin_data payload = bin_data::chain(
                prealloc(1 + sizeof(ciu_reg_106kbps_typea)),
                bits::rf_config_item::analog_106kbps_typea,
                config);
        return chn().command_response(command_code::rf_configuration, std::move(payload), timeout);
    }

    controller::result<> controller::rf_configuration_analog_212_424kbps(ciu_reg_212_424kbps const &config, ms timeout) {
        bin_data payload = bin_data::chain(
                prealloc(1 + sizeof(ciu_reg_212_424kbps)),
                bits::rf_config_item::analog_212_424kbps,
                config);
        return chn().command_response(command_code::rf_configuration, std::move(payload), timeout);
    }

    controller::result<> controller::rf_configuration_analog_typeb(ciu_reg_typeb const &config, ms timeout) {
        bin_data payload = bin_data::chain(
                prealloc(1 + sizeof(ciu_reg_typeb)),
                bits::rf_config_item::analog_typeb,
                config);
        return chn().command_response(command_code::rf_configuration, std::move(payload), timeout);
    }

    controller::result<> controller::rf_configuration_analog_iso_iec_14443_4(ciu_reg_iso_iec_14443_4 const &config, ms timeout) {
        bin_data payload = bin_data::chain(
                prealloc(1 + sizeof(ciu_reg_iso_iec_14443_4)),
                bits::rf_config_item::analog_iso_iec_14443_4,
                config);
        return chn().command_response(command_code::rf_configuration, std::move(payload), timeout);
    }

    std::uint8_t controller::get_target(command_code cmd, std::uint8_t target_logical_index, bool expect_more_data) {
        if (target_logical_index > bits::max_num_targets) {
            PN532_LOGE("%s: out of range (unsupported) logical target index %u (> %u).",
                       to_string(cmd), target_logical_index, bits::max_num_targets);
        }
        target_logical_index = std::min(target_logical_index, bits::max_num_targets);
        return target_logical_index | (expect_more_data ? bits::status_more_info_mask : 0x00);
    }

    controller::result<rf_status> controller::initiator_select(std::uint8_t target_logical_index, ms timeout) {
        const std::uint8_t target_byte = get_target(command_code::in_select, target_logical_index, false);
        return chn().command_parse_response<rf_status>(command_code::in_select, bin_data{target_byte}, timeout);
    }

    controller::result<rf_status> controller::initiator_deselect(std::uint8_t target_logical_index, ms timeout) {
        const std::uint8_t target_byte = get_target(command_code::in_deselect, target_logical_index, false);
        return chn().command_parse_response<rf_status>(command_code::in_deselect, bin_data{target_byte}, timeout);
    }

    controller::result<rf_status> controller::initiator_release(std::uint8_t target_logical_index, ms timeout) {
        const std::uint8_t target_byte = get_target(command_code::in_release, target_logical_index, false);
        return chn().command_parse_response<rf_status>(command_code::in_release, bin_data{target_byte}, timeout);
    }

    controller::result<rf_status> controller::initiator_psl(
            std::uint8_t target_logical_index, baudrate in_to_trg, baudrate trg_to_in,
            ms timeout) {
        const std::uint8_t target_byte = get_target(command_code::in_psl, target_logical_index, false);
        bin_data payload = bin_data::chain(prealloc(3), target_byte, in_to_trg, trg_to_in);
        return chn().command_parse_response<rf_status>(command_code::in_psl, std::move(payload), timeout);
    }

    namespace {
        void sanitize_max_targets(std::uint8_t &max_targets, const char *fname) {
            if (max_targets < 1 or max_targets > bits::max_num_targets) {
                PN532_LOGW("%s: incorrect max targets %u for %s, clamping.",
                           to_string(command_code::in_list_passive_target), max_targets, fname);
                max_targets = std::clamp(max_targets, std::uint8_t(1), bits::max_num_targets);
            }
        }
    }// namespace

    controller::result<std::vector<target_kbps106_typea>> controller::initiator_list_passive_kbps106_typea(
            std::uint8_t max_targets, ms timeout) {
        sanitize_max_targets(max_targets, "initiator_list_passive_kbps106_typea");
        return initiator_list_passive<baudrate_modulation::kbps106_iso_iec_14443_typea>(
                max_targets, bin_data{}, timeout);
    }

    controller::result<std::vector<target_kbps106_typea>> controller::initiator_list_passive_kbps106_typea(
            uid_cascade_l1 uid, std::uint8_t max_targets, ms timeout) {
        sanitize_max_targets(max_targets, "initiator_list_passive_kbps106_typea");
        return initiator_list_passive<baudrate_modulation::kbps106_iso_iec_14443_typea>(
                max_targets, bin_data::chain(uid), timeout);
    }

    controller::result<std::vector<target_kbps106_typea>> controller::initiator_list_passive_kbps106_typea(
            uid_cascade_l2 uid, std::uint8_t max_targets, ms timeout) {
        sanitize_max_targets(max_targets, "initiator_list_passive_kbps106_typea");
        return initiator_list_passive<baudrate_modulation::kbps106_iso_iec_14443_typea>(
                max_targets, bin_data::chain(uid), timeout);
    }

    controller::result<std::vector<target_kbps106_typea>> controller::initiator_list_passive_kbps106_typea(
            uid_cascade_l3 uid, std::uint8_t max_targets, ms timeout) {
        sanitize_max_targets(max_targets, "initiator_list_passive_kbps106_typea");
        return initiator_list_passive<baudrate_modulation::kbps106_iso_iec_14443_typea>(
                max_targets, bin_data::chain(uid), timeout);
    }

    controller::result<std::vector<target_kbps106_typeb>> controller::initiator_list_passive_kbps106_typeb(
            std::uint8_t application_family_id, polling_method method, std::uint8_t max_targets, ms timeout) {
        sanitize_max_targets(max_targets, "initiator_list_passive_kbps106_typeb");
        return initiator_list_passive<baudrate_modulation::kbps106_iso_iec_14443_3_typeb>(
                max_targets, bin_data::chain(prealloc(2), application_family_id, method), timeout);
    }

    controller::result<std::vector<target_kbps212_felica>> controller::initiator_list_passive_kbps212_felica(
            std::array<std::uint8_t, 5> const &payload, std::uint8_t max_targets, ms timeout) {
        sanitize_max_targets(max_targets, "initiator_list_passive_kbps212_felica");
        return initiator_list_passive<baudrate_modulation::kbps212_felica_polling>(
                max_targets, bin_data::chain(payload), timeout);
    }

    controller::result<std::vector<target_kbps424_felica>> controller::initiator_list_passive_kbps424_felica(
            std::array<std::uint8_t, 5> const &payload, std::uint8_t max_targets, ms timeout) {
        sanitize_max_targets(max_targets, "initiator_list_passive_kbps424_felica");
        return initiator_list_passive<baudrate_modulation::kbps424_felica_polling>(
                max_targets, bin_data::chain(payload), timeout);
    }

    controller::result<std::vector<target_kbps106_jewel_tag>> controller::initiator_list_passive_kbps106_jewel_tag(ms timeout) {
        return initiator_list_passive<baudrate_modulation::kbps106_innovision_jewel_tag>(1, bin_data{}, timeout);
    }

    template <baudrate_modulation BrMd>
    controller::result<std::vector<bits::target<BrMd>>> controller::initiator_list_passive(
            std::uint8_t max_targets, bin_data const &initiator_data, ms timeout) {
        bin_data payload = bin_data::chain(
                prealloc(2 + initiator_data.size()),
                max_targets,
                BrMd,
                initiator_data);
        auto res_cmd = chn().command_parse_response<std::vector<bits::target<BrMd>>>(
                command_code::in_list_passive_target, std::move(payload), timeout);
        if (not res_cmd and res_cmd.error() == channel::error::comm_timeout) {
            // Canceled commands means no target was found, return thus an empty array as technically it's correct
            return std::vector<bits::target<BrMd>>{};
        }
        return res_cmd;
    }

    namespace {
        std::uint8_t get_in_atr_next(bool has_nfcid_3t, bool has_general_info) {
            return (has_nfcid_3t ? bits::in_atr_nfcid_3t_present_mask : 0x00) |
                   (has_general_info ? bits::in_atr_general_info_present_mask : 0x00);
        }

        range<std::vector<std::uint8_t>::const_iterator> sanitize_vector(
                command_code cmd, const char *v_name, std::vector<std::uint8_t> const &v, std::size_t max_len) {
            if (v.size() > max_len) {
                PN532_LOGW("%s: %s vector too long (%u), truncating to %u bytes.", to_string(cmd), v_name, v.size(), max_len);
            }
            return make_range(
                    std::begin(v),
                    std::begin(v) + std::min(max_len, v.size()));
        }

        range<std::vector<std::uint8_t>::const_iterator> sanitize_initiator_general_info(
                command_code cmd, std::vector<std::uint8_t> const &gi) {
            return sanitize_vector(cmd, "general info", gi, bits::general_info_max_length);
        }

        range<std::vector<std::uint8_t>::const_iterator> sanitize_target_general_info(
                command_code cmd, std::vector<std::uint8_t> const &gi) {
            return sanitize_vector(cmd, "general info", gi, bits::init_as_target_general_info_max_length);
        }

        range<std::vector<std::uint8_t>::const_iterator> sanitize_target_historical_bytes(
                command_code cmd, std::vector<std::uint8_t> const &hb) {
            return sanitize_vector(cmd, "historical bytes", hb, bits::init_as_target_historical_bytes_max_length);
        }
    }// namespace


    controller::result<rf_status, atr_res_info> controller::initiator_activate_target(std::uint8_t target_logical_index, ms timeout) {
        const auto next_byte = get_in_atr_next(false, false);
        return chn().command_parse_response<std::pair<rf_status, atr_res_info>>(
                command_code::in_atr,
                bin_data::chain(target_logical_index, next_byte),
                timeout);
    }

    controller::result<rf_status, atr_res_info> controller::initiator_activate_target(
            std::uint8_t target_logical_index,
            std::array<std::uint8_t, 10> const &nfcid_3t,
            ms timeout) {
        const auto next_byte = get_in_atr_next(true, false);
        return chn().command_parse_response<std::pair<rf_status, atr_res_info>>(
                command_code::in_atr,
                bin_data::chain(target_logical_index, next_byte, nfcid_3t),
                timeout);
    }

    controller::result<rf_status, atr_res_info> controller::initiator_activate_target(
            std::uint8_t target_logical_index,
            std::vector<std::uint8_t> const &general_info,
            ms timeout) {
        const auto next_byte = get_in_atr_next(false, true);
        const auto gi_view = sanitize_initiator_general_info(command_code::in_atr, general_info);
        return chn().command_parse_response<std::pair<rf_status, atr_res_info>>(
                command_code::in_atr,
                bin_data::chain(target_logical_index, next_byte, gi_view),
                timeout);
    }

    controller::result<rf_status, atr_res_info> controller::initiator_activate_target(
            std::uint8_t target_logical_index,
            std::array<std::uint8_t, 10> const &nfcid_3t,
            std::vector<std::uint8_t> const &general_info,
            ms timeout) {
        const auto next_byte = get_in_atr_next(true, true);
        const auto gi_view = sanitize_initiator_general_info(command_code::in_atr, general_info);
        return chn().command_parse_response<std::pair<rf_status, atr_res_info>>(
                command_code::in_atr,
                bin_data::chain(target_logical_index, next_byte, nfcid_3t, gi_view),
                timeout);
    }

    controller::result<std::vector<any_target>> controller::initiator_auto_poll(
            std::vector<target_type> const &types_to_poll,
            infbyte polls_per_type, poll_period period,
            ms timeout) {
        if (types_to_poll.empty()) {
            PN532_LOGW("%s: no target types specified.", to_string(command_code::in_autopoll));
            return std::vector<any_target>{};
        }
        if (types_to_poll.size() > bits::autopoll_max_types) {
            PN532_LOGW("%s: too many (%u) types to poll, at most %u will be considered.",
                       to_string(command_code::in_autopoll), types_to_poll.size(), bits::autopoll_max_types);
        }
        const auto num_types = std::min(bits::autopoll_max_types, types_to_poll.size());
        const auto target_view = make_range(std::begin(types_to_poll), std::begin(types_to_poll) + num_types);
        bin_data payload = bin_data::chain(
                prealloc(2 + num_types),
                polls_per_type,
                period,
                target_view);
        auto res_cmd = chn().command_parse_response<std::vector<any_target>>(command_code::in_autopoll, std::move(payload), timeout);
        if (not res_cmd and res_cmd.error() == channel::error::comm_timeout) {
            // Canceled commands means no target was found, return thus an empty array as technically it's correct
            return std::vector<any_target>{};
        }
        return res_cmd;
    }

    controller::result<rf_status, bin_data> controller::initiator_data_exchange(
            std::uint8_t target_logical_index, bin_data const &data, ms timeout) {
        static constexpr std::size_t max_chunk_length = bits::max_firmware_data_length - 1;// - target byte
        const auto n_chunks = std::max(1u, (data.size() + max_chunk_length - 1) / max_chunk_length);
        if (n_chunks > 1) {
            PN532_LOGI("%s: %u bytes will be sent in %u chunks.", to_string(command_code::in_data_exchange), data.size(),
                       n_chunks);
        }
        PN532_LOGD("%s: sending the following data to target %u:", to_string(command_code::in_data_exchange),
                   target_logical_index);
        ESP_LOG_BUFFER_HEX_LEVEL(PN532_TAG, data.data(), data.size(), ESP_LOG_DEBUG);
        reduce_timeout rt{timeout};
        bin_data data_in{};
        rf_status s{};
        for (std::size_t chunk_idx = 0; chunk_idx < n_chunks; ++chunk_idx) {
            const auto data_view = data.view(chunk_idx * max_chunk_length, max_chunk_length);
            const bool more_data = (chunk_idx < n_chunks - 1);
            const std::uint8_t target_byte = get_target(command_code::in_data_exchange, target_logical_index,
                                                        more_data);
            if (n_chunks > 1) {
                PN532_LOGI("%s: sending chunk %u/%u...", to_string(command_code::in_data_exchange), chunk_idx + 1, n_chunks);
            }
            bin_data payload = bin_data::chain(prealloc(1u + data_view.size()), target_byte, data_view);
            auto res_cmd = chn().command_parse_response<std::pair<rf_status, bin_data>>(
                    command_code::in_data_exchange, std::move(payload), rt.remaining());
            if (not res_cmd) {
                return res_cmd.error();
            }
            if (res_cmd->first.error != controller_error::none) {
                if (more_data) {
                    PN532_LOGE("%s: aborting multiple chunks transfer because controller returned error %s.",
                               to_string(command_code::in_data_exchange), to_string(res_cmd->first.error));
                    // Send an ack to abort whatever is left in the controller.
                    chn().send_ack(true, 1s);
                }
                return res_cmd;
            }
            // Append data and continue
            s = res_cmd->first;
            data_in << res_cmd->second;
        }
        return {s, std::move(data_in)};
    }


    controller::result<rf_status, bin_data> controller::initiator_communicate_through(bin_data raw_data, ms timeout) {
        return chn().command_parse_response<std::pair<rf_status, bin_data>>(command_code::in_communicate_thru, std::move(raw_data),
                                                                            timeout);
    }

    namespace {
        std::uint8_t get_in_jump_for_dep_psl_next(
                bool has_passive_init_data, bool has_nfcid_3t, bool has_general_info) {
            return (has_passive_init_data ? bits::in_jump_for_dep_passive_init_data_present_mask : 0x00) |
                   (has_nfcid_3t ? bits::in_jump_for_dep_nfcid_3t_present_mask : 0x00) |
                   (has_general_info ? bits::in_jump_for_dep_general_info_present_mask : 0x00);
        }
    }// namespace

    controller::result<jump_dep_psl> controller::initiator_jump_for_dep_active(baudrate speed, ms timeout) {
        const auto next_byte = get_in_jump_for_dep_psl_next(false, false, false);
        return chn().command_parse_response<jump_dep_psl>(
                command_code::in_jump_for_dep,
                bin_data::chain(true /* active */, speed, next_byte),
                timeout);
    }

    controller::result<jump_dep_psl> controller::initiator_jump_for_dep_active(
            baudrate speed, std::array<std::uint8_t, 10> const &nfcid_3t, ms timeout) {
        const auto next_byte = get_in_jump_for_dep_psl_next(false, true, false);
        return chn().command_parse_response<jump_dep_psl>(
                command_code::in_jump_for_dep,
                bin_data::chain(true /* active */, speed, next_byte, nfcid_3t),
                timeout);
    }

    controller::result<jump_dep_psl> controller::initiator_jump_for_dep_passive_106kbps(ms timeout) {
        const auto next_byte = get_in_jump_for_dep_psl_next(false, false, false);
        return chn().command_parse_response<jump_dep_psl>(
                command_code::in_jump_for_dep,
                bin_data::chain(false /* passive */, baudrate::kbps106, next_byte),
                timeout);
    }

    controller::result<jump_dep_psl> controller::initiator_jump_for_dep_passive_106kbps(
            std::array<std::uint8_t, 10> const &nfcid_3t, ms timeout) {
        const auto next_byte = get_in_jump_for_dep_psl_next(false, true, false);
        return chn().command_parse_response<jump_dep_psl>(
                command_code::in_jump_for_dep,
                bin_data::chain(false /* passive */, baudrate::kbps106, next_byte, nfcid_3t),
                timeout);
    }

    controller::result<jump_dep_psl> controller::initiator_jump_for_dep_passive_106kbps(
            std::array<std::uint8_t, 4> const &target_id, ms timeout) {
        const auto next_byte = get_in_jump_for_dep_psl_next(true, false, false);
        return chn().command_parse_response<jump_dep_psl>(
                command_code::in_jump_for_dep,
                bin_data::chain(false /* passive */, baudrate::kbps106, next_byte, target_id),
                timeout);
    }

    controller::result<jump_dep_psl> controller::initiator_jump_for_dep_passive_106kbps(
            std::array<std::uint8_t, 4> const &target_id, std::array<std::uint8_t, 10> const &nfcid_3t, ms timeout) {
        const auto next_byte = get_in_jump_for_dep_psl_next(true, true, false);
        return chn().command_parse_response<jump_dep_psl>(
                command_code::in_jump_for_dep,
                bin_data::chain(false /* passive */, baudrate::kbps106, next_byte, target_id, nfcid_3t),
                timeout);
    }

    controller::result<jump_dep_psl> controller::initiator_jump_for_dep_passive_212kbps(
            std::array<std::uint8_t, 5> const &target_id, ms timeout) {
        const auto next_byte = get_in_jump_for_dep_psl_next(true, false, false);
        return chn().command_parse_response<jump_dep_psl>(
                command_code::in_jump_for_dep,
                bin_data::chain(false /* passive */, baudrate::kbps212, next_byte, target_id, target_id),
                timeout);
    }

    controller::result<jump_dep_psl> controller::initiator_jump_for_dep_passive_424kbps(
            std::array<std::uint8_t, 5> const &target_id, ms timeout) {
        const auto next_byte = get_in_jump_for_dep_psl_next(true, false, false);
        return chn().command_parse_response<jump_dep_psl>(
                command_code::in_jump_for_dep,
                bin_data::chain(false /* passive */, baudrate::kbps424, next_byte, target_id, target_id),
                timeout);
    }


    controller::result<jump_dep_psl> controller::initiator_jump_for_dep_active(
            baudrate speed,
            std::vector<std::uint8_t> const &general_info, ms timeout) {
        const auto next_byte = get_in_jump_for_dep_psl_next(false, false, true);
        const auto gi_view = sanitize_initiator_general_info(command_code::in_jump_for_dep, general_info);
        return chn().command_parse_response<jump_dep_psl>(
                command_code::in_jump_for_dep,
                bin_data::chain(true /* active */, speed, next_byte, gi_view),
                timeout);
    }

    controller::result<jump_dep_psl> controller::initiator_jump_for_dep_active(
            baudrate speed, std::array<std::uint8_t, 10> const &nfcid_3t,
            std::vector<std::uint8_t> const &general_info, ms timeout) {
        const auto next_byte = get_in_jump_for_dep_psl_next(false, true, true);
        const auto gi_view = sanitize_initiator_general_info(command_code::in_jump_for_dep, general_info);
        return chn().command_parse_response<jump_dep_psl>(
                command_code::in_jump_for_dep,
                bin_data::chain(true /* active */, speed, next_byte, nfcid_3t, gi_view),
                timeout);
    }

    controller::result<jump_dep_psl> controller::initiator_jump_for_dep_passive_106kbps(
            std::vector<std::uint8_t> const &general_info, ms timeout) {
        const auto next_byte = get_in_jump_for_dep_psl_next(false, false, true);
        const auto gi_view = sanitize_initiator_general_info(command_code::in_jump_for_dep, general_info);
        return chn().command_parse_response<jump_dep_psl>(
                command_code::in_jump_for_dep,
                bin_data::chain(false /* passive */, baudrate::kbps106, next_byte, gi_view),
                timeout);
    }

    controller::result<jump_dep_psl> controller::initiator_jump_for_dep_passive_106kbps(
            std::array<std::uint8_t, 10> const &nfcid_3t,
            std::vector<std::uint8_t> const &general_info, ms timeout) {
        const auto next_byte = get_in_jump_for_dep_psl_next(false, true, true);
        const auto gi_view = sanitize_initiator_general_info(command_code::in_jump_for_dep, general_info);
        return chn().command_parse_response<jump_dep_psl>(
                command_code::in_jump_for_dep,
                bin_data::chain(false /* passive */, baudrate::kbps106, next_byte, nfcid_3t, gi_view),
                timeout);
    }

    controller::result<jump_dep_psl> controller::initiator_jump_for_dep_passive_106kbps(
            std::array<std::uint8_t, 4> const &target_id,
            std::vector<std::uint8_t> const &general_info, ms timeout) {
        const auto next_byte = get_in_jump_for_dep_psl_next(true, false, true);
        const auto gi_view = sanitize_initiator_general_info(command_code::in_jump_for_dep, general_info);
        return chn().command_parse_response<jump_dep_psl>(
                command_code::in_jump_for_dep,
                bin_data::chain(false /* passive */, baudrate::kbps106, next_byte, target_id, gi_view),
                timeout);
    }

    controller::result<jump_dep_psl> controller::initiator_jump_for_dep_passive_106kbps(
            std::array<std::uint8_t, 4> const &target_id, std::array<std::uint8_t, 10> const &nfcid_3t,
            std::vector<std::uint8_t> const &general_info, ms timeout) {
        const auto next_byte = get_in_jump_for_dep_psl_next(true, true, true);
        const auto gi_view = sanitize_initiator_general_info(command_code::in_jump_for_dep, general_info);
        return chn().command_parse_response<jump_dep_psl>(
                command_code::in_jump_for_dep,
                bin_data::chain(false /* passive */, baudrate::kbps106, next_byte, target_id, nfcid_3t, gi_view),
                timeout);
    }

    controller::result<jump_dep_psl> controller::initiator_jump_for_dep_passive_212kbps(
            std::array<std::uint8_t, 5> const &target_id,
            std::vector<std::uint8_t> const &general_info, ms timeout) {
        const auto next_byte = get_in_jump_for_dep_psl_next(true, false, true);
        const auto gi_view = sanitize_initiator_general_info(command_code::in_jump_for_dep, general_info);
        return chn().command_parse_response<jump_dep_psl>(
                command_code::in_jump_for_dep,
                bin_data::chain(false /* passive */, baudrate::kbps212, next_byte, target_id, target_id, gi_view),
                timeout);
    }

    controller::result<jump_dep_psl> controller::initiator_jump_for_dep_passive_424kbps(
            std::array<std::uint8_t, 5> const &target_id,
            std::vector<std::uint8_t> const &general_info, ms timeout) {
        const auto next_byte = get_in_jump_for_dep_psl_next(true, false, true);
        const auto gi_view = sanitize_initiator_general_info(command_code::in_jump_for_dep, general_info);
        return chn().command_parse_response<jump_dep_psl>(
                command_code::in_jump_for_dep,
                bin_data::chain(false /* passive */, baudrate::kbps424, next_byte, target_id, target_id, gi_view),
                timeout);
    }


    controller::result<jump_dep_psl> controller::initiator_jump_for_psl_active(baudrate speed, ms timeout) {
        const auto next_byte = get_in_jump_for_dep_psl_next(false, false, false);
        return chn().command_parse_response<jump_dep_psl>(
                command_code::in_jump_for_psl,
                bin_data::chain(true /* active */, speed, next_byte),
                timeout);
    }

    controller::result<jump_dep_psl> controller::initiator_jump_for_psl_active(
            baudrate speed, std::array<std::uint8_t, 10> const &nfcid_3t, ms timeout) {
        const auto next_byte = get_in_jump_for_dep_psl_next(false, true, false);
        return chn().command_parse_response<jump_dep_psl>(
                command_code::in_jump_for_psl,
                bin_data::chain(true /* active */, speed, next_byte, nfcid_3t),
                timeout);
    }

    controller::result<jump_dep_psl> controller::initiator_jump_for_psl_passive_106kbps(ms timeout) {
        const auto next_byte = get_in_jump_for_dep_psl_next(false, false, false);
        return chn().command_parse_response<jump_dep_psl>(
                command_code::in_jump_for_psl,
                bin_data::chain(false /* passive */, baudrate::kbps106, next_byte),
                timeout);
    }

    controller::result<jump_dep_psl> controller::initiator_jump_for_psl_passive_106kbps(
            std::array<std::uint8_t, 10> const &nfcid_3t, ms timeout) {
        const auto next_byte = get_in_jump_for_dep_psl_next(false, true, false);
        return chn().command_parse_response<jump_dep_psl>(
                command_code::in_jump_for_psl,
                bin_data::chain(false /* passive */, baudrate::kbps106, next_byte, nfcid_3t),
                timeout);
    }

    controller::result<jump_dep_psl> controller::initiator_jump_for_psl_passive_106kbps(
            std::array<std::uint8_t, 4> const &target_id, ms timeout) {
        const auto next_byte = get_in_jump_for_dep_psl_next(true, false, false);
        return chn().command_parse_response<jump_dep_psl>(
                command_code::in_jump_for_psl,
                bin_data::chain(false /* passive */, baudrate::kbps106, next_byte, target_id),
                timeout);
    }

    controller::result<jump_dep_psl> controller::initiator_jump_for_psl_passive_106kbps(
            std::array<std::uint8_t, 4> const &target_id, std::array<std::uint8_t, 10> const &nfcid_3t, ms timeout) {
        const auto next_byte = get_in_jump_for_dep_psl_next(true, true, false);
        return chn().command_parse_response<jump_dep_psl>(
                command_code::in_jump_for_psl,
                bin_data::chain(false /* passive */, baudrate::kbps106, next_byte, target_id, nfcid_3t),
                timeout);
    }

    controller::result<jump_dep_psl> controller::initiator_jump_for_psl_passive_212kbps(
            std::array<std::uint8_t, 5> const &target_id, ms timeout) {
        const auto next_byte = get_in_jump_for_dep_psl_next(true, false, false);
        return chn().command_parse_response<jump_dep_psl>(
                command_code::in_jump_for_psl,
                bin_data::chain(false /* passive */, baudrate::kbps212, next_byte, target_id, target_id),
                timeout);
    }

    controller::result<jump_dep_psl> controller::initiator_jump_for_psl_passive_424kbps(
            std::array<std::uint8_t, 5> const &target_id, ms timeout) {
        const auto next_byte = get_in_jump_for_dep_psl_next(true, false, false);
        return chn().command_parse_response<jump_dep_psl>(
                command_code::in_jump_for_psl,
                bin_data::chain(false /* passive */, baudrate::kbps424, next_byte, target_id, target_id),
                timeout);
    }


    controller::result<jump_dep_psl> controller::initiator_jump_for_psl_active(
            baudrate speed,
            std::vector<std::uint8_t> const &general_info, ms timeout) {
        const auto next_byte = get_in_jump_for_dep_psl_next(false, false, true);
        const auto gi_view = sanitize_initiator_general_info(command_code::in_jump_for_psl, general_info);
        return chn().command_parse_response<jump_dep_psl>(
                command_code::in_jump_for_psl,
                bin_data::chain(true /* active */, speed, next_byte, gi_view),
                timeout);
    }

    controller::result<jump_dep_psl> controller::initiator_jump_for_psl_active(
            baudrate speed, std::array<std::uint8_t, 10> const &nfcid_3t,
            std::vector<std::uint8_t> const &general_info, ms timeout) {
        const auto next_byte = get_in_jump_for_dep_psl_next(false, true, true);
        const auto gi_view = sanitize_initiator_general_info(command_code::in_jump_for_psl, general_info);
        return chn().command_parse_response<jump_dep_psl>(
                command_code::in_jump_for_psl,
                bin_data::chain(true /* active */, speed, next_byte, nfcid_3t, gi_view),
                timeout);
    }

    controller::result<jump_dep_psl> controller::initiator_jump_for_psl_passive_106kbps(
            std::vector<std::uint8_t> const &general_info, ms timeout) {
        const auto next_byte = get_in_jump_for_dep_psl_next(false, false, true);
        const auto gi_view = sanitize_initiator_general_info(command_code::in_jump_for_psl, general_info);
        return chn().command_parse_response<jump_dep_psl>(
                command_code::in_jump_for_psl,
                bin_data::chain(false /* passive */, baudrate::kbps106, next_byte, gi_view),
                timeout);
    }

    controller::result<jump_dep_psl> controller::initiator_jump_for_psl_passive_106kbps(
            std::array<std::uint8_t, 10> const &nfcid_3t,
            std::vector<std::uint8_t> const &general_info, ms timeout) {
        const auto next_byte = get_in_jump_for_dep_psl_next(false, true, true);
        const auto gi_view = sanitize_initiator_general_info(command_code::in_jump_for_psl, general_info);
        return chn().command_parse_response<jump_dep_psl>(
                command_code::in_jump_for_psl,
                bin_data::chain(false /* passive */, baudrate::kbps106, next_byte, nfcid_3t, gi_view),
                timeout);
    }

    controller::result<jump_dep_psl> controller::initiator_jump_for_psl_passive_106kbps(
            std::array<std::uint8_t, 4> const &target_id,
            std::vector<std::uint8_t> const &general_info, ms timeout) {
        const auto next_byte = get_in_jump_for_dep_psl_next(true, false, true);
        const auto gi_view = sanitize_initiator_general_info(command_code::in_jump_for_psl, general_info);
        return chn().command_parse_response<jump_dep_psl>(
                command_code::in_jump_for_psl,
                bin_data::chain(false /* passive */, baudrate::kbps106, next_byte, target_id, gi_view),
                timeout);
    }

    controller::result<jump_dep_psl> controller::initiator_jump_for_psl_passive_106kbps(
            std::array<std::uint8_t, 4> const &target_id, std::array<std::uint8_t, 10> const &nfcid_3t,
            std::vector<std::uint8_t> const &general_info, ms timeout) {
        const auto next_byte = get_in_jump_for_dep_psl_next(true, true, true);
        const auto gi_view = sanitize_initiator_general_info(command_code::in_jump_for_psl, general_info);
        return chn().command_parse_response<jump_dep_psl>(
                command_code::in_jump_for_psl,
                bin_data::chain(false /* passive */, baudrate::kbps106, next_byte, target_id, nfcid_3t, gi_view),
                timeout);
    }

    controller::result<jump_dep_psl> controller::initiator_jump_for_psl_passive_212kbps(
            std::array<std::uint8_t, 5> const &target_id,
            std::vector<std::uint8_t> const &general_info, ms timeout) {
        const auto next_byte = get_in_jump_for_dep_psl_next(true, false, true);
        const auto gi_view = sanitize_initiator_general_info(command_code::in_jump_for_psl, general_info);
        return chn().command_parse_response<jump_dep_psl>(
                command_code::in_jump_for_psl,
                bin_data::chain(false /* passive */, baudrate::kbps212, next_byte, target_id, target_id, gi_view),
                timeout);
    }

    controller::result<jump_dep_psl> controller::initiator_jump_for_psl_passive_424kbps(
            std::array<std::uint8_t, 5> const &target_id,
            std::vector<std::uint8_t> const &general_info, ms timeout) {
        const auto next_byte = get_in_jump_for_dep_psl_next(true, false, true);
        const auto gi_view = sanitize_initiator_general_info(command_code::in_jump_for_psl, general_info);
        return chn().command_parse_response<jump_dep_psl>(
                command_code::in_jump_for_psl,
                bin_data::chain(false /* passive */, baudrate::kbps424, next_byte, target_id, target_id, gi_view),
                timeout);
    }

    controller::result<> controller::set_parameters(parameters const &parms, ms timeout) {
        return chn().command_response(command_code::set_parameters, bin_data::chain(parms), timeout);
    }

    controller::result<rf_status> controller::power_down(std::vector<wakeup_source> const &wakeup_sources, ms timeout) {
        return chn().command_parse_response<rf_status>(command_code::power_down, bin_data::chain(wakeup_sources), timeout);
    }

    controller::result<rf_status> controller::power_down(std::vector<wakeup_source> const &wakeup_sources, bool generate_irq, ms timeout) {
        return chn().command_parse_response<rf_status>(command_code::power_down,
                                                       bin_data::chain(prealloc(2), wakeup_sources, generate_irq),
                                                       timeout);
    }

    controller::result<> controller::rf_regulation_test(tx_mode mode, ms timeout) {
        return chn().command(command_code::rf_regulation_test, bin_data::chain(mode), timeout);
    }

    controller::result<status_as_target> controller::target_get_target_status(ms timeout) {
        return chn().command_parse_response<status_as_target>(command_code::tg_get_target_status, bin_data{}, timeout);
    }

    controller::result<init_as_target_res> controller::target_init_as_target(
            bool picc_only, bool dep_only, bool passive_only, mifare_params const &mifare,
            felica_params const &felica, std::array<std::uint8_t, 10> const &nfcid_3t,
            std::vector<std::uint8_t> const &general_info,
            std::vector<std::uint8_t> const &historical_bytes, ms timeout) {
        const std::uint8_t mode_byte = (picc_only ? bits::init_as_target_picc_only_bit : 0x00) |
                                       (dep_only ? bits::init_as_target_dep_only_bit : 0x00) |
                                       (passive_only ? bits::init_as_target_passive_only_bit : 0x00);
        const auto gi_view = sanitize_target_general_info(command_code::tg_init_as_target, general_info);
        const auto tk_view = sanitize_target_historical_bytes(command_code::tg_init_as_target, historical_bytes);
        bin_data payload = bin_data::chain(
                prealloc(37u + gi_view.size() + tk_view.size()),
                mode_byte,
                mifare,
                felica,
                nfcid_3t,
                std::uint8_t(gi_view.size()),
                gi_view,
                std::uint8_t(tk_view.size()),
                tk_view);
        return chn().command_parse_response<init_as_target_res>(command_code::tg_init_as_target, std::move(payload), timeout);
    }

    controller::result<rf_status> controller::target_set_general_bytes(std::vector<std::uint8_t> const &general_info, ms timeout) {
        const auto gi_view = sanitize_target_general_info(command_code::tg_set_general_bytes, general_info);
        return chn().command_parse_response<rf_status>(command_code::tg_set_general_bytes, bin_data::chain(gi_view),
                                                       timeout);
    }

    controller::result<rf_status, bin_data> controller::target_get_data(ms timeout) {
        return chn().command_parse_response<std::pair<rf_status, bin_data>>(command_code::tg_get_data, bin_data{}, timeout);
    }

    controller::result<rf_status> controller::target_set_data(std::vector<std::uint8_t> const &data, ms timeout) {
        const auto view = sanitize_vector(command_code::tg_set_data, "data", data, bits::max_firmware_data_length - 1);
        return chn().command_parse_response<rf_status>(command_code::tg_set_data, bin_data::chain(view), timeout);
    }

    controller::result<rf_status> controller::target_set_metadata(std::vector<std::uint8_t> const &data, ms timeout) {
        const auto view = sanitize_vector(command_code::tg_set_metadata, "metadata", data,
                                          bits::max_firmware_data_length - 1);
        return chn().command_parse_response<rf_status>(command_code::tg_set_metadata, bin_data::chain(view), timeout);
    }

    controller::result<rf_status, bin_data> controller::target_get_initiator_command(ms timeout) {
        return chn().command_parse_response<std::pair<rf_status, bin_data>>(command_code::tg_get_initiator_command,
                                                                            bin_data{}, timeout);
    }

    controller::result<rf_status> controller::target_response_to_initiator(std::vector<std::uint8_t> const &data, ms timeout) {
        const auto view = sanitize_vector(command_code::tg_response_to_initiator, "response", data,
                                          bits::max_firmware_data_length - 1);
        return chn().command_parse_response<rf_status>(command_code::tg_response_to_initiator, bin_data::chain(view),
                                                       timeout);
    }


}// namespace pn532