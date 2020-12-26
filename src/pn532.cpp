//
// Created by Pietro Saccardi on 20/12/2020.
//
#include "bits_algo.hpp"
#include "pn532.hpp"
#include "log.h"

namespace pn532 {

    const std::vector<bits::target_type> nfc::poll_all_targets = {
            target_type::generic_passive_106kbps,
            target_type::generic_passive_212kbps,
            target_type::generic_passive_424kbps,
            target_type::passive_106kbps_iso_iec_14443_4_typeb,
            target_type::innovision_jewel_tag
    };

    const char *to_string(nfc::error e) {
        switch (e) {
            case nfc::error::comm_checksum_fail: return "Checksum (length or data) failed";
            case nfc::error::comm_malformed:     return "Malformed or unexpected response";
            case nfc::error::comm_error:         return "Controller returned error instead of ACK";
            case nfc::error::failure:            return "Controller acknowledged but returned error";
            case nfc::error::comm_timeout:       return "Communication reached timeout";
            case nfc::error::canceled:           return "Comm ok, but no response within timeout";
            case nfc::error::nack:               return "Controller did not acknowledge.";
            default: return "UNKNOWN";
        }
    }

    namespace {
        enum struct frame_type {
            ack,
            nack,
            info
        };
    }

    struct nfc::frame_header {
        frame_type type;
        std::size_t length;
    };

    struct nfc::frame_body {
        bits::transport transport;
        command_code command;
        bin_data info;
    };

    /* -----------------------------------------------------------------------------------------------------------------
     * RAW COMMUNICATION -----------------------------------------------------------------------------------------------
     */

    bin_data nfc::get_command_info_frame(command_code cmd, bin_data const &payload) {
        const auto cmd_byte = bits::host_to_pn532_command(cmd);
        const auto transport_byte = static_cast<std::uint8_t>(bits::transport::host_to_pn532);
        // "2" because must count transport info and command_code
        const bool use_extended_format = (payload.size() > 0xff - 2);
        if (payload.size() > bits::max_firmware_data_length) {
            LOGE("%s: payload too long for an info frame, truncating %ul bytes to %ul:",
                 to_string(cmd),
                 payload.size(),
                 bits::max_firmware_data_length);
            ESP_LOG_BUFFER_HEX_LEVEL(PN532_TAG, payload.data(), payload.size(), ESP_LOG_WARN);
        }
        const std::uint8_t length = std::min(payload.size(), bits::max_firmware_data_length);
        // Make sure data gets truncated and nothing too weird happens
        const auto truncated_data = payload.view(0, length);
        // Precompute transport info + cmd byte + info compute_checksum
        const auto checksum = bits::compute_checksum(
                transport_byte + cmd_byte,
                std::begin(truncated_data),
                std::end(truncated_data)
        );
        bin_data frame{};
        frame << prealloc(length + 12) << bits::preamble << bits::start_of_packet_code;
        if (use_extended_format) {
            frame << bits::fixed_extended_packet_length << bits::length_and_checksum_long(length + 2);
        } else {
            frame << bits::length_and_checksum_short(length + 2);
        }
        return frame << transport_byte << cmd_byte << truncated_data << checksum << bits::postamble;
    }

    bin_data const &nfc::get_ack_frame() {
        static const bin_data ack_frame = bin_data::chain(
                prealloc(6),
                bits::preamble,
                bits::start_of_packet_code,
                bits::ack_packet_code,
                bits::postamble
        );
        return ack_frame;
    }
    bin_data const &nfc::get_nack_frame() {
        static const bin_data nack_frame = bin_data::chain(
                prealloc(6),
                bits::preamble,
                bits::start_of_packet_code,
                bits::nack_packet_code,
                bits::postamble
        );
        return nack_frame;
    }


    nfc::r<> nfc::raw_send_ack(bool ack, ms timeout) {
        if (chn().send(ack ? get_ack_frame() : get_nack_frame(), timeout)) {
            return result_success;
        }
        return error::comm_timeout;
    }

    nfc::r<> nfc::raw_send_command(command_code cmd, bin_data const &payload, ms timeout) {
        if (chn().send(get_command_info_frame(cmd, payload), timeout)) {
            return result_success;
        }
        return error::comm_timeout;
    }

    bool nfc::await_frame(ms timeout) {
        return chn().await_sequence(bits::start_of_packet_code, timeout);
    }

    nfc::r<nfc::frame_header> nfc::read_header(ms timeout) {
        reduce_timeout rt{timeout};
        std::array<std::uint8_t, 2> code_or_length{};
        if (not chn().receive(code_or_length, rt.remaining())) {
            return error::comm_timeout;
        }
        if (code_or_length == bits::ack_packet_code) {
            return frame_header{frame_type::ack, 0};
        }
        if (code_or_length == bits::nack_packet_code) {
            return frame_header{frame_type::nack, 0};
        }
        std::pair<std::uint16_t, bool> length_checksum_pass;
        if (code_or_length == bits::fixed_extended_packet_length) {
            std::array<std::uint8_t, 3> ext_length{};
            if (not chn().receive(ext_length, rt.remaining())) {
                return error::comm_timeout;
            }
            length_checksum_pass = bits::check_length_checksum(ext_length);
        } else {
            length_checksum_pass = bits::check_length_checksum(code_or_length);
        }
        if (not length_checksum_pass.second) {
            LOGE("Length checksum failed.");
            return error::comm_checksum_fail;
        }
        return frame_header{frame_type::info, length_checksum_pass.first};
    }

    nfc::r<nfc::frame_body> nfc::read_response_body(frame_header const &hdr, ms timeout) {
        if (hdr.type != frame_type::info) {
            LOGE("Ack and nack frames do not have body.");
            return error::comm_malformed;
        }
        const auto res = chn().receive(hdr.length + 1, timeout);  // Data includes checksum
        if (not res.second) {
            return error::comm_timeout;
        }
        bin_data const &data = res.first;
        if (data.size() != hdr.length + 1) {
            LOGE("Cannot parse frame body if expected frame length differs from actual data.");
            return error::comm_malformed;
        }
        if (not bits::checksum(std::begin(data), std::end(data))) {
            LOGE("Frame body checksum failed.");
            return error::comm_checksum_fail;
        }
        // This could be a special error frame
        if (hdr.length == 1 and data[0] == bits::specific_app_level_err_code) {
            LOGW("Received error from controller.");
            return error::failure;
        }
        // All info known frames must have the transport and the command
        if (hdr.length < 2) {
            LOGE("Cannot parse frame body if frame length %ul is less than 2.", hdr.length);
            return error::comm_malformed;
        }
        // Can output
        return frame_body{
            static_cast<bits::transport>(data[0]),
            bits::pn532_to_host_command(data[1]),
            // Copy the body
            bin_data{std::begin(data) + 2, std::end(data) - 1}
        };
    }


    nfc::r<bool> nfc::raw_await_ack(ms timeout) {
        reduce_timeout rt{timeout};
        if (not await_frame(rt.remaining())) {
            return error::comm_timeout;
        }
        const auto res_hdr = read_header(rt.remaining());
        if (not res_hdr) {
            return res_hdr.error();
        }
        if (res_hdr->type != frame_type::info) {
            // Either ack or nack
            return res_hdr->type == frame_type::ack;
        }
        // Make sure to consume the command_code
        LOGE("Expected ack/nack, got a standard info response instead; will consume the data now.");
        const auto res_body = read_response_body(*res_hdr, rt.remaining());
        if (res_body) {
            LOGE("%s: dropped response.", to_string(res_body->command));
            ESP_LOG_BUFFER_HEX_LEVEL(PN532_TAG, res_body->info.data(), res_body->info.size(), ESP_LOG_ERROR);
        } else if (res_body.error() == error::failure) {
            LOGE("Received an error instead of an ack");
            return error::comm_error;
        }
        return error::comm_malformed;
    }

    nfc::r<bin_data> nfc::raw_await_response(command_code cmd, ms timeout) {
        /**
         * @note The handling of a channel error in @ref command_response relies on this function producing only these
         * three errors: ''comm_malformed'', ''comm_timeout'', ''comm_checksum_fail''. If this changes, update the code
         * in @ref command_response.
         */
        reduce_timeout rt{timeout};
        if (not await_frame(rt.remaining())) {
            return error::comm_timeout;
        }
        const auto res_hdr = read_header(rt.remaining());
        if (not res_hdr) {
            return res_hdr.error();
        }
        if (res_hdr->type != frame_type::info) {
            LOGE("Expected info command, got ack/nack.");
            return error::comm_malformed;
        }
        auto res_body = read_response_body(*res_hdr, rt.remaining());
        if (not res_body) {
            return res_body.error();
        }
        if (res_body->command != cmd) {
            LOGW("%s: got a reply to command %s instead.",
                 to_string(res_body->command), to_string(cmd));
            return error::comm_malformed;
        }
        if (res_body->transport != bits::transport::pn532_to_host) {
            LOGE("Received a message from the host instead of pn532.");
            return error::comm_malformed;
        }
        return std::move(res_body->info);
    }

    nfc::r<> nfc::command(command_code cmd, bin_data const &payload, ms timeout) {
        reduce_timeout rt{timeout};
        const auto res_cmd = raw_send_command(cmd, payload, rt.remaining());
        if (not res_cmd) {
            LOGW("%s: unable to send command: %s.", to_string(cmd), to_string(res_cmd.error()));
            return res_cmd.error();
        }
        LOGD("%s: command sent.", to_string(cmd));
        const auto res_ack = raw_await_ack(rt.remaining());
        if (res_ack) {
            if (*res_ack) {
                LOGD("%s: acknowledged.", to_string(cmd));
                return result_success;
            }
            LOGD("%s: NOT acknowledged.", to_string(cmd));
            return error::nack;
        }
        LOGW("%s: ACK/NACK not received: %s.", to_string(cmd), to_string(res_ack.error()));
        return res_ack.error();
    }

    nfc::r<bin_data> nfc::command_response(command_code cmd, bin_data const &payload, ms timeout)
    {
        reduce_timeout rt{timeout};
        const auto res_cmd = command(cmd, payload, rt.remaining());
        if (not res_cmd) {
            return res_cmd.error();
        }
        nfc::r<bin_data> res_response = error::comm_malformed;
        do {
            // As long as we have channel errors and still time left, request the response
            res_response = raw_await_response(cmd, rt.remaining());
            if (not res_response) {
                // Send a nack only if the error is malformed communication
                if (res_response.error() == error::comm_malformed or
                    res_response.error() == error::comm_checksum_fail)
                {
                    LOGW("%s: requesting response again (%s).", to_string(cmd), to_string(res_response.error()));
                    // Retry command response
                    raw_send_ack(false, rt.remaining());
                } else if (res_response.error() != error::comm_timeout) {
                    // Assert that this is the only other return code possible, aka timeout, but then break because we
                    // do not know what we should be doing
                    LOGE("Implementation error unexpected error code from pn532::nfc::raw_await_response: %s",
                         to_string(res_response.error()));
                    break;
                }
            }
        } while(not res_response and res_response.error() != error::comm_timeout);
        if (not res_response) {
            LOGW("%s: canceling command after %lld ms.", to_string(cmd), rt.elapsed().count());
            raw_send_ack(true, one_sec); // Abort command, allow large timeout time for this
            if (res_response.error() == error::comm_timeout) {
                return error::canceled;
            }
            return res_response.error();
        } else {
            LOGD("%s: success, command took %lld ms.", to_string(cmd), rt.elapsed().count());
            raw_send_ack(true, one_sec); // Confirm response, allow large timeout time for this
            return std::move(*res_response);
        }
    }

    /* -----------------------------------------------------------------------------------------------------------------
     * COMMAND IMPLEMENTATION ------------------------------------------------------------------------------------------
     */

    nfc::r<bool> nfc::diagnose_comm_line(ms timeout) {
        LOGI("%s: running %s...", to_string(command_code::diagnose), to_string(bits::test::comm_line));
        // Generate 256 bytes of random data to test
        bin_data payload;
        payload.resize(0xff);
        std::iota(std::begin(payload), std::end(payload), 0x00);
        // Set the first byte to be the test number
        payload[0] = static_cast<std::uint8_t>(bits::test::comm_line);
        const auto res_cmd = command_response(command_code::diagnose, payload, timeout);
        if (not res_cmd) {
            return res_cmd.error();
        }
        // Test that the reurned data coincides
        if (payload.size() == res_cmd->size() and
            std::equal(std::begin(payload), std::end(payload), std::begin(*res_cmd)))
        {
            LOGI("%s: %s test succeeded.", to_string(command_code::diagnose), to_string(bits::test::comm_line));
            return true;
        } else {
            LOGW("%s: %s test failed.", to_string(command_code::diagnose), to_string(bits::test::comm_line));
            return false;
        }
    }

    namespace {
        template <class ...Args>
        nfc::r<bool> nfc_diagnose_simple(nfc &controller, bits::test test, std::uint8_t expected, ms timeout,
                                         std::size_t expected_body_size = 0, Args &&...append_to_body)
       {
            LOGI("%s: running %s...", to_string(command_code::diagnose), to_string(test));
            const bin_data payload = bin_data::chain(prealloc(expected_body_size + 1), test,
                                                     std::forward<Args>(append_to_body)...);
            const auto res_cmd = controller.command_response(command_code::diagnose, payload, timeout);
            if (not res_cmd) {
                return res_cmd.error();
            }
            // Test that the reurned data coincides
            if (res_cmd->size() != 1) {
                LOGW("%s: %s test received %ul bytes instead of 1.",
                     to_string(command_code::diagnose), to_string(test), res_cmd->size());
                return nfc::error::comm_malformed;
            }
            if (res_cmd->at(0) == expected) {
                LOGI("%s: %s test succeeded.", to_string(command_code::diagnose), to_string(test));
                return true;
            } else {
                LOGW("%s: %s test failed.", to_string(command_code::diagnose), to_string(test));
                return false;
            }
        }
    }

    nfc::r<unsigned, unsigned> nfc::diagnose_poll_target(bool slow, bool fast, ms timeout) {
        auto get_fails = [&](bool do_test, speed speed) -> nfc::r<unsigned> {
            if (not do_test) {
                return std::numeric_limits<unsigned>::max();
            }
            const auto res_cmd = command_response(
                    command_code::diagnose,
                    bin_data::chain(prealloc(2), bits::test::poll_target, speed),
                    timeout);
            if (res_cmd) {
                if (res_cmd->size() == 1) {
                    return res_cmd->at(0);
                } else {
                    LOGW("%s: %s test failed at %s.", to_string(command_code::diagnose),
                         to_string(bits::test::poll_target), to_string(speed));
                }
            }
            return res_cmd.error();
        };

        LOGI("%s: running %s...", to_string(command_code::diagnose), to_string(bits::test::poll_target));
        const auto slow_fails = get_fails(slow, speed::kbps212);
        if (slow_fails) {
            const auto fast_fails = get_fails(fast, speed::kbps424);
            if (fast_fails) {
                LOGI("%s: %s test succeeded.", to_string(command_code::diagnose), to_string(bits::test::poll_target));
                return {*slow_fails, *fast_fails};
            }
            return fast_fails.error();
        }
        return slow_fails.error();
    }

    nfc::r<> nfc::diagnose_echo_back(ms reply_delay, std::uint8_t tx_mode, std::uint8_t rx_mode, ms timeout) {
        LOGI("%s: running %s...", to_string(command_code::diagnose), to_string(bits::test::echo_back));
        const bin_data payload = bin_data::chain(
                prealloc(4),
                bits::test::echo_back,
                std::uint8_t(reply_delay.count() * bits::echo_back_reply_delay_steps_per_ms),
                tx_mode,
                rx_mode
        );
        return command(command_code::diagnose, payload, timeout);
    }

    nfc::r<bool> nfc::diagnose_rom(ms timeout) {
        return nfc_diagnose_simple(*this, bits::test::rom, 0x00, timeout);
    }

    nfc::r<bool> nfc::diagnose_ram(ms timeout) {
        return nfc_diagnose_simple(*this, bits::test::ram, 0x00, timeout);
    }

    nfc::r<bool> nfc::diagnose_attention_req_or_card_presence(ms timeout) {
        return nfc_diagnose_simple(*this, bits::test::attention_req_or_card_presence, 0x00, timeout);
    }

    nfc::r<bool> nfc::diagnose_self_antenna(low_current_thr low_threshold, high_current_thr high_threshold, ms timeout) {
        const reg_antenna_detector r{
                .detected_low_pwr = false,
                .detected_high_pwr = false,
                .low_current_threshold = low_threshold,
                .high_current_threshold = high_threshold,
                .enable_detection = true
        };
        return nfc_diagnose_simple(*this, bits::test::self_antenna, 0x00, timeout, 1, r);
    }

    nfc::r<firmware_version> nfc::get_firmware_version(ms timeout) {
        return command_parse_response<firmware_version>(command_code::get_firmware_version, bin_data{}, timeout);
    }

    nfc::r<general_status> nfc::get_general_status(ms timeout) {
        return command_parse_response<general_status>(command_code::get_general_status, bin_data{}, timeout);
    }


    nfc::r<std::vector<uint8_t>> nfc::read_registers(std::vector<reg_addr> const &addresses, ms timeout) {
        static constexpr std::size_t max_addr_count = bits::max_firmware_data_length / 2;
        if (addresses.size() > max_addr_count) {
            LOGE("%s: requested %ul addresses, but can read at most %ul in a single batch.",
                 to_string(command_code::read_register), addresses.size(), max_addr_count);
        }
        const std::size_t effective_length = std::min(addresses.size(), max_addr_count);
        bin_data payload{};
        payload.reserve(effective_length * 2);
        for (std::size_t i = 0; i < effective_length; ++i) {
            payload << addresses[i];
        }
        auto res_cmd = command_response(command_code::read_register, payload, timeout);
        if (not res_cmd) {
            return res_cmd.error();
        }
        if (res_cmd->size() != effective_length) {
            LOGE("%s: requested %ul registers, got %ul instead.", to_string(command_code::read_register),
                 addresses.size(), res_cmd->size());
        }
        return std::move(*res_cmd);
    }

    nfc::r<> nfc::write_registers(std::vector<std::pair<reg_addr, std::uint8_t>> const &addr_value_pairs, ms timeout) {
        static constexpr std::size_t max_avp_count = bits::max_firmware_data_length / 3;
        if (addr_value_pairs.size() > max_avp_count) {
            LOGE("%s: requested %ul addresses, but can read at most %ul in a single batch.",
                 to_string(command_code::write_register), addr_value_pairs.size(), max_avp_count);
        }
        const std::size_t effective_length = std::min(addr_value_pairs.size(), max_avp_count);
        bin_data payload{};
        payload.reserve(effective_length * 3);
        for (std::size_t i = 0; i < effective_length; ++i) {
            payload << addr_value_pairs[i].first << addr_value_pairs[i].second;
        }
        return command_response(command_code::write_register, payload, timeout);
    }

    nfc::r<gpio_status> nfc::read_gpio(ms timeout) {
        return command_parse_response<gpio_status>(command_code::read_gpio, bin_data{}, timeout);
    }

    nfc::r<> nfc::write_gpio(gpio_status const &status, bool write_p3, bool write_p7, ms timeout) {
        if (not write_p3 and not write_p7) {
            LOGW("Attempt to write nothing on the GPIO, did you miss to pass some parameter?");
            return result_success;
        }
        bin_data payload{};
        payload.reserve(2);
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
        return command_response(command_code::write_gpio, payload, timeout);
    }

    nfc::r<> nfc::set_gpio_pin(gpio_loc loc, std::uint8_t pin_idx, bool value, ms timeout) {
        reduce_timeout rt{timeout};
        auto res_read = read_gpio(rt.remaining());
        if (not res_read) {
            return res_read.error();
        }
        (*res_read)[{loc, pin_idx}] = value;
        const bool write_p3 = (loc == gpio_loc::p3);
        const bool write_p7 = (loc == gpio_loc::p7);
        return write_gpio(*res_read, write_p3, write_p7, rt.remaining());
    }

    nfc::r<> nfc::set_serial_baud_rate(baud_rate br, ms timeout) {
        return command_response(command_code::set_serial_baudrate, bin_data::chain(br), timeout);
    }

    nfc::r<> nfc::sam_configuration(sam_mode mode, ms sam_timeout, bool controller_drives_irq, ms timeout) {
        const std::uint8_t sam_timeout_byte = std::min(0xffll, sam_timeout.count() / bits::sam_timeout_unit_ms);
        const bin_data payload = bin_data::chain(
                prealloc(3),
                mode,
                sam_timeout_byte,
                controller_drives_irq);
        return command_response(command_code::sam_configuration, payload, timeout);
    }

    nfc::r<> nfc::rf_configuration_field(bool auto_rfca, bool rf_on, ms timeout) {
        const std::uint8_t config_data =
                (auto_rfca ? bits::rf_configuration_field_auto_rfca_mask  : 0x00) |
                (rf_on     ? bits::rf_configuration_field_auto_rf_on_mask : 0x00);
        const bin_data payload = bin_data::chain(
                prealloc(2),
                bits::rf_config_item::rf_field,
                config_data);
        return command_response(command_code::rf_configuration, payload, timeout);
    }
    nfc::r<> nfc::rf_configuration_timings(std::uint8_t rfu, rf_timeout atr_res_timeout, rf_timeout retry_timeout,
                                           ms timeout)
    {
        const bin_data payload = bin_data::chain(
                prealloc(4),
                bits::rf_config_item::timings,
                rfu,
                atr_res_timeout,
                retry_timeout);
        return command_response(command_code::rf_configuration, payload, timeout);
    }

    nfc::r<> nfc::rf_configuration_retries(std::uint8_t comm_retries, ms timeout) {
        const bin_data payload = bin_data::chain(
                prealloc(2),
                bits::rf_config_item::max_rty_com,
                comm_retries);
        return command_response(command_code::rf_configuration, payload, timeout);
    }

    nfc::r<> nfc::rf_configuration_retries(std::uint8_t atr_retries, std::uint8_t psl_retries,
                                           std::uint8_t passive_activation, ms timeout)
    {
        const bin_data payload = bin_data::chain(
                prealloc(4),
                bits::rf_config_item::max_retries,
                atr_retries,
                psl_retries,
                passive_activation);
        return command_response(command_code::rf_configuration, payload, timeout);
    }

    nfc::r<> nfc::rf_configuration_analog_106kbps_typea(ciu_reg_106kbps_typea const &config, ms timeout) {
        const bin_data payload = bin_data::chain(
                prealloc(1 + sizeof(ciu_reg_106kbps_typea)),
                bits::rf_config_item::analog_106kbps_typea,
                config);
        return command_response(command_code::rf_configuration, payload, timeout);
    }

    nfc::r<> nfc::rf_configuration_analog_212_424kbps(ciu_reg_212_424kbps const &config, ms timeout) {
        const bin_data payload = bin_data::chain(
                prealloc(1 + sizeof(ciu_reg_212_424kbps)),
                bits::rf_config_item::analog_212_424kbps,
                config);
        return command_response(command_code::rf_configuration, payload, timeout);
    }

    nfc::r<> nfc::rf_configuration_analog_typeb(ciu_reg_typeb const &config, ms timeout) {
        const bin_data payload = bin_data::chain(
                prealloc(1 + sizeof(ciu_reg_typeb)),
                bits::rf_config_item::analog_typeb,
                config);
        return command_response(command_code::rf_configuration, payload, timeout);
    }

    nfc::r<> nfc::rf_configuration_analog_iso_iec_14443_4(ciu_reg_iso_iec_14443_4 const &config, ms timeout) {
        const bin_data payload = bin_data::chain(
                prealloc(1 + sizeof(ciu_reg_iso_iec_14443_4)),
                bits::rf_config_item::analog_iso_iec_14443_4,
                config);
        return command_response(command_code::rf_configuration, payload, timeout);
    }

    std::uint8_t nfc::get_target(command_code cmd, std::uint8_t target_logical_index, bool expect_more_data) {
        if (target_logical_index > bits::max_num_targets) {
            LOGE("%s: out of range (unsupported) logical target index %u (> %u).",
                 to_string(cmd), target_logical_index, bits::max_num_targets);
        }
        target_logical_index = std::min(target_logical_index, bits::max_num_targets);
        return target_logical_index | (expect_more_data ? bits::status_more_info_mask : 0x00);
    }

    nfc::r<status, bin_data> nfc::initiator_data_exchange_internal(bin_data const &payload, ms timeout) {
        return command_parse_response<std::pair<status, bin_data>>(command_code::in_data_exchange, payload, timeout);
    }

    nfc::r<status> nfc::initiator_select(std::uint8_t target_logical_index, ms timeout) {
        const std::uint8_t target_byte = get_target(command_code ::in_select, target_logical_index, false);
        return command_parse_response<status>(command_code::in_select, bin_data{target_byte}, timeout);
    }

    namespace {
        void sanitize_max_targets(std::uint8_t &max_targets, const char *fname) {
            if (max_targets < 1 or max_targets > bits::max_num_targets) {
                LOGW("%s: incorrect max targets %u for %s, clamping.",
                     to_string(command_code::in_list_passive_target), max_targets, fname);
                max_targets = std::min(std::max(max_targets, std::uint8_t(1)), bits::max_num_targets);
            }
        }
    }

    nfc::r<std::vector<target_kbps106_typea>> nfc::initiator_list_passive_kbps106_typea(
            std::uint8_t max_targets, ms timeout)
    {
        sanitize_max_targets(max_targets, "initiator_list_passive_kbps106_typea");
        return initiator_list_passive<baudrate_modulation::kbps106_iso_iec_14443_typea>(
                max_targets, bin_data{}, timeout);
    }

    nfc::r<std::vector<target_kbps106_typea>> nfc::initiator_list_passive_kbps106_typea(
            uid_cascade_l1 uid, std::uint8_t max_targets, ms timeout)
    {
        sanitize_max_targets(max_targets, "initiator_list_passive_kbps106_typea");
        return initiator_list_passive<baudrate_modulation::kbps106_iso_iec_14443_typea>(
                max_targets, bin_data::chain(uid), timeout);
    }

    nfc::r<std::vector<target_kbps106_typea>> nfc::initiator_list_passive_kbps106_typea(
            uid_cascade_l2 uid, std::uint8_t max_targets, ms timeout)
    {
        sanitize_max_targets(max_targets, "initiator_list_passive_kbps106_typea");
        return initiator_list_passive<baudrate_modulation::kbps106_iso_iec_14443_typea>(
                max_targets, bin_data::chain(uid), timeout);
    }

    nfc::r<std::vector<target_kbps106_typea>> nfc::initiator_list_passive_kbps106_typea(
            uid_cascade_l3 uid, std::uint8_t max_targets, ms timeout)
    {
        sanitize_max_targets(max_targets, "initiator_list_passive_kbps106_typea");
        return initiator_list_passive<baudrate_modulation::kbps106_iso_iec_14443_typea>(
                max_targets, bin_data::chain(uid), timeout);
    }

    nfc::r<std::vector<target_kbps106_typeb>> nfc::initiator_list_passive_kbps106_typeb(
            std::uint8_t application_family_id, polling_method method, std::uint8_t max_targets, ms timeout)
    {
        sanitize_max_targets(max_targets, "initiator_list_passive_kbps106_typeb");
        return initiator_list_passive<baudrate_modulation::kbps106_iso_iec_14443_3_typeb>(
                max_targets, bin_data::chain(prealloc(2), application_family_id, method), timeout);
    }

    nfc::r<std::vector<target_kbps212_felica>> nfc::initiator_list_passive_kbps212_felica(
            std::array<std::uint8_t, 5> const &payload, std::uint8_t max_targets, ms timeout)
    {
        sanitize_max_targets(max_targets, "initiator_list_passive_kbps212_felica");
        return initiator_list_passive<baudrate_modulation::kbps212_felica_polling>(
                max_targets, bin_data::chain(payload), timeout);

    }

    nfc::r<std::vector<target_kbps424_felica>> nfc::initiator_list_passive_kbps424_felica(
            std::array<std::uint8_t, 5> const &payload, std::uint8_t max_targets, ms timeout)
    {
        sanitize_max_targets(max_targets, "initiator_list_passive_kbps424_felica");
        return initiator_list_passive<baudrate_modulation::kbps424_felica_polling>(
                max_targets, bin_data::chain(payload), timeout);
    }

    nfc::r<std::vector<target_kbps106_jewel_tag>> nfc::initiator_list_passive_kbps106_jewel_tag(ms timeout)
    {
        return initiator_list_passive<baudrate_modulation::kbps106_innovision_jewel_tag>(1, bin_data{}, timeout);
    }

    template <baudrate_modulation BrMd>
    nfc::r<std::vector<bits::target<BrMd>>> nfc::initiator_list_passive(
            std::uint8_t max_targets, bin_data const &initiator_data, ms timeout)
    {
        const bin_data payload = bin_data::chain(
                prealloc(2 + initiator_data.size()),
                max_targets,
                BrMd,
                initiator_data
        );
        auto res_cmd = command_parse_response<std::vector<bits::target<BrMd>>>(
                command_code::in_list_passive_target, payload, timeout);
        if (not res_cmd and res_cmd.error() == error::canceled) {
            // Canceled commands means no target was found, return thus an empty array as technically it's correct
            return std::vector<bits::target<BrMd>>{};
        }
        return res_cmd;
    }

    namespace {
        std::uint8_t get_in_atr_next(bool has_nfcid_3t, bool has_general_info) {
            return (has_nfcid_3t ? bits::in_atr_nfcid_3t_present_mask : 0x00)
                | (has_general_info ? bits::in_atr_general_info_present_mask : 0x00);
        }
    }


    nfc::r<status, atr_res_info> nfc::initiator_activate_target(std::uint8_t target_logical_index, ms timeout)
    {
        const auto next_byte = get_in_atr_next(false, false);
        return command_parse_response<std::pair<status, atr_res_info>>(
                command_code::in_atr,
                bin_data::chain(target_logical_index, next_byte),
                timeout
        );
    }
    nfc::r<status, atr_res_info> nfc::initiator_activate_target(std::uint8_t target_logical_index,
                                                      std::array<std::uint8_t, 10> const &nfcid_3t,
                                                      ms timeout)
    {
        const auto next_byte = get_in_atr_next(true, false);
        return command_parse_response<std::pair<status, atr_res_info>>(
                command_code::in_atr,
                bin_data::chain(target_logical_index, next_byte, nfcid_3t),
                timeout
        );
    }
    nfc::r<status, atr_res_info> nfc::initiator_activate_target(std::uint8_t target_logical_index,
                                                      std::vector<std::uint8_t> const &general_info,
                                                      ms timeout)
    {
        const auto next_byte = get_in_atr_next(false, true);
        return command_parse_response<std::pair<status, atr_res_info>>(
                command_code::in_atr,
                bin_data::chain(target_logical_index, next_byte, general_info),
                timeout
        );
    }

    nfc::r<status, atr_res_info> nfc::initiator_activate_target(std::uint8_t target_logical_index,
                                                      std::array<std::uint8_t, 10> const &nfcid_3t,
                                                      std::vector<std::uint8_t> const &general_info,
                                                      ms timeout)
    {
        const auto next_byte = get_in_atr_next(true, true);
        return command_parse_response<std::pair<status, atr_res_info>>(
                command_code::in_atr,
                bin_data::chain(target_logical_index, next_byte, nfcid_3t, general_info),
                timeout
        );
    }

    nfc::r<std::vector<any_target>> nfc::initiator_auto_poll(std::vector<target_type> const &types_to_poll,
                                                   std::uint8_t polls_per_type, poll_period period,
                                                   ms timeout)
    {
        if (types_to_poll.empty()) {
            LOGW("%s: no target types specified.", to_string(command_code::in_autopoll));
            return std::vector<any_target>{};
        }
        if (types_to_poll.size() > bits::autopoll_max_types) {
            LOGW("%s: too many (%ul) types to poll, at most %u will be considered.",
                 to_string(command_code::in_autopoll), types_to_poll.size(), bits::autopoll_max_types);
        }
        const auto num_types = std::min(bits::autopoll_max_types, types_to_poll.size());
        const auto target_view = make_range(std::begin(types_to_poll), std::begin(types_to_poll) + num_types);
        const bin_data payload = bin_data::chain(
                prealloc(2 + num_types),
                polls_per_type,
                period,
                target_view
        );
        auto res_cmd = command_parse_response<std::vector<any_target>>(command_code::in_autopoll, payload, timeout);
        if (not res_cmd and res_cmd.error() == error::canceled) {
            // Canceled commands means no target was found, return thus an empty array as technically it's correct
            return std::vector<any_target>{};
        }
        return res_cmd;
    }

}