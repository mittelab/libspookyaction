//
// Created by Pietro Saccardi on 20/12/2020.
//
#include "bits_algo.hpp"
#include "pn532.hpp"
#include "log.h"

namespace pn532 {

    const char *to_string(nfc::error e) {
        switch (e) {
            case nfc::error::comm_checksum_fail: return "Checksum (length or data) failed";
            case nfc::error::comm_malformed:     return "Malformed or unexpected response";
            case nfc::error::comm_error:         return "Controller returned error instead of ACK";
            case nfc::error::failure:            return "Controller acknowledged but returned error";
            case nfc::error::timeout:            return "Communication reached timeout";
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


    bin_data nfc::get_command_info_frame(command_code cmd, bin_data const &payload) {
        const auto cmd_byte = bits::host_to_pn532_command(cmd);
        const auto transport_byte = static_cast<std::uint8_t>(bits::transport::host_to_pn532);
        // "2" because must count transport info and command_code
        const bool use_extended_format = (payload.size() > 0xff - 2);
        if (payload.size() > bits::max_firmware_data_length) {
            LOGE("Payload too long for command %s for an info frame, truncating %ul bytes to %ul:",
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
        frame.reserve(length + 12);
        frame << bits::preamble << bits::start_of_packet_code;
        if (use_extended_format) {
            frame << bits::fixed_extended_packet_length << bits::length_and_checksum_long(length);
        } else {
            frame << bits::length_and_checksum_short(length);
        }
        frame << transport_byte << cmd_byte << truncated_data << checksum << bits::postamble;
        return frame;
    }

    bin_data const &nfc::get_ack_frame() {
        static const bin_data ack_frame = bin_data::chain(
                bits::preamble,
                bits::start_of_packet_code,
                bits::ack_packet_code,
                bits::postamble
        );
        return ack_frame;
    }
    bin_data const &nfc::get_nack_frame() {
        static const bin_data nack_frame = bin_data::chain(
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
        return error::timeout;
    }

    nfc::r<> nfc::raw_send_command(command_code cmd, bin_data const &payload, ms timeout) {
        if (chn().send(get_command_info_frame(cmd, payload), timeout)) {
            return result_success;
        }
        return error::timeout;
    }

    bool nfc::await_frame(ms timeout) {
        return chn().await_sequence(bits::start_of_packet_code, timeout);
    }

    nfc::r<nfc::frame_header> nfc::read_header(ms timeout) {
        reduce_timeout rt{timeout};
        std::array<std::uint8_t, 2> code_or_length{};
        if (not chn().receive(code_or_length, rt.remaining())) {
            return error::timeout;
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
                return error::timeout;
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
            return error::timeout;
        }
        if (res.first.size() != hdr.length + 1) {
            LOGE("Cannot parse frame body if expected frame length differs from actual data.");
            return error::comm_malformed;
        }
        if (not bits::checksum(std::begin(res.first), std::end(res.first))) {
            LOGE("Frame body checksum failed.");
            return error::comm_checksum_fail;
        }
        // This could be a special error frame
        if (hdr.length == 1 and res.first[0] == bits::specific_app_level_err_code) {
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
            static_cast<bits::transport>(res.first[0]),
            bits::pn532_to_host_command(res.first[1]),
            // Copy the body
            bin_data{std::begin(res.first) + 2, std::end(res.first) - 1}
        };
    }


    nfc::r<bool> nfc::raw_await_ack(ms timeout) {
        reduce_timeout rt{timeout};
        if (not await_frame(rt.remaining())) {
            return error::timeout;
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
            LOGE("Dropped response to %s:", to_string(res_body->command));
            ESP_LOG_BUFFER_HEX_LEVEL(PN532_TAG, res_body->info.data(), res_body->info.size(), ESP_LOG_ERROR);
        } else if (res_body.error() == error::failure) {
            LOGE("Received an error instead of an ack");
            return error::comm_error;
        }
        return error::comm_malformed;
    }

    nfc::r<bin_data> nfc::raw_await_response(command_code cmd, ms timeout) {
        reduce_timeout rt{timeout};
        if (not await_frame(rt.remaining())) {
            return error::timeout;
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
            LOGW("Got a reply to command %s instead of issued command %s.",
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
            LOGW("Unable to send command %s: %s.", to_string(cmd), to_string(res_cmd.error()));
            return res_cmd.error();
        }
        LOGD("Sent command %s.", to_string(cmd));
        const auto res_ack = raw_await_ack(rt.remaining());
        if (res_ack) {
            if (*res_ack) {
                LOGD("Command %s was acknowledged by the controller.", to_string(cmd));
                return result_success;
            }
            LOGD("Command %s was NOT acknowledged by the controller.", to_string(cmd));
            return error::nack;
        }
        LOGW("Controller did not acknowledge command %s: %s.", to_string(cmd), to_string(res_ack.error()));
        return res_ack.error();
    }

    nfc::r<bin_data> nfc::command_response(command_code cmd, bin_data const &payload, ms timeout)
    {
        reduce_timeout rt{timeout};
        const auto res_cmd = command(cmd, payload, rt.remaining());
        if (not res_cmd) {
            return res_cmd.error();
        }
        auto res_response = raw_await_response(cmd, rt.remaining());
        if (not res_response) {
            LOGW("Could not read response to command %s: %s.", to_string(cmd), to_string(res_response.error()));
            // Send a nack only if the error is malformed communication
            if (res_response.error() == error::comm_malformed or
                res_response.error() == error::comm_checksum_fail)
            {
                // Ignore timeout
                raw_send_ack(false, rt.remaining());
            }
            return res_response.error();
        }
        LOGD("Successfully retrieved response to command %s.", to_string(cmd));
        // Accept and send reply, ignore timeout
        raw_send_ack(true, rt.remaining());
        return std::move(*res_response);
    }

    nfc::r<bool> nfc::diagnose_comm_line(ms timeout) {
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
            return true;
        } else {
            LOGW("%s: %s test failed, returned sequence does not match sent sequence.",
                 to_string(command_code::diagnose), to_string(bits::test::comm_line));
            return false;
        }
    }

    namespace {
        template <class ...Args>
        nfc::r<bool> nfc_diagnose_simple(nfc &controller, bits::test test, std::uint8_t expected, ms timeout,
                                         Args &&...append_to_body)
       {
            const bin_data payload = bin_data::chain(
                    static_cast<std::uint8_t>(test),
                    std::forward<Args>(append_to_body)...
            );
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
                    bin_data::chain(
                            static_cast<std::uint8_t>(bits::test::poll_target),
                            static_cast<std::uint8_t>(speed)),
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

        const auto slow_fails = get_fails(slow, speed::kbps212);
        if (slow_fails) {
            const auto fast_fails = get_fails(fast, speed::kbps424);
            if (fast_fails) {
                return {*slow_fails, *fast_fails};
            }
            return fast_fails.error();
        }
        return slow_fails.error();
    }

    nfc::r<> nfc::diagnose_echo_back(ms reply_delay, std::uint8_t tx_mode, std::uint8_t rx_mode, ms timeout) {
        const bin_data payload = bin_data::chain(
                static_cast<std::uint8_t>(bits::test::echo_back),
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

    nfc::r<bool> nfc::diagnose_self_antenna(std::uint8_t threshold, ms timeout) {
        return nfc_diagnose_simple(*this, bits::test::self_antenna, 0x00, timeout, threshold);
    }

    nfc::r<firmware_version> nfc::get_firmware_version(ms timeout) {
        const auto res_cmd = command_response(command_code::get_firmware_version, bin_data{}, timeout);
        if (not res_cmd) {
            return res_cmd.error();
        }
        if (res_cmd->size() != 4) {
            LOGE("%s: expected 4 bytes of data, not %ul.",
                 to_string(command_code::get_firmware_version), res_cmd->size());
            return error::comm_malformed;
        }
        // Unpack
        return firmware_version{
                .ic = res_cmd->at(0),
                .version = res_cmd->at(1),
                .revision = res_cmd->at(2),
                .iso_18092 = 0 != (res_cmd->at(3) & bits::firmware_iso_18092_mask),
                .iso_iec_14443_typea = 0 != (res_cmd->at(3) & bits::firmware_iso_iec_14443_typea_mask),
                .iso_iec_14443_typeb = 0 != (res_cmd->at(3) & bits::firmware_iso_iec_14443_typeb_mask)
        };
    }

    nfc::r<general_status> nfc::get_general_status(ms timeout) {
        const auto res_cmd = command_response(command_code::get_general_status, bin_data{}, timeout);
        if (not res_cmd) {
            return res_cmd.error();
        }
        if (res_cmd->size() != 12) {
            LOGE("%s: expected 12 bytes of data, not %ul.",
                 to_string(command_code::get_general_status), res_cmd->size());
            return error::comm_malformed;
        }
        // Unpack
        auto parse_target_status = [](bin_data const &d, std::size_t ofs) -> target_status {
            return target_status{
                    .logical_index = d[ofs],
                    .bitrate_rx = static_cast<speed>(d[ofs + 1]),
                    .bitrate_tx = static_cast<speed>(d[ofs + 2]),
                    .modulation_type = static_cast<modulation>(d[ofs + 3])
            };
        };

        auto const &b = *res_cmd;
        general_status s{
                .last_error = static_cast<controller_error>(b[0] & bits::status_error_mask),
                .rf_field_present = b[1] != 0x00,
                .targets = {},
                .sam_status = b[11],
        };
        if (b[2] > bits::max_num_targets) {
            LOGE("%s: detected more than %u targets handled by PN532, most likely an error.",
                 to_string(command_code::get_general_status), bits::max_num_targets);
        }
        const std::size_t num_targets = std::min(std::size_t(b[2]), std::size_t(bits::max_num_targets));
        s.targets.reserve(num_targets);
        for (std::size_t i = 0; i < num_targets; ++i) {
            s.targets.push_back(parse_target_status(b, 3 + 4 * i));
        }
        return s;
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
        const auto res_cmd = command_response(command_code::read_gpio, bin_data{}, timeout);
        if (not res_cmd) {
            return res_cmd.error();
        }
        if (res_cmd->size() != 3) {
            LOGE("%s: got %ul bytes, expected 3.", to_string(command_code::read_gpio), res_cmd->size());
            return error::comm_malformed;
        }
        return gpio_status{res_cmd->at(0), res_cmd->at(1), res_cmd->at(2)};
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
        return command_response(command_code::set_serial_baudrate, {static_cast<std::uint8_t>(br)}, timeout);
    }

    nfc::r<> nfc::sam_configuration(sam_mode mode, ms sam_timeout, bool controller_drives_irq, ms timeout) {
        const std::uint8_t sam_timeout_byte = std::min(0xffll, sam_timeout.count() / bits::sam_timeout_unit_ms);
        const bin_data payload = bin_data::chain(
                static_cast<std::uint8_t>(mode),
                sam_timeout_byte,
                std::uint8_t(controller_drives_irq ? 0x01 : 0x00)
        );
        return command_response(command_code::sam_configuration, payload, timeout);
    }

    nfc::r<> nfc::rf_configuration_field(bool auto_rfca, bool rf_on, ms timeout) {
        const std::uint8_t config_data =
                (auto_rfca ? bits::rf_configuration_field_auto_rfca_mask  : 0x00) |
                (rf_on     ? bits::rf_configuration_field_auto_rf_on_mask : 0x00);
        bin_data payload{};
        payload.reserve(2);
        payload << static_cast<std::uint8_t>(bits::rf_config_item::rf_field) << config_data;
        return command_response(command_code::rf_configuration, payload, timeout);
    }
    nfc::r<> nfc::rf_configuration_timings(std::uint8_t rfu, rf_timeout atr_res_timeout, rf_timeout retry_timeout,
                                           ms timeout)
    {
        bin_data payload{};
        payload.reserve(4);
        payload << static_cast<std::uint8_t>(bits::rf_config_item::timings) << rfu
            << static_cast<std::uint8_t>(atr_res_timeout) << static_cast<std::uint8_t>(retry_timeout);
        return command_response(command_code::rf_configuration, payload, timeout);
    }

    nfc::r<> nfc::rf_configuration_retries(std::uint8_t comm_retries, ms timeout) {
        bin_data payload{};
        payload.reserve(2);
        payload << static_cast<std::uint8_t>(bits::rf_config_item::max_rty_com) << comm_retries;
        return command_response(command_code::rf_configuration, payload, timeout);
    }

    nfc::r<> nfc::rf_configuration_retries(std::uint8_t atr_retries, std::uint8_t psl_retries,
                                           std::uint8_t passive_activation, ms timeout)
    {
        bin_data payload{};
        payload.reserve(4);
        payload << static_cast<std::uint8_t>(bits::rf_config_item::max_retries) << atr_retries << psl_retries
            << passive_activation;
        return command_response(command_code::rf_configuration, payload, timeout);
    }

    nfc::r<> nfc::rf_configuration_analog_106kbps_typea(ciu_reg_106kbps_typea const &config, ms timeout) {
        bin_data payload{};
        payload.reserve(1 + sizeof(ciu_reg_106kbps_typea));
        payload << static_cast<std::uint8_t>(bits::rf_config_item::analog_106kbps_typea) << config;
        return command_response(command_code::rf_configuration, payload, timeout);
    }

    nfc::r<> nfc::rf_configuration_analog_212_424kbps(ciu_reg_212_424kbps const &config, ms timeout) {
        bin_data payload{};
        payload.reserve(1 + sizeof(ciu_reg_212_424kbps));
        payload << static_cast<std::uint8_t>(bits::rf_config_item::analog_212_424kbps) << config;
        return command_response(command_code::rf_configuration, payload, timeout);
    }

    nfc::r<> nfc::rf_configuration_analog_typeb(ciu_reg_typeb const &config, ms timeout) {
        bin_data payload{};
        payload.reserve(1 + sizeof(ciu_reg_typeb));
        payload << static_cast<std::uint8_t>(bits::rf_config_item::analog_typeb) << config;
        return command_response(command_code::rf_configuration, payload, timeout);
    }

    nfc::r<> nfc::rf_configuration_analog_iso_iec_14443_4(ciu_reg_iso_iec_14443_4 const &config, ms timeout) {
        bin_data payload{};
        payload.reserve(1 + sizeof(ciu_reg_iso_iec_14443_4));
        payload << static_cast<std::uint8_t>(bits::rf_config_item::analog_iso_iec_14443_4) << config;
        return command_response(command_code::rf_configuration, payload, timeout);
    }

    std::uint8_t nfc::get_target(command_code cmd, std::uint8_t target_logical_index, bool expect_more_data) {
        if (target_logical_index >= bits::max_num_targets) {
            LOGE("%s: out of range (unsupported) logical target index %u (>= %u).",
                 to_string(cmd), target_logical_index, bits::max_num_targets);
        }
        target_logical_index = std::min(target_logical_index, std::uint8_t(bits::max_num_targets - 1));
        return target_logical_index | (expect_more_data ? bits::status_more_info_mask : 0x00);
    }

    status nfc::get_status(std::uint8_t data) {
        return {
                .nad_present = 0 != (data & bits::status_nad_mask),
                .expect_more_info = 0 != (data & bits::status_more_info_mask),
                .error = static_cast<controller_error>(data & bits::status_error_mask),
        };
    }

    nfc::r<status, bin_data> nfc::initiator_data_exchange_internal(bin_data const &payload, ms timeout) {
        const auto res_cmd = command_response(command_code::in_data_exchange, payload, timeout);
        if (not res_cmd) {
            return res_cmd.error();
        }
        if (res_cmd.empty()) {
            LOGE("%s: missing status byte.", to_string(command_code::in_data_exchange));
            return error::comm_malformed;
        }
        return {get_status(res_cmd->front()), bin_data{res_cmd->view(1)}};
    }

    nfc::r<status> nfc::initiator_select(std::uint8_t target_logical_index, ms timeout) {
        const std::uint8_t target_byte = get_target(command_code ::in_select, target_logical_index, false);
        const auto res_cmd = command_response(command_code::in_select, bin_data{target_byte}, timeout);
        if (not res_cmd) {
            return res_cmd.error();
        }
        if (res_cmd.empty()) {
            LOGE("%s: missing status byte.", to_string(command_code::in_select));
            return error::comm_malformed;
        }
        return get_status(res_cmd->front());
    }

}