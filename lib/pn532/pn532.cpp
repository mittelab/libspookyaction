//
// Created by Pietro Saccardi on 20/12/2020.
//

#include <tuple>
#include "bits_algo.hpp"
#include "pn532.hpp"
#include "log.h"

namespace pn532 {

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
        std::pair<std::uint16_t, bool> length_checksum_pass{0, false};
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
        LOGE("Expected ack/nack, got a standard command_code instead; will consume the command_code now.");
        const auto res_body = read_response_body(*res_hdr, rt.remaining());
        if (res_body) {
            LOGW("Dropped command response %d:", static_cast<int>(res_body->command));
            ESP_LOG_BUFFER_HEX_LEVEL(PN532_TAG, res_body->info.data(), res_body->info.size(), ESP_LOG_WARN);
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
            LOGE("Expected info command_code, got ack/nack.");
            return error::comm_malformed;
        }
        auto res_body = read_response_body(*res_hdr, rt.remaining());
        if (not res_body) {
            return res_body.error();
        }
        if (res_body->command != cmd) {
            LOGW("Got a reply with command_code code %d instead of requested %d.",
                 static_cast<int>(res_body->command), static_cast<int>(cmd));
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
            return res_cmd.error();
        }
        const auto res_ack = raw_await_ack(rt.remaining());
        if (res_ack) {
            if (*res_ack) {
                return result_success;
            }
            return error::nack;
        }
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
            // Send a nack only if the error is malformed communication
            if (res_response.error() == error::comm_malformed or
                res_response.error() == error::comm_checksum_fail)
            {
                // Ignore timeout
                raw_send_ack(false, rt.remaining());
            }
            return res_response.error();
        }
        // Accept and send reply, ignore timeout
        raw_send_ack(true, rt.remaining());
        return std::move(*res_response);
    }

    nfc::r<> nfc::diagnose_comm_line(ms timeout) {
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
            return result_success;
        } else {
            LOGW("Communication test failed, returned sequence does not match sent sequence.");
            return error::failure;
        }
    }

    namespace {
        template <class ...Args>
        nfc::r<> nfc_diagnose_simple(nfc &controller, bits::test test, std::uint8_t expected, ms timeout,
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
            if (res_cmd->size() == 1 and res_cmd->at(0) == expected) {
                return result_success;
            } else {
                LOGW("Diagnostic test %d failed.", static_cast<int>(test));
                return nfc::error::failure;
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
                    LOGW("Poll target test failed at speed %d.", static_cast<int>(speed));
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

    nfc::r<> nfc::diagnose_rom(ms timeout) {
        return nfc_diagnose_simple(*this, bits::test::rom, 0x00, timeout);
    }
    nfc::r<> nfc::diagnose_ram(ms timeout) {
        return nfc_diagnose_simple(*this, bits::test::ram, 0x00, timeout);
    }
    nfc::r<> nfc::diagnose_attention_req_or_card_presence(ms timeout) {
        return nfc_diagnose_simple(*this, bits::test::attention_req_or_card_presence, 0x00, timeout);
    }

    nfc::r<> nfc::diagnose_self_antenna(std::uint8_t threshold, ms timeout) {
        return nfc_diagnose_simple(*this, bits::test::self_antenna, 0x00, timeout, threshold);
    }

    nfc::r<firmware_version> nfc::get_firmware_version(ms timeout) {
        const auto res_cmd = command_response(command_code::get_firmware_version, bin_data{}, timeout);
        if (not res_cmd) {
            return res_cmd.error();
        }
        if (res_cmd->size() != 4) {
            LOGW("Get firmware version: expected 4 bytes of data, not %ull.", res_cmd->size());
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
            LOGW("Get status: expected 12 bytes of data, not %ull.", res_cmd->size());
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
                .nad_present = 0 != (b[0] & bits::error_nad_mask),
                .mi_set = 0 != (b[0] & bits::error_mi_mask),
                .last_error = static_cast<controller_error>(b[0] & bits::error_code_mask),
                .rf_field_present = b[1] != 0x00,
                .targets = {},
                .sam_status = b[11],
        };
        if (b[2] > 2) {
            LOGE("Detected more than two targets handled by PN532, most likely an error.");
        }
        const std::size_t num_targets = std::min(std::size_t(b[2]), 2u);
        s.targets.reserve(num_targets);
        for (std::size_t i = 0; i < num_targets; ++i) {
            s.targets.push_back(parse_target_status(b, 3 + 4 * i));
        }
        return s;
    }


    nfc::r<std::vector<uint8_t>> nfc::read_registers(std::vector<reg_addr> const &addresses, ms timeout) {
        static constexpr std::size_t max_addr_count = bits::max_firmware_data_length / 2;
        if (addresses.size() > max_addr_count) {
            LOGW("Read register: requested %ul addresses, but can read at most %ul in a single batch.",
                 addresses.size(), max_addr_count);
        }
        const std::size_t effective_length = std::min(addresses.size(), max_addr_count);
        bin_data payload{};
        for (std::size_t i = 0; i < effective_length; ++i) {
            payload << addresses[i];
        }
        auto res_cmd = command_response(command_code::read_register, payload, timeout);
        if (not res_cmd) {
            return res_cmd.error();
        }
        if (res_cmd->size() != effective_length) {
            LOGW("Read register: requested %ul registers, got %ul instead.", addresses.size(), res_cmd->size());
        }
        return std::move(*res_cmd);
    }

    nfc::r<> nfc::write_registers(std::vector<std::pair<reg_addr, std::uint8_t>> const &addr_value_pairs, ms timeout) {
        static constexpr std::size_t max_avp_count = bits::max_firmware_data_length / 3;
        if (addr_value_pairs.size() > max_avp_count) {
            LOGW("Write register: requested %ul addresses, but can read at most %ul in a single batch.",
                 addr_value_pairs.size(), max_avp_count);
        }
        const std::size_t effective_length = std::min(addr_value_pairs.size(), max_avp_count);
        bin_data payload{};
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
            LOGW("Read GPIO: got %ul bytes, expected 3.", res_cmd->size());
            return error::comm_malformed;
        }
        return gpio_status{res_cmd->at(0), res_cmd->at(1), res_cmd->at(2)};
    }

    nfc::r<> nfc::write_gpio(gpio_status const &status, bool write_p3, bool write_p7, ms timeout) {
        bin_data payload;
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

    bin_data nfc::get_command_info_frame(command_code cmd, bin_data const &payload) {
        const auto cmd_byte = bits::host_to_pn532_command(cmd);
        const auto transport_byte = static_cast<std::uint8_t>(bits::transport::host_to_pn532);
        // "2" because must count transport info and command_code
        const bool use_extended_format = (payload.size() > 0xff - 2);
        const std::uint8_t length = std::min(payload.size(), bits::max_firmware_data_length);
        // Make sure data gets truncated and nothing too weird happens
        const auto truncated_data = payload.view(0, length);
        // Precompute transport info + cmd byte + info compute_checksum
        const auto checksum = bits::compute_checksum(
                transport_byte + cmd_byte,
                std::begin(truncated_data),
                std::end(truncated_data)
        );
        bin_data frame = bin_data::chain(bits::preamble, bits::start_of_packet_code);
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
}