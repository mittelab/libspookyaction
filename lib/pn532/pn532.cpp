//
// Created by Pietro Saccardi on 20/12/2020.
//

#include <tuple>
#include "bits_algo.hpp"
#include "pn532.hpp"
#include "log.h"

namespace pn532 {

    namespace frames {
        enum struct frame_type {
            ack,
            nack,
            other
        };

        struct header {
            frame_type type = frame_type::other;
            std::size_t length = 0;
            bool checksum_pass = false;
        };

        struct information_body {
            bits::transport transport = bits::transport::host_to_pn532;
            command_code command = command_code::diagnose;
            range<bin_data::const_iterator> payload = {};
            bool checksum_pass = false;
        };

        bin_data get_information(command_code cmd, bin_data const &payload);
        bin_data const &get_ack();
        bin_data const &get_nack();

        information_body parse_information_body(header const &hdr, bin_data const &data);
        bool is_error_frame(header const &hdr, bin_data const &data);

    }


    old_result nfc::raw_send_ack(bool ack, ms timeout) {
        return chn().send(ack ? frames::get_ack() : frames::get_nack(), timeout) ? old_result::success : old_result::timeout;
    }

    old_result nfc::raw_send_command(command_code cmd, bin_data const &payload, ms timeout) {
        return chn().send(frames::get_information(cmd, payload), timeout) ? old_result::success : old_result::timeout;
    }

    bool nfc::await_frame(ms timeout) {
        return chn().await_sequence(bits::start_of_packet_code, timeout);
    }

    std::pair<frames::header, bool> nfc::read_header(ms timeout) {
        bool success = true;
        frames::header hdr{};
        reduce_timeout rt{timeout};
        std::array<std::uint8_t, 2> code_or_length{};
        if (chn().receive(code_or_length, rt.remaining())) {
            if (code_or_length == bits::ack_packet_code) {
                hdr.type = frames::frame_type::ack;
                hdr.length = 0;
                hdr.checksum_pass = true;
            } else if (code_or_length == bits::nack_packet_code) {
                hdr.type = frames::frame_type::nack;
                hdr.length = 0;
                hdr.checksum_pass = true;
            } else if (code_or_length == bits::fixed_extended_packet_length) {
                hdr.type = frames::frame_type::other;
                std::array<std::uint8_t, 3> ext_length{};
                if (chn().receive(ext_length, rt.remaining())) {
                    std::tie(hdr.length, hdr.checksum_pass) = bits::check_length_checksum(ext_length);
                } else {
                    success = false;
                }
            } else {
                hdr.type = frames::frame_type::other;
                std::tie(hdr.length, hdr.checksum_pass) = bits::check_length_checksum(code_or_length);
            }
        } else {
            success = false;
        }
        return std::make_pair(hdr, success);
    }

    std::pair<bin_data, bool> nfc::read_body(frames::header const &hdr, ms timeout) {
        if (not hdr.checksum_pass) {
            LOGE("Cannot parse frame body if frame length compute_checksum failed.");
            return {bin_data{}, false};
        } else if (hdr.length == 0) {
            return {bin_data{}, true};
        }
        return chn().receive(hdr.length + 1, timeout);  // Includes checksum
    }


    std::pair<bool, old_result> nfc::raw_await_ack(ms timeout) {
        reduce_timeout rt{timeout};
        if (await_frame(rt.remaining())) {
            const auto header_success = read_header(rt.remaining());
            if (header_success.second) {
                // Make sure to consume the command_code
                if (header_success.first.type == frames::frame_type::other) {
                    LOGE("Expected ack/nack, got a standard command_code instead; will consume the command_code now.");
                    const auto data_success = read_body(header_success.first, rt.remaining());
                    if (data_success.second and frames::is_error_frame(header_success.first, data_success.first)) {
                        LOGE("Received an error instead of an ack");
                        return {false, old_result::comm_error};
                    }
                    return {false, old_result::comm_malformed};
                } else {
                    return {header_success.first.type == frames::frame_type::ack, old_result::success};
                }
            }
        }
        return {false, old_result::timeout};
    }

    std::tuple<command_code, bin_data, old_result> nfc::raw_await_response(ms timeout) {
        reduce_timeout rt{timeout};
        if (await_frame(rt.remaining())) {
            const auto header_success = read_header(rt.remaining());
            if (header_success.second) {
                // Make sure to consume the command_code
                if (header_success.first.type == frames::frame_type::other) {
                    const auto data_success = read_body(header_success.first, rt.remaining());
                    if (data_success.second) {
                        if (frames::is_error_frame(header_success.first, data_success.first)) {
                            LOGE("Received an error instead of info.");
                            return std::make_tuple(command_code::diagnose, bin_data{}, old_result::comm_error);
                        }
                        const frames::information_body body = frames::parse_information_body(header_success.first,
                                                                                             data_success.first);
                        bin_data copy{std::begin(body.payload), std::end(body.payload)};
                        if (not body.checksum_pass) {
                            LOGE("Body did not checksum.");
                            return std::make_tuple(body.command, std::move(copy), old_result::comm_checksum_fail);
                        } else if (body.transport != bits::transport::pn532_to_host) {
                            LOGE("Received a message from the host instead of pn532.");
                            return std::make_tuple(body.command, std::move(copy), old_result::comm_malformed);
                        }
                        return std::make_tuple(body.command, std::move(copy), old_result::success);
                    }
                } else {
                    LOGE("Expected info command_code, got ack/nack.");
                    return std::make_tuple(command_code::diagnose, bin_data{}, old_result::comm_malformed);
                }
            }
        }
        return std::make_tuple(command_code::diagnose, bin_data{}, old_result::timeout);
    }

    old_result nfc::command(command_code cmd, bin_data const &payload, ms timeout) {
        reduce_timeout rt{timeout};
        const auto res_cmd = raw_send_command(cmd, payload, rt.remaining());
        if (res_cmd != old_result::success) {
            return res_cmd;
        }
        const auto res_ack = raw_await_ack(rt.remaining());
        if (res_ack.second == old_result::success) {
            return res_ack.first ? old_result::success : old_result::nack;
        }
        return res_ack.second;
    }

    std::pair<bin_data, old_result> nfc::command_response(command_code cmd, bin_data const &payload, ms timeout)
    {
        reduce_timeout rt{timeout};
        const auto res_cmd = command(cmd, payload, rt.remaining());
        if (res_cmd != old_result::success) {
            return {bin_data{}, res_cmd};
        }
        auto res_response = raw_await_response(rt.remaining());
        if (std::get<2>(res_response) != old_result::success) {
            return {std::get<1>(res_response), std::get<2>(res_response)};
        } else if (std::get<0>(res_response) != cmd) {
            LOGW("Got a reply with command_code code %d instead of requested %d.",
                 static_cast<int>(std::get<0>(res_response)), static_cast<int>(cmd));
        }
        // Accept and send reply, ignore timeout
        raw_send_ack(true, rt.remaining());
        return {std::move(std::get<1>(res_response)), old_result::success};
    }

    old_result nfc::diagnose_comm_line(ms timeout) {
        // Generate 256 bytes of random data to test
        bin_data payload;
        payload.resize(0xff);
        std::iota(std::begin(payload), std::end(payload), 0x00);
        // Set the first byte to be the test number
        payload[0] = static_cast<std::uint8_t>(bits::test::comm_line);
        const auto res_cmd = command_response(command_code::diagnose, payload, timeout);
        if (res_cmd.second == old_result::success) {
            // Test that the reurned data coincides
            if (payload.size() == res_cmd.first.size() and
                std::equal(std::begin(payload), std::end(payload), std::begin(res_cmd.first)))
            {
                return old_result::success;
            } else {
                LOGW("Communication test failed, returned sequence does not match sent sequence.");
                return old_result::failure;
            }
        }
        return res_cmd.second;
    }

    namespace {
        template <class ...Args>
        old_result nfc_diagnose_simple(nfc &controller, bits::test test, std::uint8_t expected, ms timeout,
                                       Args &&...append_to_body)
       {
            const bin_data payload = bin_data::chain(
                    static_cast<std::uint8_t>(test),
                    std::forward<Args>(append_to_body)...
            );
            const auto res_cmd = controller.command_response(command_code::diagnose, payload, timeout);
            if (res_cmd.second == old_result::success) {
                // Test that the reurned data coincides
                if (res_cmd.first.size() == 1 and res_cmd.first[0] == expected) {
                    return old_result::success;
                } else {
                    LOGW("Diagnostic test %d failed.", static_cast<int>(test));
                    return old_result::failure;
                }
            }
            return res_cmd.second;
        }
    }

    std::tuple<unsigned, unsigned, old_result> nfc::diagnose_poll_target(ms timeout) {
        auto get_fails = [&](speed speed) -> std::pair<unsigned, old_result> {
            const auto res_cmd = command_response(
                    command_code::diagnose,
                    bin_data::chain(
                            static_cast<std::uint8_t>(bits::test::poll_target),
                            static_cast<std::uint8_t>(speed)),
                    timeout);
            if (res_cmd.second == old_result::success) {
                if (res_cmd.first.size() == 1) {
                    return {res_cmd.first[0], old_result::success};
                } else {
                    LOGW("Poll target test failed at speed %d.", static_cast<int>(speed));
                }
            }
            return {std::numeric_limits<unsigned>::max(), res_cmd.second};
        };

        const auto slow_fails = get_fails(speed::kbps212);
        if (slow_fails.second == old_result::success) {
            const auto fast_fails = get_fails(speed::kbps424);
            return std::make_tuple(slow_fails.first, fast_fails.first, fast_fails.second);
        } else {
            return std::make_tuple(slow_fails.first, std::numeric_limits<unsigned>::max(), slow_fails.second);
        }
    }

    old_result nfc::diagnose_echo_back(ms reply_delay, std::uint8_t tx_mode, std::uint8_t rx_mode, ms timeout) {
        const bin_data payload = bin_data::chain(
                static_cast<std::uint8_t>(bits::test::echo_back),
                std::uint8_t(reply_delay.count() * bits::echo_back_reply_delay_steps_per_ms),
                tx_mode,
                rx_mode
        );
        return command(command_code::diagnose, payload, timeout);
    }

    old_result nfc::diagnose_rom(ms timeout) {
        return nfc_diagnose_simple(*this, bits::test::rom, 0x00, timeout);
    }
    old_result nfc::diagnose_ram(ms timeout) {
        return nfc_diagnose_simple(*this, bits::test::ram, 0x00, timeout);
    }
    old_result nfc::diagnose_attention_req_or_card_presence(ms timeout) {
        return nfc_diagnose_simple(*this, bits::test::attention_req_or_card_presence, 0x00, timeout);
    }

    old_result nfc::diagnose_self_antenna(std::uint8_t threshold, ms timeout) {
        return nfc_diagnose_simple(*this, bits::test::self_antenna, 0x00, timeout, threshold);
    }

    std::pair<firmware_version, old_result> nfc::get_firmware_version(ms timeout) {
        const auto res_cmd = command_response(command_code::get_firmware_version, bin_data{}, timeout);
        if (res_cmd.second != old_result::success) {
            return {firmware_version{}, res_cmd.second};
        } else if (res_cmd.first.size() != 4) {
            LOGW("Get firmware version: expected 4 bytes of data, not %ull.", res_cmd.first.size());
            return {firmware_version{}, old_result::comm_malformed};
        }
        // Unpack
        firmware_version fw{};
        fw.ic = res_cmd.first[0];
        fw.version = res_cmd.first[1];
        fw.revision = res_cmd.first[2];
        fw.iso_18092 = 0 != (res_cmd.first[3] & bits::firmware_iso_18092_mask);
        fw.iso_iec_14443_typea = 0 != (res_cmd.first[3] & bits::firmware_iso_iec_14443_typea_mask);
        fw.iso_iec_14443_typeb = 0 != (res_cmd.first[3] & bits::firmware_iso_iec_14443_typeb_mask);
        return {fw, old_result::success};
    }

    std::pair<general_status, old_result> nfc::get_general_status(ms timeout) {
        const auto res_cmd = command_response(command_code::get_general_status, bin_data{}, timeout);
        if (res_cmd.second != old_result::success) {
            return {general_status{}, res_cmd.second};
        } else if (res_cmd.first.size() != 12) {
            LOGW("Get status: expected 12 bytes of data, not %ull.", res_cmd.first.size());
            return {general_status{}, old_result::comm_malformed};
        }
        // Unpack
        auto parse_target_status = [](bin_data const &d, std::size_t ofs) -> target_status {
            target_status retval{};
            retval.logical_index = d[ofs];
            retval.bitrate_rx = static_cast<speed>(d[ofs + 1]);
            retval.bitrate_tx = static_cast<speed>(d[ofs + 2]);
            retval.modulation_type = static_cast<modulation>(d[ofs + 3]);
            return retval;
        };

        auto const &b = res_cmd.first;
        general_status s{};
        s.nad_present = 0 != (b[0] & bits::error_nad_mask);
        s.mi_set = 0 != (b[0] & bits::error_mi_mask);
        s.last_error = static_cast<controller_error>(b[0] & bits::error_code_mask);
        s.rf_field_present = b[1] != 0x00;
        s.sam_status = b[11];
        if (b[2] > 2) {
            LOGE("Detected more than two targets handled by PN532, most likely an error.");
        }
        const std::size_t num_targets = std::min(std::size_t(b[2]), 2u);
        s.targets.reserve(num_targets);
        for (std::size_t i = 0; i < num_targets; ++i) {
            s.targets.push_back(parse_target_status(b, 3 + 4 * i));
        }
        return {s, old_result::success};
    }

    std::pair<std::vector<uint8_t>, old_result> nfc::read_register(std::vector<reg_addr> const &addresses, ms timeout) {
        bin_data payload{};
        for (reg_addr const &addr : addresses) {
            payload << addr;
        }
        auto res_cmd = command_response(command_code::read_register, payload, timeout);
        if (res_cmd.first.size() != addresses.size()) {
            LOGW("Read register: requested %ul registers, got %ul instead.", addresses.size(), res_cmd.first.size());
        }
        return {std::move(res_cmd.first), res_cmd.second};
    }

    old_result nfc::write_register(std::vector<std::pair<reg_addr, std::uint8_t>> const &addr_value_pairs, ms timeout) {
        bin_data payload{};
        for (auto const &addr_value : addr_value_pairs) {
            payload << addr_value.first << addr_value.second;
        }
        return command_response(command_code::write_register, payload, timeout).second;
    }

    std::pair<gpio_status, old_result> nfc::read_gpio(ms timeout) {
        auto res_cmd = command_response(command_code::read_gpio, bin_data{}, timeout);
        if (res_cmd.second == old_result::success) {
            if (res_cmd.first.size() != 3) {
                LOGW("Read GPIO: got %ul bytes, expected 3.", res_cmd.first.size());
                return {gpio_status{}, old_result::comm_malformed};
            }
            return {gpio_status{res_cmd.first[0], res_cmd.first[1], res_cmd.first[2]}, old_result::success};
        }
        return {gpio_status{}, res_cmd.second};
    }

    old_result nfc::write_gpio(gpio_status const &status, bool write_p3, bool write_p7, ms timeout) {
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
        return command_response(command_code::write_gpio, payload, timeout).second;
    }

    old_result nfc::set_gpio_pin(gpio_loc loc, std::uint8_t pin_idx, bool value, ms timeout) {
        reduce_timeout rt{timeout};
        auto res_read = read_gpio(rt.remaining());
        if (res_read.second != old_result::success) {
            return res_read.second;
        }
        res_read.first[{loc, pin_idx}] = value;
        const bool write_p3 = (loc == gpio_loc::p3);
        const bool write_p7 = (loc == gpio_loc::p7);
        return write_gpio(res_read.first, write_p3, write_p7, rt.remaining());
    }

    bool frames::is_error_frame(header const &hdr, bin_data const &data) {
        return hdr.checksum_pass
               and hdr.length == 1
               and data.size() == 2
               and bits::checksum(std::begin(data), std::end(data))
               and data[0] == bits::specific_app_level_err_code;
    }


    frames::information_body frames::parse_information_body(frames::header const &hdr, bin_data const &data) {
        frames::information_body retval{};
        if (hdr.type != frame_type::other) {
            LOGE("Ack and nack frames do not have body.");
        } else if (not hdr.checksum_pass) {
            LOGE("Cannot parse frame body if frame length compute_checksum failed.");
        } else if (hdr.length < 2) {
            LOGE("Cannot parse frame body if frame length is less than 2.");
        } else if (data.size() != hdr.length + 1) {
            LOGE("Cannot parse frame body if expected frame length differs from actual data.");
        } else {
            retval.checksum_pass = bits::checksum(std::begin(data), std::end(data));
            retval.transport = static_cast<bits::transport>(data[0]);
            retval.command = bits::pn532_to_host_command(data[1]);
            retval.payload = data.view(2, data.size() - 3);  // Checksum byte
        }
        return retval;
    }


    bin_data frames::get_information(command_code cmd, bin_data const &payload) {
        const auto cmd_byte = bits::host_to_pn532_command(cmd);
        const auto transport_byte = static_cast<std::uint8_t>(bits::transport::host_to_pn532);
        // "2" because must count transport info and command_code
        const bool use_extended_format = (payload.size() > 0xff - 2);
        const std::uint8_t length = std::min(payload.size(), bits::max_firmware_data_length - 2);
        // Make sure data gets truncated and nothing too weird happens
        const auto truncated_data = payload.view(0, length);
        // Precompute transport info + cmd byte + payload compute_checksum
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

    bin_data const &frames::get_ack() {
        static const bin_data ack_frame = bin_data::chain(
                bits::preamble,
                bits::start_of_packet_code,
                bits::ack_packet_code,
                bits::postamble
        );
        return ack_frame;
    }
    bin_data const &frames::get_nack() {
        static const bin_data nack_frame = bin_data::chain(
                bits::preamble,
                bits::start_of_packet_code,
                bits::nack_packet_code,
                bits::postamble
        );
        return nack_frame;
    }
}