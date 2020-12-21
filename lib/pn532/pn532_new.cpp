//
// Created by Pietro Saccardi on 20/12/2020.
//

#include <tuple>
#include "pn532_new.hpp"
#include "bin_data.hpp"
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
            pieces::transport transport = pieces::transport::host_to_pn532;
            pieces::command command = pieces::command::diagnose;
            range<bin_data::const_iterator> payload = {};
            bool checksum_pass = false;
        };

        bin_data get_information(pieces::command cmd, bin_data const &payload);
        bin_data const &get_ack();
        bin_data const &get_nack();

        information_body parse_information_body(header const &hdr, bin_data const &data);
        bool is_error_frame(header const &hdr, bin_data const &data);

    }


    result nfc::send_ack(bool ack, std::chrono::milliseconds timeout) {
        return chn().send(ack ? frames::get_ack() : frames::get_nack(), timeout) ? result::success : result::timeout;
    }

    result nfc::send_cmd(pieces::command cmd, bin_data const &payload, std::chrono::milliseconds timeout) {
        return chn().send(frames::get_information(cmd, payload), timeout) ? result::success : result::timeout;
    }

    bool nfc::await_frame(std::chrono::milliseconds timeout) {
        return chn().await_sequence(pieces::start_of_packet_code, timeout);
    }

    std::pair<frames::header, bool> nfc::read_header(std::chrono::milliseconds timeout) {
        bool success = true;
        frames::header hdr{};
        reduce_timeout rt{timeout};
        std::array<std::uint8_t, 2> code_or_length{};
        if (chn().receive(code_or_length, rt.remaining())) {
            if (code_or_length == pieces::ack_packet_code) {
                hdr.type = frames::frame_type::ack;
                hdr.length = 0;
                hdr.checksum_pass = true;
            } else if (code_or_length == pieces::nack_packet_code) {
                hdr.type = frames::frame_type::nack;
                hdr.length = 0;
                hdr.checksum_pass = true;
            } else if (code_or_length == pieces::fixed_extended_packet_length) {
                hdr.type = frames::frame_type::other;
                std::array<std::uint8_t, 3> ext_length{};
                if (chn().receive(ext_length, rt.remaining())) {
                    std::tie(hdr.length, hdr.checksum_pass) = pieces::check_length_checksum(ext_length);
                } else {
                    success = false;
                }
            } else {
                hdr.type = frames::frame_type::other;
                std::tie(hdr.length, hdr.checksum_pass) = pieces::check_length_checksum(code_or_length);
            }
        } else {
            success = false;
        }
        return std::make_pair(hdr, success);
    }

    std::pair<bin_data, bool> nfc::read_body(frames::header const &hdr, std::chrono::milliseconds timeout) {
        if (not hdr.checksum_pass) {
            LOGE("Cannot parse frame body if frame length compute_checksum failed.");
            return {bin_data{}, false};
        } else if (hdr.length == 0) {
            return {bin_data{}, true};
        }
        return chn().receive(hdr.length + 1, timeout);  // Includes checksum
    }


    std::pair<bool, result> nfc::await_ack(std::chrono::milliseconds timeout) {
        reduce_timeout rt{timeout};
        if (await_frame(rt.remaining())) {
            const auto header_success = read_header(rt.remaining());
            if (header_success.second) {
                // Make sure to consume the command
                if (header_success.first.type == frames::frame_type::other) {
                    LOGE("Expected ack/nack, got a standard command instead; will consume the command now.");
                    const auto data_success = read_body(header_success.first, rt.remaining());
                    if (data_success.second and frames::is_error_frame(header_success.first, data_success.first)) {
                        LOGE("Received an error instead of an ack");
                        return {false, result::error};
                    }
                    return {false, result::malformed};
                } else {
                    return {header_success.first.type == frames::frame_type::ack, result::success};
                }
            }
        }
        return {false, result::timeout};
    }

    std::tuple<pieces::command, bin_data, result> nfc::await_cmd(std::chrono::milliseconds timeout) {
        reduce_timeout rt{timeout};
        if (await_frame(rt.remaining())) {
            const auto header_success = read_header(rt.remaining());
            if (header_success.second) {
                // Make sure to consume the command
                if (header_success.first.type == frames::frame_type::other) {
                    const auto data_success = read_body(header_success.first, rt.remaining());
                    if (data_success.second) {
                        if (frames::is_error_frame(header_success.first, data_success.first)) {
                            LOGE("Received an error instead of info.");
                            return std::make_tuple(pieces::command::diagnose, bin_data{}, result::error);
                        }
                        const frames::information_body body = frames::parse_information_body(header_success.first,
                                                                                             data_success.first);
                        bin_data copy{std::begin(body.payload), std::end(body.payload)};
                        if (not body.checksum_pass) {
                            LOGE("Body did not checksum.");
                            return std::make_tuple(body.command, std::move(copy), result::checksum_fail);
                        } else if (body.transport != pieces::transport::pn532_to_host) {
                            LOGE("Received a message from the host instead of pn532.");
                            return std::make_tuple(body.command, std::move(copy), result::malformed);
                        }
                        return std::make_tuple(body.command, std::move(copy), result::success);
                    }
                } else {
                    LOGE("Expected info command, got ack/nack.");
                    return std::make_tuple(pieces::command::diagnose, bin_data{}, result::malformed);
                }
            }
        }
        return std::make_tuple(pieces::command::diagnose, bin_data{}, result::timeout);
    }

    bool frames::is_error_frame(header const &hdr, bin_data const &data) {
        return hdr.checksum_pass
            and hdr.length == 1
            and data.size() == 2
            and pieces::checksum(std::begin(data), std::end(data))
            and data[0] == pieces::specific_app_level_err_code;
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
            retval.checksum_pass = pieces::checksum(std::begin(data), std::end(data));
            retval.transport = static_cast<pieces::transport>(data[0]);
            retval.command = static_cast<pieces::command>(data[1]);
            retval.payload = data.view(2, data.size() - 3);  // Checksum byte
        }
        return retval;
    }


    bin_data frames::get_information(pieces::command cmd, bin_data const &payload) {
        const auto cmd_byte = static_cast<std::uint8_t>(cmd);
        const auto transport_byte = static_cast<std::uint8_t>(pieces::transport::host_to_pn532);
        // "2" because must count transport info and command
        const bool use_extended_format = (payload.size() > 0xff - 2);
        const std::uint8_t length = std::min(payload.size(), pieces::max_firmware_data_length - 2);
        // Make sure data gets truncated and nothing too weird happens
        const auto truncated_data = payload.view(0, length);
        // Precompute transport info + cmd byte + payload compute_checksum
        const auto checksum = pieces::compute_checksum(
                transport_byte + cmd_byte,
                std::begin(truncated_data),
                std::end(truncated_data)
        );
        bin_data frame = bin_data::chain(pieces::preamble, pieces::start_of_packet_code);
        if (use_extended_format) {
            frame << pieces::fixed_extended_packet_length << pieces::length_and_checksum_long(length);
        } else {
            frame << pieces::length_and_checksum_short(length);
        }
        frame << transport_byte << cmd_byte << truncated_data << checksum << pieces::postamble;
        return frame;
    }

    bin_data const &frames::get_ack() {
        static const bin_data ack_frame = bin_data::chain(
                pieces::preamble,
                pieces::start_of_packet_code,
                pieces::ack_packet_code,
                pieces::postamble
        );
        return ack_frame;
    }
    bin_data const &frames::get_nack() {
        static const bin_data nack_frame = bin_data::chain(
                pieces::preamble,
                pieces::start_of_packet_code,
                pieces::nack_packet_code,
                pieces::postamble
        );
        return nack_frame;
    }
}