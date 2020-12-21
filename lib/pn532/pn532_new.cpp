//
// Created by Pietro Saccardi on 20/12/2020.
//

#include <tuple>
#include "pn532_new.hpp"
#include "bin_data.hpp"
#include "hsu.hpp"

namespace pn532 {

    namespace frames {
        enum struct type {
            ack,
            nack,
            other
        };

        enum struct direction {
            host_to_pn532
        };

        struct header {
            type type = type::other;
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
        information_body parse_body(header const &hdr, bin_data const &data);

    }


    bool nfc::send_ack(bool ack, std::chrono::milliseconds timeout) {
        return chn().write(ack ? frames::get_ack() : frames::get_nack(), timeout);
    }

    bool nfc::send_cmd(pieces::command cmd, bin_data const &payload, std::chrono::milliseconds timeout) {
        return chn().write(frames::get_information(cmd, payload), timeout);
    }

    bool nfc::await_frame(std::chrono::milliseconds timeout) {
        return chn().await_sequence(pieces::start_of_packet_code, timeout);
    }

    std::pair<frames::header, bool> nfc::read_header(std::chrono::milliseconds timeout) {
        bool success = true;
        frames::header hdr{};
        reduce_timeout rt{timeout};
        std::array<std::uint8_t, 2> code_or_length{};
        if (chn().read(code_or_length, rt.remaining())) {
            if (code_or_length == pieces::ack_packet_code) {
                hdr.type = frames::type::ack;
                hdr.length = 0;
                hdr.checksum_pass = true;
            } else if (code_or_length == pieces::nack_packet_code) {
                hdr.type = frames::type::nack;
                hdr.length = 0;
                hdr.checksum_pass = true;
            } else if (code_or_length == pieces::fixed_extended_packet_length) {
                hdr.type = frames::type::other;
                std::array<std::uint8_t, 3> ext_length{};
                if (chn().read(ext_length, rt.remaining())) {
                    std::tie(hdr.length, hdr.checksum_pass) = pieces::check_length_checksum(ext_length);
                } else {
                    success = false;
                }
            } else {
                hdr.type = frames::type::other;
                std::tie(hdr.length, hdr.checksum_pass) = pieces::check_length_checksum(code_or_length);
            }
        } else {
            success = false;
        }
        return std::make_pair(hdr, success);
    }

    std::pair<bin_data, bool> nfc::read_body(frames::header const &hdr, std::chrono::milliseconds timeout) {
        if (not hdr.checksum_pass) {
            // TODO LOG("Cannot parse frame body if frame length compute_checksum failed.")
            return {bin_data{}, false};
        } else if (hdr.length == 0) {
            return {bin_data{}, true};
        }
        return chn().read(hdr.length + 1, timeout);  // Includes checksum
    }


    frames::information_body frames::parse_body(frames::header const &hdr, bin_data const &data) {
        frames::information_body retval{};
        if (hdr.type != type::other) {
            // TODO LOG("Ack and nack frames do not have body.")
        } else if (not hdr.checksum_pass) {
            // TODO LOG("Cannot parse frame body if frame length compute_checksum failed.")
        } else if (hdr.length < 2) {
            // TODO LOG("Cannot parse frame body if frame length is less than 2.")
        } else if (data.size() != hdr.length + 1) {
            // TODO LOG("Cannot parse frame body if expected frame length differs from actual data.")
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