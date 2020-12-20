//
// Created by Pietro Saccardi on 20/12/2020.
//

#include "pn532_new.hpp"
#include "hsu.hpp"

namespace pn532 {

    bin_data frames::get_information(command cmd, bin_data const &payload) {
        const auto cmd_byte = static_cast<std::uint8_t>(cmd);
        // "2" because must count transport info and command
        const bool use_extended_format = (payload.size() > 0xff - 2);
        const std::uint8_t length = std::min(payload.size(), pieces::max_firmware_data_length - 2);
        // Make sure data gets truncated and nothing too weird happens
        const auto truncated_data = payload.view(0, length);
        // Precompute transport info + cmd byte + payload checksum
        const auto checksum = pieces::checksum(
                pieces::host_to_pn532 + cmd_byte,
                std::begin(truncated_data),
                std::end(truncated_data)
        );
        bin_data frame = bin_data::chain(pieces::preamble, pieces::start_of_packet_code);
        if (use_extended_format) {
            frame << pieces::length_and_checksum_long(length);
        } else {
            frame << pieces::length_and_checksum_short(length);
        }
        frame << cmd_byte << truncated_data << checksum << pieces::postamble;
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
    bin_data const &frames::get_error() {
        static const bin_data error_frame = bin_data::chain(
                pieces::preamble,
                pieces::start_of_packet_code,
                pieces::length_and_checksum_short(1),
                pieces::specific_app_level_err_code,
                pieces::checksum(pieces::specific_app_level_err_code),
                pieces::postamble
        );
        return error_frame;
    }
}