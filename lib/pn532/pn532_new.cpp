//
// Created by Pietro Saccardi on 20/12/2020.
//

#include "pn532_new.hpp"
#include "bin_data.hpp"
#include "hsu.hpp"

namespace pn532 {

    namespace frames {
        bin_data get_information(command cmd, bin_data const &payload);

        bin_data const &get_ack();
        bin_data const &get_nack();

        template <std::size_t Length>
        bool wait_for_sequence(channel &chn, std::array<std::uint8_t, Length> const &sequence,
                               std::chrono::milliseconds timeout);
    }


    bool nfc::send_ack(bool ack, std::chrono::milliseconds timeout) {
        return chn().write(ack ? frames::get_ack() : frames::get_nack(), timeout);
    }

    bool nfc::send_cmd(command cmd, bin_data const &payload, std::chrono::milliseconds timeout) {
        return chn().write(frames::get_information(cmd, payload), timeout);
    }

    bool nfc::await_frame(std::chrono::milliseconds timeout) {
        return chn().await_sequence(pieces::start_of_packet_code, timeout);
    }


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
}