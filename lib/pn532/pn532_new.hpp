//
// Created by Pietro Saccardi on 20/12/2020.
//

#ifndef APERTURAPORTA_PN532_HPP
#define APERTURAPORTA_PN532_HPP


#include <array>
#include <vector>
#include <cstddef>
#include <limits>
#include "instructions_new.hpp"
#include "channel.hpp"

namespace pn532 {

    namespace frames {
        struct header;
    }

    class bin_data;

    enum struct result {
        success,
        timeout,
        comm_checksum_fail,
        comm_error,
        comm_malformed,
        nack,
        failure
    };

    struct firmware_version {
        std::uint8_t ic = std::numeric_limits<std::uint8_t>::max();
        std::uint8_t version = std::numeric_limits<std::uint8_t>::max();
        std::uint8_t revision = std::numeric_limits<std::uint8_t>::max();
        bool iso_18092 = false;
        bool iso_iec_14443_typeb = false;
        bool iso_iec_14443_typea = false;
    };

    struct target_status {
        std::uint8_t logical_index;
        pieces::speed bitrate_rx;
        pieces::speed bitrate_tx;
        pieces::modulation modulation_type;
    };

    struct general_status {
        bool nad_present;
        bool mi_set;
        pieces::error last_error;
        bool rf_field_present;
        std::vector<target_status> targets;
        std::uint8_t sam_status;
    };

    class nfc {
        channel *_channel;

        inline channel &chn() const;

        bool await_frame(ms timeout);
        std::pair<frames::header, bool> read_header(ms timeout);
        std::pair<bin_data, bool> read_body(frames::header const &hdr, ms timeout);

    public:
        inline explicit nfc(channel &chn);

        nfc(nfc const &) = delete;
        nfc(nfc &&) = default;

        nfc &operator=(nfc const &) = delete;
        nfc &operator=(nfc &&) = default;

        result raw_send_ack(bool ack = true, ms timeout = one_sec);
        result raw_send_command(pieces::command cmd, bin_data const &payload, ms timeout = one_sec);

        std::pair<bool, result> raw_await_ack(ms timeout = one_sec);
        std::tuple<pieces::command, bin_data, result> raw_await_response(ms timeout = one_sec);

        result command(pieces::command cmd, bin_data const &payload, ms timeout = one_sec);
        std::pair<bin_data, result> command_response(pieces::command cmd, bin_data const &payload, ms timeout = one_sec);

        std::pair<bin_data, result> diagnose(pieces::test test, bin_data const &payload, ms timeout = one_sec);

        result diagnose_rom(ms timeout = one_sec);
        result diagnose_ram(ms timeout = one_sec);
        result diagnose_attention_req_or_card_presence(ms timeout = one_sec);

        result diagnose_comm_line(ms timeout = one_sec);
        /**
         *
         * @param timeout
         * @return Number of fails (<128) at 212 kbps, number of fails (<128) as 424 kbps, command result.
         */
        std::tuple<unsigned, unsigned, result> diagnose_poll_target(ms timeout = one_sec);

        /**
         * @param tx_mode
         * @param rx_mode
         * @todo Figure out what these should be (page 70)
         */
        result diagnose_echo_back(ms reply_delay, std::uint8_t tx_mode, std::uint8_t rx_mode, ms timeout = one_sec);
        /**
         * @param threshold
         * @todo Figure out the bit packing for this (page 72)
         */
        result diagnose_self_antenna(std::uint8_t threshold, ms timeout = one_sec);

        std::pair<firmware_version, result> get_firmware_version(ms timeout = one_sec);

        std::pair<general_status, result> get_general_status(ms timeout = one_sec);
    };



    nfc::nfc(channel &chn) : _channel{&chn} {}
    channel &nfc::chn() const { return *_channel; }


}


#endif //APERTURAPORTA_PN532_HPP
