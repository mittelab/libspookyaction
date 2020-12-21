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
        checksum_fail,
        error,
        malformed,
        nack
    };

    class nfc {
        channel *_channel;

        inline channel &chn() const;

        bool await_frame(std::chrono::milliseconds timeout);
        std::pair<frames::header, bool> read_header(std::chrono::milliseconds timeout);
        std::pair<bin_data, bool> read_body(frames::header const &hdr, std::chrono::milliseconds timeout);
    public:
        inline explicit nfc(channel &chn);

        nfc(nfc const &) = delete;
        nfc(nfc &&) = default;

        nfc &operator=(nfc const &) = delete;
        nfc &operator=(nfc &&) = default;

        result raw_send_ack(bool ack = true, std::chrono::milliseconds timeout = one_sec);
        result raw_send_command(pieces::command cmd, bin_data const &payload, std::chrono::milliseconds timeout = one_sec);

        std::pair<bool, result> raw_await_ack(std::chrono::milliseconds timeout = one_sec);
        std::tuple<pieces::command, bin_data, result> raw_await_response(std::chrono::milliseconds timeout = one_sec);

        result command(pieces::command cmd, bin_data const &payload, std::chrono::milliseconds timeout = one_sec);
        std::pair<bin_data, result> command_response(pieces::command cmd, bin_data const &payload, std::chrono::milliseconds timeout = one_sec);
    };



    nfc::nfc(channel &chn) : _channel{&chn} {}
    channel &nfc::chn() const { return *_channel; }

}


#endif //APERTURAPORTA_PN532_HPP
