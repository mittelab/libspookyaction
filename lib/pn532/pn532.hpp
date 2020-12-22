//
// Created by Pietro Saccardi on 20/12/2020.
//

#ifndef APERTURAPORTA_PN532_HPP
#define APERTURAPORTA_PN532_HPP

#include "result.hpp"
#include "bits.hpp"
#include "data.hpp"
#include "channel.hpp"

namespace pn532 {

    namespace frames {
        struct header;
    }

    class bin_data;

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

        old_result raw_send_ack(bool ack = true, ms timeout = one_sec);

        old_result raw_send_command(command_code cmd, bin_data const &payload, ms timeout = one_sec);

        std::pair<bool, old_result> raw_await_ack(ms timeout = one_sec);

        std::tuple<command_code, bin_data, old_result> raw_await_response(ms timeout = one_sec);

        old_result command(command_code cmd, bin_data const &payload, ms timeout = one_sec);

        std::pair<bin_data, old_result> command_response(command_code cmd, bin_data const &payload, ms timeout = one_sec);

        old_result diagnose_rom(ms timeout = one_sec);

        old_result diagnose_ram(ms timeout = one_sec);

        old_result diagnose_attention_req_or_card_presence(ms timeout = one_sec);

        old_result diagnose_comm_line(ms timeout = one_sec);

        /**
         *
         * @param timeout
         * @return Number of fails (<128) at 212 kbps, number of fails (<128) as 424 kbps, command_code result.
         */
        std::tuple<unsigned, unsigned, old_result> diagnose_poll_target(ms timeout = one_sec);

        /**
         * @param tx_mode
         * @param rx_mode
         * @todo Figure out what these should be (page 70)
         */
        old_result diagnose_echo_back(ms reply_delay, std::uint8_t tx_mode, std::uint8_t rx_mode, ms timeout = one_sec);

        /**
         * @param threshold
         * @todo Figure out the bit packing for this (page 72)
         */
        old_result diagnose_self_antenna(std::uint8_t threshold, ms timeout = one_sec);

        std::pair<firmware_version, old_result> get_firmware_version(ms timeout = one_sec);

        std::pair<general_status, old_result> get_general_status(ms timeout = one_sec);

        std::pair<std::vector<uint8_t>, old_result> read_register(std::vector<reg_addr> const &addresses, ms timeout = one_sec);

        old_result write_register(std::vector<std::pair<reg_addr, std::uint8_t>> const &addr_value_pairs, ms timeout = one_sec);

        std::pair<gpio_status, old_result> read_gpio(ms timeout = one_sec);

        old_result write_gpio(gpio_status const &status, bool write_p3 = true, bool write_p7 = true, ms timeout = one_sec);

        old_result set_gpio_pin(gpio_loc loc, std::uint8_t pin_idx, bool value, ms timeout = one_sec);

        /*
- (SetSerialBaudRate)
- SAMConfiguration

- RFConfiguration
- InDataExchange
- InSelect
- InAutoPoll
         */
    };

}


namespace pn532 {

    nfc::nfc(channel &chn) : _channel{&chn} {}
    channel &nfc::chn() const { return *_channel; }


}


#endif //APERTURAPORTA_PN532_HPP
