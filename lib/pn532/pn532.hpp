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

    class bin_data;

    class nfc {
    public:
        enum struct error {
            timeout,
            comm_checksum_fail,
            comm_error,
            comm_malformed,
            nack,
            failure
        };

        template <class Data = void>
        using r = result<Data, error>;

        inline explicit nfc(channel &chn);

        nfc(nfc const &) = delete;

        nfc(nfc &&) = default;

        nfc &operator=(nfc const &) = delete;

        nfc &operator=(nfc &&) = default;

        r<> raw_send_ack(bool ack = true, ms timeout = one_sec);

        r<> raw_send_command(command_code cmd, bin_data const &payload, ms timeout = one_sec);

        r<bool> raw_await_ack(ms timeout = one_sec);

        r<bin_data> raw_await_response(command_code cmd, ms timeout = one_sec);

        r<> command(command_code cmd, bin_data const &payload, ms timeout = one_sec);

        r<bin_data> command_response(command_code cmd, bin_data const &payload, ms timeout = one_sec);

        r<> diagnose_rom(ms timeout = one_sec);

        r<> diagnose_ram(ms timeout = one_sec);

        r<> diagnose_attention_req_or_card_presence(ms timeout = one_sec);

        r<> diagnose_comm_line(ms timeout = one_sec);

        /**
         *
         * @param timeout
         * @return Number of fails (<128) at 212 kbps, number of fails (<128) as 424 kbps, command_code result.
         */
        r<std::pair<unsigned, unsigned>> diagnose_poll_target(bool slow = true, bool fast = true, ms timeout = one_sec);

        /**
         * @param tx_mode
         * @param rx_mode
         * @todo Figure out what these should be (page 70)
         */
        r<> diagnose_echo_back(ms reply_delay, std::uint8_t tx_mode, std::uint8_t rx_mode, ms timeout = one_sec);

        /**
         * @param threshold
         * @todo Figure out the bit packing for this (page 72)
         */
        r<> diagnose_self_antenna(std::uint8_t threshold, ms timeout = one_sec);

        r<firmware_version> get_firmware_version(ms timeout = one_sec);

        r<general_status> get_general_status(ms timeout = one_sec);

        r<std::vector<uint8_t>> read_register(std::vector<reg_addr> const &addresses, ms timeout = one_sec);

        r<> write_register(std::vector<std::pair<reg_addr, std::uint8_t>> const &addr_value_pairs, ms timeout = one_sec);

        r<gpio_status> read_gpio(ms timeout = one_sec);

        r<> write_gpio(gpio_status const &status, bool write_p3 = true, bool write_p7 = true, ms timeout = one_sec);

        r<> set_gpio_pin(gpio_loc loc, std::uint8_t pin_idx, bool value, ms timeout = one_sec);

        /*
- (SetSerialBaudRate)
- SAMConfiguration

- RFConfiguration
- InDataExchange
- InSelect
- InAutoPoll
         */
    private:
        channel *_channel;

        struct frame_header;
        struct frame_body;

        inline channel &chn() const;

        bool await_frame(ms timeout);

        r<frame_header> read_header(ms timeout);

        r<frame_body> read_response_body(frame_header const &hdr, ms timeout);

        static bin_data get_command_info_frame(command_code cmd, bin_data const &payload);
        static bin_data const &get_ack_frame();
        static bin_data const &get_nack_frame();
    };

}


namespace pn532 {

    nfc::nfc(channel &chn) : _channel{&chn} {}
    channel &nfc::chn() const { return *_channel; }


}


#endif //APERTURAPORTA_PN532_HPP
