//
// Created by Pietro Saccardi on 20/12/2020.
//

#ifndef APERTURAPORTA_PN532_HPP
#define APERTURAPORTA_PN532_HPP

#include "result.hpp"
#include "bits.hpp"
#include "data.hpp"
#include "channel.hpp"
#include "msg.hpp"

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

        template <class ...Tn>
        using r = result<error, Tn...>;

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
        r<unsigned, unsigned> diagnose_poll_target(bool slow = true, bool fast = true, ms timeout = one_sec);

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

        /**
         * @param addresses Max 131 elements.
         */
        r<std::vector<uint8_t>> read_registers(std::vector<reg_addr> const &addresses, ms timeout = one_sec);

        inline r<uint8_t> read_register(reg_addr const &addr, ms timeout = one_sec);

        /**
         * @param addr_value_pairs Max 87 elements.
         */
        r<> write_registers(std::vector<std::pair<reg_addr, std::uint8_t>> const &addr_value_pairs, ms timeout = one_sec);

        inline r<> write_register(reg_addr const &addr, std::uint8_t val, ms timeout = one_sec);

        r<gpio_status> read_gpio(ms timeout = one_sec);

        r<> write_gpio(gpio_status const &status, bool write_p3 = true, bool write_p7 = true, ms timeout = one_sec);

        r<> set_gpio_pin(gpio_loc loc, std::uint8_t pin_idx, bool value, ms timeout = one_sec);

        r<> set_serial_baud_rate(baud_rate br, ms timeout = one_sec);

        r<> sam_configuration(sam_mode mode, ms sam_timeout, bool controller_drives_irq = true, ms timeout = one_sec);

        r<> rf_configuration_field(bool auto_rfca, bool rf_on, ms timeout = one_sec);

        r<> rf_configuration_timings(std::uint8_t rfu, rf_timeout atr_res_timeout = rf_timeout::ms_102_4,
                                     rf_timeout retry_timeout = rf_timeout::ms_51_2, ms timeout = one_sec);

        r<> rf_configuration_retries(std::uint8_t comm_retries = 0, ms timeout = one_sec);

        r<> rf_configuration_retries(std::uint8_t atr_retries, std::uint8_t psl_retries,
                                     std::uint8_t passive_activation = std::numeric_limits<std::uint8_t>::max(),
                                     ms timeout = one_sec);

        r<> rf_configuration_analog_106kbps_typea(ciu_reg_106kbps_typea const &config, ms timeout = one_sec);

        r<> rf_configuration_analog_212_424kbps(ciu_reg_212_424kbps const &config, ms timeout = one_sec);

        r<> rf_configuration_analog_typeb(ciu_reg_typeb const &config, ms timeout = one_sec);

        r<> rf_configuration_analog_iso_iec_14443_4(ciu_reg_iso_iec_14443_4 const &config, ms timeout = one_sec);

        template <class T>
        r<status, bin_data> initiator_data_exchange(std::uint8_t target_logical_index, T const &data,
                                                    bool expect_more_data, ms timeout = one_sec);

        r<status> initiator_select(std::uint8_t target_logical_index, ms timeout = one_sec);

    private:
        channel *_channel;

        struct frame_header;
        struct frame_body;

        inline channel &chn() const;

        bool await_frame(ms timeout);

        r<frame_header> read_header(ms timeout);

        r<frame_body> read_response_body(frame_header const &hdr, ms timeout);

        r<status, bin_data> initiator_data_exchange_internal(bin_data const &payload, ms timeout);

        static bin_data get_command_info_frame(command_code cmd, bin_data const &payload);
        static bin_data const &get_ack_frame();
        static bin_data const &get_nack_frame();
        static std::uint8_t get_target(command_code cmd, std::uint8_t target_logical_index, bool expect_more_data);
        static status get_status(std::uint8_t data);
    };

    const char *to_string(nfc::error e);
}


namespace pn532 {

    nfc::nfc(channel &chn) : _channel{&chn} {}
    channel &nfc::chn() const { return *_channel; }

    nfc::r<uint8_t> nfc::read_register(reg_addr const &addr, ms timeout) {
        const auto res_cmd = read_registers({addr}, timeout);
        if (res_cmd) {
            return res_cmd->at(0);
        }
        return res_cmd.error();
    }

    nfc::r<> nfc::write_register(reg_addr const &addr, std::uint8_t val, ms timeout) {
        return write_registers({{addr, val}}, timeout);
    }

    template <class T>
    nfc::r<status, bin_data> nfc::initiator_data_exchange(std::uint8_t target_logical_index, T const &data,
                                                          bool expect_more_data, ms timeout)
    {
        return initiator_data_exchange_internal(
                bin_data::chain(
                        get_target(command_code::in_data_exchange, target_logical_index, expect_more_data),
                        data
                ), timeout);
    }

}


#endif //APERTURAPORTA_PN532_HPP
