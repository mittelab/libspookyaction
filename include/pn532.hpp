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

    static constexpr ms default_timeout = one_sec;
    static constexpr ms long_timeout = 3 * default_timeout;

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

        r<> raw_send_ack(bool ack = true, ms timeout = default_timeout);

        /**
         * @param payload Max 263 bytes, will be truncated
         */
        r<> raw_send_command(command_code cmd, bin_data const &payload, ms timeout = default_timeout);

        r<bool> raw_await_ack(ms timeout = default_timeout);

        /**
         * @return Either the received data, or one of the following errors: @ref error::comm_malformed,
         *  @ref error::comm_checksum_fail, or @ref error::timeout. No other error codes are produced.
         */
        r<bin_data> raw_await_response(command_code cmd, ms timeout = default_timeout);

        /** @brief Command without response.
         * @param payload Max 263 bytes, will be truncated
         */
        r<> command(command_code cmd, bin_data const &payload, ms timeout = default_timeout);

        /**
         * @param payload Max 263 bytes, will be truncated
         */
        r<bin_data> command_response(command_code cmd, bin_data const &payload, ms timeout = default_timeout);

        /**
         * @param payload Max 263 bytes, will be truncated
         */
        template <class Data, class = typename std::enable_if<bin_stream::is_extractable<Data>::value>::type>
        r<Data> command_parse_response(command_code cmd, bin_data const &payload, ms timeout = default_timeout);

        r<bool> diagnose_rom(ms timeout = long_timeout);

        r<bool> diagnose_ram(ms timeout = long_timeout);

        r<bool> diagnose_attention_req_or_card_presence(ms timeout = long_timeout);

        r<bool> diagnose_comm_line(ms timeout = long_timeout);

        /**
         *
         * @param timeout
         * @return Number of fails (<128) at 212 kbps, number of fails (<128) as 424 kbps, command_code result.
         */
        r<unsigned, unsigned> diagnose_poll_target(bool slow = true, bool fast = true, ms timeout = long_timeout);

        /**
         * @param tx_mode Cfr. CIU_TxMode register (0x6302), §8.6.23.18 PN432/C1 Data sheet
         * @param rx_mode Cfr. CIU_RxMode register (0x6303), §8.6.23.19 PN432/C1 Data sheet
         */
        r<> diagnose_echo_back(ms reply_delay, std::uint8_t tx_mode, std::uint8_t rx_mode, ms timeout = long_timeout);

        r<bool> diagnose_self_antenna(low_current_thr low_threshold, high_current_thr high_threshold, ms timeout = long_timeout);

        r<firmware_version> get_firmware_version(ms timeout = default_timeout);

        r<general_status> get_general_status(ms timeout = default_timeout);

        /**
         * @param addresses Max 131 elements.
         */
        r<std::vector<uint8_t>> read_registers(std::vector<reg_addr> const &addresses, ms timeout = default_timeout);

        inline r<uint8_t> read_register(reg_addr const &addr, ms timeout = default_timeout);

        /**
         * @param addr_value_pairs Max 87 elements.
         */
        r<> write_registers(std::vector<std::pair<reg_addr, std::uint8_t>> const &addr_value_pairs, ms timeout = default_timeout);

        inline r<> write_register(reg_addr const &addr, std::uint8_t val, ms timeout = default_timeout);

        r<gpio_status> read_gpio(ms timeout = default_timeout);

        r<> write_gpio(gpio_status const &status, bool write_p3 = true, bool write_p7 = true, ms timeout = default_timeout);

        r<> set_gpio_pin(gpio_loc loc, std::uint8_t pin_idx, bool value, ms timeout = default_timeout);

        r<> set_serial_baud_rate(baud_rate br, ms timeout = default_timeout);

        r<> sam_configuration(sam_mode mode, ms sam_timeout, bool controller_drives_irq = true, ms timeout = default_timeout);

        r<> rf_configuration_field(bool auto_rfca, bool rf_on, ms timeout = default_timeout);

        r<> rf_configuration_timings(std::uint8_t rfu, rf_timeout atr_res_timeout = rf_timeout::ms_102_4,
                                     rf_timeout retry_timeout = rf_timeout::ms_51_2, ms timeout = default_timeout);

        r<> rf_configuration_retries(std::uint8_t comm_retries = 0, ms timeout = default_timeout);

        r<> rf_configuration_retries(std::uint8_t atr_retries, std::uint8_t psl_retries,
                                     std::uint8_t passive_activation = std::numeric_limits<std::uint8_t>::max(),
                                     ms timeout = default_timeout);

        r<> rf_configuration_analog_106kbps_typea(ciu_reg_106kbps_typea const &config, ms timeout = default_timeout);

        r<> rf_configuration_analog_212_424kbps(ciu_reg_212_424kbps const &config, ms timeout = default_timeout);

        r<> rf_configuration_analog_typeb(ciu_reg_typeb const &config, ms timeout = default_timeout);

        r<> rf_configuration_analog_iso_iec_14443_4(ciu_reg_iso_iec_14443_4 const &config, ms timeout = default_timeout);

        template <class T>
        r<status, bin_data> initiator_data_exchange(std::uint8_t target_logical_index, T const &data,
                                                    bool expect_more_data, ms timeout = default_timeout);

        r<status> initiator_select(std::uint8_t target_logical_index, ms timeout = default_timeout);

        r<std::vector<target_kbps106_typea>> initiator_list_passive_kbps106_typea(
                std::uint8_t max_targets = bits::max_num_targets, ms timeout = default_timeout);
        r<std::vector<target_kbps106_typea>> initiator_list_passive_kbps106_typea(
                uid_cascade_l1 uid, std::uint8_t max_targets = 1, ms timeout = default_timeout);
        r<std::vector<target_kbps106_typea>> initiator_list_passive_kbps106_typea(
                uid_cascade_l2 uid, std::uint8_t max_targets = 1, ms timeout = default_timeout);
        r<std::vector<target_kbps106_typea>> initiator_list_passive_kbps106_typea(
                uid_cascade_l3 uid, std::uint8_t max_targets = 1, ms timeout = default_timeout);
        r<std::vector<target_kbps106_typeb>> initiator_list_passive_kbps106_typeb(
                std::uint8_t application_family_id, polling_method method = polling_method::timeslot,
                std::uint8_t max_targets = bits::max_num_targets, ms timeout = default_timeout);

        r<std::vector<target_kbps212_felica>> initiator_list_passive_kbps212_felica(
                std::array<std::uint8_t, 5> const &payload, std::uint8_t max_targets = bits::max_num_targets,
                ms timeout = default_timeout);

        r<std::vector<target_kbps424_felica>> initiator_list_passive_kbps424_felica(
                std::array<std::uint8_t, 5> const &payload, std::uint8_t max_targets = bits::max_num_targets,
                ms timeout = default_timeout);
        r<std::vector<target_kbps106_jewel_tag>> initiator_list_passive_kbps106_jewel_tag(
                ms timeout = default_timeout);


        r<status, atr_res_info> initiator_activate_target(std::uint8_t target_logical_index, ms timeout = default_timeout);
        r<status, atr_res_info> initiator_activate_target(std::uint8_t target_logical_index,
                                                          std::array<std::uint8_t, 10> const &nfcid_3t,
                                                          ms timeout = default_timeout);
        /**
         * @param general_info Max 48 bytes.
         */
        r<status, atr_res_info> initiator_activate_target(std::uint8_t target_logical_index,
                                                          std::vector<std::uint8_t> const &general_info,
                                                          ms timeout = default_timeout);

        /**
         * @param general_info Max 48 bytes.
         */
        r<status, atr_res_info> initiator_activate_target(std::uint8_t target_logical_index,
                                                          std::array<std::uint8_t, 10> const &nfcid_3t,
                                                          std::vector<std::uint8_t> const &general_info,
                                                          ms timeout = default_timeout);

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

        template <baudrate_modulation BrMd>
        r<std::vector<bits::target<BrMd>>> initiator_list_passive(std::uint8_t max_targets,
                                                                  bin_data const &initiator_data, ms timeout);
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

    template <class Data, class>
    nfc::r<Data> nfc::command_parse_response(command_code cmd, bin_data const &payload, ms timeout) {
        const auto res_cmd = command_response(cmd, payload, timeout);
        if (not res_cmd) {
            return res_cmd.error();
        }
        bin_stream s{*res_cmd};
        Data data{};
        s >> data;
        if (s.bad()) {
            LOGE("%s: could not parse result from response data.", to_string(cmd));
            return error::comm_malformed;
        }
        return data;
    }

    template <class T>
    nfc::r<status, bin_data> nfc::initiator_data_exchange(std::uint8_t target_logical_index, T const &data,
                                                          bool expect_more_data, ms timeout)
    {
        const std::uint8_t target_byte = get_target(command_code::in_data_exchange, target_logical_index, expect_more_data);
        return initiator_data_exchange_internal(bin_data::chain(target_byte, data), timeout);
    }

}


#endif //APERTURAPORTA_PN532_HPP
