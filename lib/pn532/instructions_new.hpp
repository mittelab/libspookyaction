//
// Created by Pietro Saccardi on 20/12/2020.
//

#ifndef APERTURAPORTA_INSTRUCTIONS_HPP
#define APERTURAPORTA_INSTRUCTIONS_HPP

#include <array>
#include <vector>
#include <cstddef>
#include <numeric>

namespace pn532 {

    namespace pieces {
        static constexpr std::uint8_t preamble = 0x00;
        static constexpr std::uint8_t postamble = 0x00;

        enum struct transport : std::uint8_t {
            host_to_pn532 = 0xd4,
            pn532_to_host = 0xd5
        };

        static constexpr std::uint8_t specific_app_level_err_code = 0x7f;
        static constexpr std::array<std::uint8_t, 2> start_of_packet_code = {0x00, 0xff};
        static constexpr std::array<std::uint8_t, 2> ack_packet_code = {0x00, 0xff};
        static constexpr std::array<std::uint8_t, 2> nack_packet_code = {0xff, 0x00};
        static constexpr std::array<std::uint8_t, 2> fixed_extended_packet_length = {0xff, 0xff};

        static constexpr std::size_t max_firmware_data_length = 265;

        static constexpr unsigned echo_back_reply_delay_steps_per_ms = 2;

        inline std::uint8_t compute_checksum(std::uint8_t byte);

        template<class ByteIterator>
        std::uint8_t compute_checksum(ByteIterator begin, ByteIterator end);

        template<class ByteIterator>
        std::uint8_t compute_checksum(std::uint8_t sum_init, ByteIterator begin, ByteIterator end);

        template<class ByteIterator>
        bool checksum(ByteIterator begin, ByteIterator end);

        inline std::array<std::uint8_t, 2> length_and_checksum_short(std::uint8_t length);

        inline std::array<std::uint8_t, 3> length_and_checksum_long(std::uint16_t length);

        inline std::pair<std::uint8_t, bool> check_length_checksum(std::array<std::uint8_t, 2> const &data);

        inline std::pair<std::uint16_t, bool> check_length_checksum(std::array<std::uint8_t, 3> const &data);

        enum struct command : std::uint8_t {
            diagnose = 0x00,
            get_firmware_version = 0x02,
            get_general_status = 0x04,
            read_register = 0x06,
            write_register = 0x08,
            read_gpio = 0x0c,
            write_gpio = 0x0e,
            set_serial_baudrate = 0x10,
            set_parameters = 0x12,
            sam_configuration = 0x14,
            power_down = 0x16,
            rf_configuration = 0x32,
            rf_regulation_test = 0x58,
            in_jump_for_dep = 0x56,
            in_jump_for_psl = 0x46,
            in_list_passive_target = 0x4a,
            in_atr = 0x50,
            in_psl = 0x4e,
            in_data_exchange = 0x40,
            in_communicate_thru = 0x42,
            in_deselect = 0x44,
            in_release = 0x52,
            in_select = 0x54,
            in_autopoll = 0x60,
            tg_init_as_target = 0x8c,
            tg_set_general_bytes = 0x92,
            tg_get_data = 0x86,
            tg_set_data = 0x8e,
            tg_set_metadata = 0x94,
            tg_get_initiator_command = 0x88,
            tg_response_to_initiator = 0x90,
            tg_get_target_status = 0x8a
        };

        enum struct test : std::uint8_t {
            comm_line = 0x0,
            rom = 0x1,
            ram = 0x2,
            poll_target = 0x4,
            echo_back = 0x5,
            attention_req_or_card_presence = 0x6,
            self_antenna = 0x6
        };

        enum struct speed : std::uint8_t {
            kbps212 = 0x1,
            kbps424 = 0x2
        };

        inline std::uint8_t host_to_pn532_command(command cmd);
        inline command pn532_to_host_command(std::uint8_t cmd);


        std::uint8_t compute_checksum(std::uint8_t byte) {
            return ~byte + 1;
        }

        template<class ByteIterator>
        std::uint8_t compute_checksum(ByteIterator begin, ByteIterator end) {
            return compute_checksum(0, begin, end);
        }

        template<class ByteIterator>
        std::uint8_t compute_checksum(std::uint8_t sum_init, ByteIterator begin, ByteIterator end) {
            return compute_checksum(std::accumulate(begin, end, sum_init));
        }

        template<class ByteIterator>
        bool checksum(ByteIterator begin, ByteIterator end) {
            return std::accumulate(begin, end, 0) == 0;
        }

        std::array<std::uint8_t, 2> length_and_checksum_short(std::uint8_t length) {
            return {length, compute_checksum(&length, &length)};
        }

        std::array<std::uint8_t, 3> length_and_checksum_long(std::uint16_t length) {
            const std::array<std::uint8_t, 2> bits = {std::uint8_t(length >> 8), std::uint8_t(length & 0xff)};
            return {bits[0], bits[1], compute_checksum(std::begin(bits), std::end(bits))};
        }

        std::pair<std::uint8_t, bool> check_length_checksum(std::array<std::uint8_t, 2> const &data) {
            return {data[0], compute_checksum(data[0]) == data[1]};
        }

        std::pair<std::uint16_t, bool> check_length_checksum(std::array<std::uint8_t, 3> const &data) {
            return {(std::uint16_t(data[0]) << 8) | data[1],
                    compute_checksum(std::begin(data), std::begin(data) + 2) == data[3]};
        }


        inline std::uint8_t host_to_pn532_command(command cmd) {
            return static_cast<std::uint8_t>(cmd);
        }
        inline command pn532_to_host_command(std::uint8_t cmd) {
            return static_cast<command>(cmd - 1);
        }
    }
}

#endif //APERTURAPORTA_INSTRUCTIONS_HPP
