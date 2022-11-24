//
// Created by Pietro Saccardi on 22/12/2020.
//

#ifndef PN532_BITS_ALGO_HPP
#define PN532_BITS_ALGO_HPP

#include <array>
#include <cstdint>
#include <numeric>
#include <pn532/bits.hpp>

namespace pn532::bits {

    [[nodiscard]] inline std::uint8_t compute_checksum(std::uint8_t byte);

    template <class ByteIterator>
    [[nodiscard]] std::uint8_t compute_checksum(ByteIterator begin, ByteIterator end);

    template <class ByteIterator>
    [[nodiscard]] std::uint8_t compute_checksum(std::uint8_t sum_init, ByteIterator begin, ByteIterator end);

    template <class ByteIterator>
    [[nodiscard]] bool checksum(ByteIterator begin, ByteIterator end);

    [[nodiscard]] inline std::array<std::uint8_t, 2> length_and_checksum_short(std::uint8_t length);

    [[nodiscard]] inline std::array<std::uint8_t, 3> length_and_checksum_long(std::uint16_t length);

    [[nodiscard]] inline std::pair<std::uint8_t, bool> check_length_checksum(std::array<std::uint8_t, 2> const &data);

    [[nodiscard]] inline std::pair<std::uint16_t, bool> check_length_checksum(std::array<std::uint8_t, 3> const &data);

    [[nodiscard]] inline std::uint8_t host_to_pn532_command(command cmd);

    [[nodiscard]] inline command pn532_to_host_command(std::uint8_t cmd);

}// namespace pn532::bits

namespace pn532::bits {

    std::uint8_t compute_checksum(std::uint8_t byte) {
        return ~byte + 1;
    }

    template <class ByteIterator>
    std::uint8_t compute_checksum(ByteIterator begin, ByteIterator end) {
        return compute_checksum(0, begin, end);
    }

    template <class ByteIterator>
    std::uint8_t compute_checksum(std::uint8_t sum_init, ByteIterator begin, ByteIterator end) {
        return compute_checksum(std::accumulate(begin, end, sum_init));
    }

    template <class ByteIterator>
    bool checksum(ByteIterator begin, ByteIterator end) {
        return (std::accumulate(begin, end, 0) & 0xff) == 0;
    }

    std::array<std::uint8_t, 2> length_and_checksum_short(std::uint8_t length) {
        return {length, compute_checksum(length)};
    }

    std::array<std::uint8_t, 3> length_and_checksum_long(std::uint16_t length) {
        const std::array<std::uint8_t, 2> bits = {std::uint8_t(length >> 8), std::uint8_t(length & 0xff)};
        return {bits[0], bits[1], compute_checksum(std::begin(bits), std::end(bits))};
    }

    std::pair<std::uint8_t, bool> check_length_checksum(std::array<std::uint8_t, 2> const &data) {
        return {data[0], checksum(std::begin(data), std::end(data))};
    }

    std::pair<std::uint16_t, bool> check_length_checksum(std::array<std::uint8_t, 3> const &data) {
        return {(std::uint16_t(data[0]) << 8) | data[1],
                checksum(std::begin(data), std::end(data))};
    }

    inline std::uint8_t host_to_pn532_command(command cmd) {
        return static_cast<std::uint8_t>(cmd);
    }

    inline command pn532_to_host_command(std::uint8_t cmd) {
        return static_cast<command>(cmd - 1);
    }
}// namespace pn532::bits

#endif//PN532_BITS_ALGO_HPP
