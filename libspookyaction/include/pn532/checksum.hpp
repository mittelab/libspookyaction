//
// Created by Pietro Saccardi on 22/12/2020.
//

#ifndef PN532_BITS_ALGO_HPP
#define PN532_BITS_ALGO_HPP

#include <array>
#include <cstdint>
#include <numeric>
#include <pn532/bits.hpp>

namespace pn532 {

    /**
     * @brief Computes the checksum of a single byte.
     * I.e., `~byte+1`.
     */
    [[nodiscard]] inline std::uint8_t compute_checksum(std::uint8_t byte);

    /**
     * @brief Computes the checksum of a sequence of bytes.
     * @tparam ByteIterator Any forward iterator type that yields `std::uint8_t`.
     * @param begin Iterator pointing to the first element.
     * @param end Past-the-end iterator.
     * @return The checksum, i.e. @f$ 1+\neg\sum_{i=\text{begin}}^{\text{end}} *i @f$
     */
    template <class ByteIterator>
    [[nodiscard]] std::uint8_t compute_checksum(ByteIterator begin, ByteIterator end);

    /**
     * @brief Incrementally computes the checksum of a sequence of bytes.
     * @tparam ByteIterator Any forward iterator type that yields `std::uint8_t`.
     * @param sum_init Initial value of the sum (for incremental computation).
     * @param begin Iterator pointing to the first element.
     * @param end Past-the-end iterator.
     * @return The checksum, i.e. @f$ \text{sum_init}+1+\neg\sum_{i=\text{begin}}^{\text{end}} *i @f$
     */
    template <class ByteIterator>
    [[nodiscard]] std::uint8_t compute_checksum(std::uint8_t sum_init, ByteIterator begin, ByteIterator end);

    /**
     * @brief Checks that the given sequence of bytes sums up to zero.
     * When the checksum byte (computed e.g. with @ref compute_checksum) is appended to a sequence, the whole
     * sequence sums up to zero. This function thus expects the sequence to end with the checksum byte.
     * @tparam ByteIterator Any forward iterator type that yields `std::uint8_t`.
     * @param begin Iterator pointing to the first element.
     * @param end Past-the-end iterator.
     * @return True if and only if the sequence sums to zero.
     */
    template <class ByteIterator>
    [[nodiscard]] bool checksum(ByteIterator begin, ByteIterator end);

#ifndef DOXYGEN_SHOULD_SKIP_THIS
    namespace bits {

        /**
         * @defgroup LengthChecksum Length and checksum routines
         * @addtogroup LengthChecksum
         * These functions are helpers that compute the checksum of the length of a PN532 packet.
         * @{
         */
        [[nodiscard]] inline std::array<std::uint8_t, 2> length_and_checksum_short(std::uint8_t length);

        [[nodiscard]] inline std::array<std::uint8_t, 3> length_and_checksum_long(std::uint16_t length);

        [[nodiscard]] inline std::pair<std::uint8_t, bool> check_length_checksum(std::array<std::uint8_t, 2> const &data);

        [[nodiscard]] inline std::pair<std::uint16_t, bool> check_length_checksum(std::array<std::uint8_t, 3> const &data);

        /**
         * @}
         */

        /**
         * @defgroup HostPN532Conv Host/PN532 command code conversion
         * @addtogroup HostPN532Conv
         * @{
         */
        [[nodiscard]] inline std::uint8_t host_to_pn532_command(command_code cmd);

        [[nodiscard]] inline command_code pn532_to_host_command(std::uint8_t cmd);
        /**
         * @}
         */
    }// namespace bits
#endif
}// namespace pn532

namespace pn532 {

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

    namespace bits {
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

        std::uint8_t host_to_pn532_command(command_code cmd) {
            return static_cast<std::uint8_t>(cmd);
        }

        command_code pn532_to_host_command(std::uint8_t cmd) {
            return static_cast<command_code>(cmd - 1);
        }
    }// namespace bits
}// namespace pn532

#endif//PN532_BITS_ALGO_HPP
