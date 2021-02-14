//
// Created by Pietro Saccardi on 10/01/2021.
//

#include "desfire/crypto_algo.hpp"
#include <esp32/rom/crc.h>

namespace desfire {


    std::uint16_t compute_crc16(std::uint8_t extra_byte, std::uint16_t init) {
        /* @note This is correct, we need to negate the init value (0x6363, as per spec), negate the output value
         * (that is documented in ESP's CRC header), and remember to send LSB first.
         */
        return ~crc16_le(~init, &extra_byte, 1);
    }

    std::uint32_t compute_crc32(std::uint8_t extra_byte, std::uint32_t init) {
        /* @note This is correct, we need to negate the init value (0xffffffff, as per spec), negate the output value
         * (that is documented in ESP's CRC header), and remember to send LSB first.
         */
        return ~crc32_le(~init, &extra_byte, 1);
    }

    std::uint16_t compute_crc16(mlab::range<mlab::bin_data::const_iterator> const &data, std::uint16_t init) {
        /* @note This is correct, we need to negate the init value (0x6363, as per spec), negate the output value
         * (that is documented in ESP's CRC header), and remember to send LSB first.
         */
        return ~crc16_le(~init, data.data(), data.size());
    }
    std::uint32_t compute_crc32(mlab::range<mlab::bin_data::const_iterator> const &data, std::uint32_t init) {
        /* @note This is correct, we need to negate the init value (0xffffffff, as per spec), negate the output value
         * (that is documented in ESP's CRC header), and remember to send LSB first.
         */
        return ~crc32_le(~init, data.data(), data.size());
    }
}// namespace desfire
