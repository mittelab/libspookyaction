//
// Created by Pietro Saccardi on 10/01/2021.
//

#include <rom/crc.h>
#include "desfire/crypto_algo.hpp"

namespace desfire {

    std::uint16_t compute_crc16n(mlab::range<mlab::bin_data::const_iterator> data, std::uint16_t init) {
        /* @note This is correct, we need to negate the init value (0x6363, as per spec), negate the output value
         * (that is documented in ESP's CRC header), and remember to send LSB first.
         */
        return ~crc16_le(~init, data.data(), data.size());
    }
    std::uint32_t compute_crc32n(mlab::range<mlab::bin_data::const_iterator> data, std::uint32_t init) {
        /* @note This is correct, we need to negate the init value (0xffffffff, as per spec), negate the output value
         * (that is documented in ESP's CRC header), and remember to send LSB first.
         */
        return ~crc32_le(~init, data.data(), data.size());
    }

    std::array<std::uint8_t, 2> compute_crc16(mlab::range<mlab::bin_data::const_iterator> data, std::uint16_t init) {
        const std::uint16_t word = compute_crc16n(data, init);
        return {std::uint8_t(word & 0xff), std::uint8_t(word >> 8)};
    }
    std::array<std::uint8_t, 4> compute_crc32(mlab::range<mlab::bin_data::const_iterator> data, std::uint32_t init) {
        const std::uint32_t dword = compute_crc32n(data, init);
        return {
                std::uint8_t(dword & 0xff),
                std::uint8_t((dword >> 8) & 0xff),
                std::uint8_t((dword >> 16) & 0xff),
                std::uint8_t((dword >> 24) & 0xff)
        };
    }
}
