//
// Created by Pietro Saccardi on 10/01/2021.
//

#include "desfire/crypto_algo.hpp"
#include <esp32/rom/crc.h>
#include <esp_system.h>

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

    std::uint16_t compute_crc16(mlab::range<std::uint8_t const *> data, std::uint16_t init) {
        /* @note This is correct, we need to negate the init value (0x6363, as per spec), negate the output value
         * (that is documented in ESP's CRC header), and remember to send LSB first.
         */
        return ~crc16_le(~init, std::begin(data), data.size());
    }
    std::uint32_t compute_crc32(mlab::range<std::uint8_t const *> data, std::uint32_t init) {
        /* @note This is correct, we need to negate the init value (0xffffffff, as per spec), negate the output value
         * (that is documented in ESP's CRC header), and remember to send LSB first.
         */
        return ~crc32_le(~init, std::begin(data), data.size());
    }
}// namespace desfire

namespace mlab {

    bin_data &operator<<(bin_data &bd, desfire::randbytes const &rndb) {
        const std::size_t old_size = bd.size();
        bd.resize(bd.size() + rndb.n, 0x00);
        esp_fill_random(&bd[old_size], rndb.n);
        return bd;
    }

}// namespace mlab