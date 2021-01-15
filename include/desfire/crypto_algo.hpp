//
// Created by Pietro Saccardi on 02/01/2021.
//

#ifndef DESFIRE_CRYPTO_ALGO_HPP
#define DESFIRE_CRYPTO_ALGO_HPP

#include <cstdint>
#include <utility>
#include <iterator>
#include <algorithm>
#include <esp_system.h>
#include "mlab/bin_data.hpp"
#include "log.h"

namespace desfire {


    template <class Integral, class = typename std::enable_if<std::is_integral<Integral>::value and std::is_unsigned<Integral>::value>::type>
    std::pair<unsigned, Integral> log2_remainder(Integral n);

    template <class It>
    void lshift_sequence(It begin, It end, unsigned lshift);

    template <std::size_t BlockSize>
    std::size_t padded_length(std::size_t size);

    template <std::size_t Length>
    void set_key_version(std::array<std::uint8_t, Length> &k, std::uint8_t v);

    template <std::size_t Length>
    std::uint8_t get_key_version(std::array<std::uint8_t, Length> const &k);

    /**
     *
     * @tparam BlockSize
     * @tparam ByteIterator
     * @tparam N A unsigned integer size matching the crc size, e.g. ''std::uint32_t'' for a CRC32.
     * @tparam Fn Must match signature ''N crc_fn(ByteIterator b, ByteIterator e, N init)''.
     * @param begin
     * @param end
     * @param crc_fn
     * @param init
     * @return
     */
    template <std::size_t BlockSize, class ByteIterator, class N, class Fn>
    static std::pair<ByteIterator, bool> find_crc_tail(ByteIterator begin, ByteIterator end, Fn &&crc_fn, N init);

    struct randbytes {
        std::size_t n;
        explicit randbytes(std::size_t len) : n{len} {}
    };

    static constexpr std::uint16_t crc16_init = 0x6363;
    static constexpr std::uint32_t crc32_init = 0xffffffff;

    std::array<std::uint8_t, 2> compute_crc16(mlab::range<mlab::bin_data::const_iterator> data, std::uint16_t init = crc16_init);
    std::array<std::uint8_t, 4> compute_crc32(mlab::range<mlab::bin_data::const_iterator> data, std::uint32_t init = crc32_init);
    std::uint16_t compute_crc16n(mlab::range<mlab::bin_data::const_iterator> data, std::uint16_t init = crc16_init);
    std::uint32_t compute_crc32n(mlab::range<mlab::bin_data::const_iterator> data, std::uint32_t init = crc32_init);
}

namespace mlab {
    inline bin_data &operator<<(bin_data &bd, desfire::randbytes const &rndb);
}

namespace desfire {

    template <class It>
    void lshift_sequence(It begin, It end, unsigned lshift) {
        using value_type = typename std::iterator_traits<It>::value_type;
        static constexpr unsigned value_nbits = sizeof(value_type) * 8;
        const unsigned complementary_rshift = value_nbits - std::min(value_nbits, lshift);
        if (begin != end) {
            It prev = begin++;
            for (; begin != end; prev = begin++) {
                *prev = ((*prev) << lshift) | ((*begin) >> complementary_rshift);
            }
            *prev <<= lshift;
        }
    }

    template <std::size_t BlockSize>
    std::size_t padded_length(std::size_t size) {
        static_assert(BlockSize % 2 == 0, "This version works just with powers of two.");
        return (size + BlockSize - 1) & -BlockSize;
    }

    template <std::size_t BlockSize, class ByteIterator, class N, class Fn>
    static std::pair<ByteIterator, bool> find_crc_tail(ByteIterator begin, ByteIterator end, Fn &&crc_fn, N init) {
        static const auto nonzero_byte_pred = [](std::uint8_t b) -> bool { return b != 0; };
        const bool multiple_of_block_size = std::distance(begin, end) % BlockSize == 0;
        if (not multiple_of_block_size) {
            DESFIRE_LOGE("Cannot scan for CRC tail if data length is not a multiple of the block size.");
        }
        // Store the last successful crc and end of the payload
        ByteIterator last_payload_end = end;
        bool crc_pass = false;
        if (begin != end and multiple_of_block_size) {
            // Find the last nonzero byte, get and iterator to the element past that.
            // You just have to scan the last block, and in the worst case, the last non-padding byte is the first
            // byte of the last block.
            // This is achieved by reverse scanning for a nonzero byte, and getting the underlying iterator.
            // Since the reverse iterator holds an underlying iterator to the next element (in the normal traversal
            // sense), we can just get that.
            const auto rev_end = std::reverse_iterator<ByteIterator>(end);
            auto end_payload = std::find_if(rev_end, rev_end + BlockSize, nonzero_byte_pred).base();
            for (   // Compute the crc until the supposed end of the payload
                    N crc = crc_fn(begin, end_payload, init);
                // Keep advancing the supposed end of the payload until end
                    end_payload != end;
                // Update the crc with one byte at a time
                    crc = crc_fn(end_payload, std::next(end_payload), crc), ++end_payload
                    ) {
                if (crc == N(0)) {
                    // This is a valid end of the payload with a successful crc check
                    last_payload_end = end_payload;
                    crc_pass = true;
                }
            }
        }
        return {last_payload_end, crc_pass};
    }

    template <class Integral, class>
    std::pair<unsigned, Integral> log2_remainder(Integral n) {
        Integral mask = ~Integral{0};
        for (unsigned i = 0; i < sizeof(Integral) * 8; ++i) {
            mask >>= 1;
            const Integral remainder = n & mask;
            if (remainder != n) {
                return {sizeof(Integral) * 8 - i - 1, remainder};
            }
        }
        return {0, n};
    }


    template <std::size_t Length>
    void set_key_version(std::array<std::uint8_t, Length> &k, std::uint8_t v) {
        for (auto &b : k) {
            b = (b & 0b11111110) | (v >> 7);
            v <<= 1;
        }
    }

    template <std::size_t Length>
    std::uint8_t get_key_version(std::array<std::uint8_t, Length> const &k) {
        std::uint8_t v = 0x0;
        for (std::size_t i = 0; i < std::min(Length, 8u); ++i) {
            v = (v << 1) | (k[i] & 0b00000001);
        }
        return v;
    }



}
namespace mlab {

    bin_data &operator<<(bin_data &bd, desfire::randbytes const &rndb) {
        const std::size_t old_size = bd.size();
        bd.resize(bd.size() + rndb.n, 0x00);
        esp_fill_random(&bd[old_size], rndb.n);
        return bd;
    }

}

#endif //DESFIRE_CRYPTO_ALGO_HPP
