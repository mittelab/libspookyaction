//
// Created by Pietro Saccardi on 02/01/2021.
//

#ifndef DESFIRE_CRYPTO_ALGO_HPP
#define DESFIRE_CRYPTO_ALGO_HPP

#include "log.h"
#include "mlab/bin_data.hpp"
#include <algorithm>
#include <cstdint>
#include <iterator>
#include <utility>

namespace desfire {

    static constexpr std::array<std::uint8_t, 2> default_padding_bytes = {0x00, 0x80};

    template <class Integral>
    [[nodiscard]] std::pair<unsigned, Integral> log2_remainder(Integral n);

    template <class It>
    void lshift_sequence(It begin, It end, unsigned lshift);

    template <std::size_t BlockSize>
    [[nodiscard]] std::size_t padded_length(std::size_t size);

    inline std::size_t padded_length(std::size_t size, std::size_t block_size);

    template <std::size_t Length>
    void set_key_version(std::array<std::uint8_t, Length> &k, std::uint8_t v);

    template <std::size_t Length>
    [[nodiscard]] std::uint8_t get_key_version(std::array<std::uint8_t, Length> const &k);

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
     * @param incremental_crc If true, @p crc_fn will be called only on the new bytes being tested, using as ''init''
     *  value the previously calculated CRC value. If false, @p crc_fn is always called on the full data interval,
     *  starting at @p begin.
     * @param valid_padding_bytes An array of possible padding bytes values, by default just 0x00. Some ciphers prepend
     *  0x80 before the zeroes.
     * @note In general, for a CRC function, it should hold ''CRC(A || B, init) = CRC(B, CRC(A, init))''. If this is the
     * case, specify @p incremental_crc true. If this is not the case (e.g. you are simulating the injection of extra
     * data in between the data payload and the CRC), specify false. The behavior is pseudo code is as follows:
     * @code
     *  crc_i := crc_fn(data[0:i], init)
     *  if incremental_crc:
     *      crc_{i+1} := crc_fn(data[i+1], crc_i)
     *  else:
     *      crc_{i+1} := crc_fn(data[0:i+1], init)
     * @endcode
     * @return
     */
    template <std::size_t BlockSize, class ByteIterator, class N, class Fn, std::size_t NPaddingBytes = 2>
    std::pair<ByteIterator, bool> find_crc_tail(ByteIterator begin, ByteIterator end, Fn &&crc_fn, N init, bool incremental_crc,
                                                std::array<std::uint8_t, NPaddingBytes> const &valid_padding_bytes = default_padding_bytes);

    struct randbytes {
        std::size_t n;
        explicit randbytes(std::size_t len) : n{len} {}
    };

    static constexpr std::uint16_t crc16_init = 0x6363;
    static constexpr std::uint32_t crc32_init = 0xffffffff;

    [[nodiscard]] std::uint16_t compute_crc16(mlab::range<mlab::bin_data::const_iterator> const &data, std::uint16_t init = crc16_init);
    [[nodiscard]] std::uint32_t compute_crc32(mlab::range<mlab::bin_data::const_iterator> const &data, std::uint32_t init = crc32_init);

    [[nodiscard]] std::uint16_t compute_crc16(std::uint8_t extra_byte, std::uint16_t init = crc16_init);
    [[nodiscard]] std::uint32_t compute_crc32(std::uint8_t extra_byte, std::uint32_t init = crc32_init);

    [[nodiscard]] inline std::uint16_t compute_crc16(mlab::bin_data const &data, std::uint16_t init = crc16_init);
    [[nodiscard]] inline std::uint32_t compute_crc32(mlab::bin_data const &data, std::uint32_t init = crc32_init);
}// namespace desfire

namespace mlab {
    bin_data &operator<<(bin_data &bd, desfire::randbytes const &rndb);
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

    std::size_t padded_length(std::size_t size, std::size_t block_size) {
        if (block_size % 2 == 0) {
            return (size + block_size - 1) & -block_size;
        } else {
            const auto rem_div = std::div(long(size), long(block_size));
            return rem_div.quot * block_size + (rem_div.rem > 0 ? block_size : 0);
        }
    }

    template <std::size_t BlockSize, class ByteIterator, class N, class Fn, std::size_t NPaddingBytes>
    std::pair<ByteIterator, bool> find_crc_tail(ByteIterator begin, ByteIterator end, Fn &&crc_fn, N init,
                                                bool incremental_crc,
                                                std::array<std::uint8_t, NPaddingBytes> const &valid_padding_bytes) {
        static const auto nonzero_byte_pred = [&](std::uint8_t b) -> bool {
            return std::find(std::begin(valid_padding_bytes), std::end(valid_padding_bytes), b) == std::end(valid_padding_bytes);
        };
        const bool multiple_of_block_size = std::distance(begin, end) % BlockSize == 0;
        if (not multiple_of_block_size) {
            DESFIRE_LOGE("Cannot scan for CRC tail if data length is not a multiple of the block size.");
        }
        if (begin != end and multiple_of_block_size) {
            // Find the last nonzero byte, get and iterator to the element past that.
            // You just have to scan the last block, and in the worst case, the last non-padding byte is the first
            // byte of the last block.
            // This is achieved by reverse scanning for a nonzero byte, and getting the underlying iterator.
            // Since the reverse iterator holds an underlying iterator to the next element (in the normal traversal
            // sense), we can just get that.
            const auto rev_end = std::reverse_iterator<ByteIterator>(end);
            auto end_payload = std::find_if(rev_end, rev_end + BlockSize, nonzero_byte_pred).base();
            // Compute the crc until the supposed end of the payload
            N crc = crc_fn(begin, end_payload, init);
            while (crc != N(0) and end_payload != end) {
                if (incremental_crc) {
                    // Update the crc with one byte at a time
                    crc = crc_fn(end_payload, std::next(end_payload), crc);
                } else {
                    // Recalculate the crc on the whole new sequence
                    crc = crc_fn(begin, std::next(end_payload), init);
                }
                // Keep advancing the supposed end of the payload until end
                ++end_payload;
            }
            return {end_payload, crc == N(0)};
        }
        return {end, false};
    }

    template <class Integral>
    std::pair<unsigned, Integral> log2_remainder(Integral n) {
        static_assert(std::is_integral_v<Integral> and std::is_unsigned_v<Integral>);
        Integral mask = ~Integral(0);
        for (unsigned i = 0; i < sizeof(Integral) * 8; ++i) {
            mask >>= 1;
            if (const Integral remainder = n & mask; remainder != n) {
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

    std::uint16_t compute_crc16(mlab::bin_data const &data, std::uint16_t init) {
        return compute_crc16(data.view(), init);
    }
    std::uint32_t compute_crc32(mlab::bin_data const &data, std::uint32_t init) {
        return compute_crc32(data.view(), init);
    }


}// namespace desfire

#endif//DESFIRE_CRYPTO_ALGO_HPP
