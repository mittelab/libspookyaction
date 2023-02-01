//
// Created by Pietro Saccardi on 02/01/2021.
//

#ifndef DESFIRE_CRYPTO_ALGO_HPP
#define DESFIRE_CRYPTO_ALGO_HPP

#include <algorithm>
#include <cstdint>
#include <desfire/log.h>
#include <iterator>
#include <mlab/bin_data.hpp>
#include <mlab/mathutils.hpp>
#include <utility>

namespace desfire {

    static constexpr std::array<std::uint8_t, 2> default_padding_bytes = {0x00, 0x80};

    template <class It>
    void lshift_sequence(It begin, It end, unsigned lshift);

    template <class Container>
    void set_key_version(Container &c, std::uint8_t v);

    template <class Container>
    [[nodiscard]] std::uint8_t get_key_version(Container const &c);

    /**
     *
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
    template <class ByteIterator, class N, class Fn, std::size_t NPaddingBytes = 2>
    std::pair<ByteIterator, bool> find_crc_tail(ByteIterator begin, ByteIterator end, Fn &&crc_fn, N init, std::size_t block_size,
                                                bool incremental_crc, std::array<std::uint8_t, NPaddingBytes> const &valid_padding_bytes = default_padding_bytes);

    struct randbytes {
        std::size_t n;
        explicit randbytes(std::size_t len) : n{len} {}
    };

    static constexpr std::uint16_t crc16_init = 0x6363;
    static constexpr std::uint32_t crc32_init = 0xffffffff;

    [[nodiscard]] std::uint16_t compute_crc16(mlab::range<std::uint8_t const *> data, std::uint16_t init = crc16_init);
    [[nodiscard]] std::uint32_t compute_crc32(mlab::range<std::uint8_t const *> data, std::uint32_t init = crc32_init);

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

    template <class ByteIterator, class N, class Fn, std::size_t NPaddingBytes>
    std::pair<ByteIterator, bool> find_crc_tail(ByteIterator begin, ByteIterator end, Fn &&crc_fn, N init,
                                                std::size_t block_size, bool incremental_crc,
                                                std::array<std::uint8_t, NPaddingBytes> const &valid_padding_bytes) {
        static const auto nonzero_byte_pred = [&](std::uint8_t b) -> bool {
            return std::find(std::begin(valid_padding_bytes), std::end(valid_padding_bytes), b) == std::end(valid_padding_bytes);
        };
        const bool multiple_of_block_size = std::distance(begin, end) % block_size == 0;
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
            auto end_payload = std::find_if(rev_end, rev_end + block_size, nonzero_byte_pred).base();
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

    template <class Container>
    void set_key_version(Container &c, std::uint8_t v) {
        std::uint_fast8_t i = 0;
        for (std::uint8_t &b : c) {
            if (++i > 8) {
                break;
            }
            b = (b & 0b11111110) | (v >> 7);
            v <<= 1;
        }
    }

    template <class Container>
    std::uint8_t get_key_version(Container const &c) {
        std::uint8_t v = 0x0;
        std::uint_fast8_t i = 0;
        for (std::uint8_t b : c) {
            if (++i > 8) {
                break;
            }
            v = (v << 1) | (b & 0b00000001);
        }
        return v;
    }

    std::uint16_t compute_crc16(mlab::bin_data const &data, std::uint16_t init) {
        return compute_crc16(data.data_view(), init);
    }
    std::uint32_t compute_crc32(mlab::bin_data const &data, std::uint32_t init) {
        return compute_crc32(data.data_view(), init);
    }


}// namespace desfire

#endif//DESFIRE_CRYPTO_ALGO_HPP
