//
// Created by Pietro Saccardi on 02/01/2021.
//

#ifndef APERTURAPORTA_CRYPTO_ALGO_HPP
#define APERTURAPORTA_CRYPTO_ALGO_HPP

#include <cstdint>
#include <utility>
#include <iterator>
#include <algorithm>

namespace desfire {

    template <class It>
    void lshift_sequence(It begin, It end, unsigned lshift);

    template <std::size_t BlockSize>
    std::size_t padded_length(std::size_t size);

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
        // Store the last successful crc and end of the payload
        ByteIterator last_payload_end = end;
        bool crc_pass = false;
        if (begin != end) {
            assert(std::distance(begin, end) % BlockSize == 0);
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

}

#endif //APERTURAPORTA_CRYPTO_ALGO_HPP
