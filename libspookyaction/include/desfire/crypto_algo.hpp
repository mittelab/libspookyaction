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

    /**
     * Structure that can be injected into a `mlab::bin_data` to produce a sequence of random bytes.
     * @code
     * mlab::bin_data d;
     * d << randbytes(24); // Generate 24 random bytes
     * @endcode
     */
    struct randbytes {
        std::size_t n;//!< Number of random bytes to generate
        /**
         * Marks that @p len random bytes have to be generated.
         */
        constexpr explicit randbytes(std::size_t len) : n{len} {}
    };

    static constexpr std::uint16_t crc16_init = 0x6363;    //!< Default initialization value used in Desfire for a CRC16.
    static constexpr std::uint32_t crc32_init = 0xffffffff;//!< Default initialization value used in Desfire for a CRC32.

    /**
     * @param data Sequence for which to compute the CRC (or a single byte).
     * @param init Initial value for the CRC
     * @return `init + CRC(data)`.
     */
    [[nodiscard]] std::uint16_t compute_crc16(mlab::range<std::uint8_t const *> data, std::uint16_t init = crc16_init);
    /**
     * @copydoc compute_crc16
     */
    [[nodiscard]] std::uint32_t compute_crc32(mlab::range<std::uint8_t const *> data, std::uint32_t init = crc32_init);
    /**
     * @copydoc compute_crc16
     */
    [[nodiscard]] inline std::uint16_t compute_crc16(mlab::bin_data const &data, std::uint16_t init = crc16_init);
    /**
     * @copydoc compute_crc16
     */
    [[nodiscard]] inline std::uint32_t compute_crc32(mlab::bin_data const &data, std::uint32_t init = crc32_init);
    /**
     * @copydoc compute_crc16
     */
    [[nodiscard]] std::uint16_t compute_crc16(std::uint8_t data, std::uint16_t init = crc16_init);
    /**
     * @copydoc compute_crc16
     */
    [[nodiscard]] std::uint32_t compute_crc32(std::uint8_t data, std::uint32_t init = crc32_init);

    /**
     * @brief Performs a left shift across a sequence of integers, where the bits carry over across elements.
     * E.g. The sequence 0x00 0xff shifted by one is 0x01 0xfe.
     * @tparam It A forward iterator yielding an unsigned integer type.
     * @param begin Iterator to the first element of the sequence.
     * @param end Iterator to past-the-end of the sequence.
     * @param lshift Amount of bits to left shift.
     */
    template <class It>
    void lshift_sequence(It begin, It end, unsigned lshift);

    /**
     * @brief Unpacks the byte @p v, bit by bit, onto the least significant bit of each element of @p c.
     * This will overwrite the lsb of the first 8 elements of @p c.
     * @tparam Container Any container that is range-enumerable of `std::uint8_t`.
     * @param c Container of the key body.
     * @param v Version byte.
     */
    template <class Container>
    void set_key_version(Container &c, std::uint8_t v);

    /**
     * Unpacks all the least significant bits in the elements of @p c, in order, into a version byte.
     * The return value is made up by the sequence of the lsb of the first 8 elements of @p c.
     * @tparam Container Any container that is range-enumerable of `std::uint8_t`.
     * @param c Container of the key body.
     * @return The least significant bits, in order.
     */
    template <class Container>
    [[nodiscard]] std::uint8_t get_key_version(Container const &c);

    /**
     * @brief Finds the last point in a sequence where the CRC checks out and only @p valid_padding_bytes follow.
     * This method is used to identify the location of a CRC code in a sequence of the type `[message] [crc] [padding]`.
     * More specifically, this finds the last point in the sequence where a CRC is valid on the previous message and only
     * padding bytes follow (at most `@p block_size - 1` padding bytes).
     * This reverses the operation of appending a CRC and then padding to a multiple of @p block size.
     * @tparam ByteIterator A bidirectional iterator with `std::uint8_t` as value type, which supports reversing, i.e. not a generator.
     * @tparam N A unsigned integer size matching the crc size, e.g. ''std::uint32_t'' for a CRC32.
     * @tparam Fn Must match signature ''N crc_fn(ByteIterator b, ByteIterator e, N init)''.
     * @tparam BytesContainer Any byte container, possibly small and fast, since every element will be checked.
     * @param begin Iterator to the beginning of the byte sequence.
     * @param end Iterator past-the-end of the byte sequence.
     * @param crc_fn Function that computes the CRC of a subsequence of bytes, starting with a given initial CRC value.
     *  This could be called to compute the CRC incrementally on adjacent subsequences, if @p incremental_crc is true.
     * @param init Initial value for the CRC.
     * @param block_size Padding block size: this represent how long at most a sequence of padding bytes can be, and corresponds
     *  to the maximum number of bytes we need to check for a valid CRC. In other words, the `[message] [crc]` sequence, must have been
     *  padded to the next multiple of @p block_size.
     * @param incremental_crc If true, @p crc_fn will be called only on the new bytes being tested, using as ''init''
     *  value the previously calculated CRC value. If false, @p crc_fn is always called on the full data interval,
     *  starting at @p begin.
     * @param valid_padding_bytes An array of possible padding bytes values, by default just 0x00 and 0x80. Some ciphers prepend
     *  0x80 before the zeroes.
     * @note In general, for a CRC function, it should hold ''CRC(A || B, init) = CRC(B, CRC(A, init))''. If this is the
     *  case, specify @p incremental_crc true. If this is not the case (e.g. you are simulating the injection of extra
     *  data in between the data payload and the CRC), specify false. The behavior is pseudo code is as follows:
     * @code{.unparsed}
     *  crc_i := crc_fn(data[0:i], init)
     *  if incremental_crc:
     *      crc_{i+1} := crc_fn(data[i+1], crc_i)
     *  else:
     *      crc_{i+1} := crc_fn(data[0:i+1], init)
     * @endcode
     * @return An iterator past-the-end of `[message]`, i.e. an iterator to the first CRC byte (the last one of such iterators if multiple
     *  positions in the sequence have this property), and a boolean specifying whether the CRC checks out.
     */
    template <class ByteIterator, class N, class Fn, class BytesContainer>
    [[nodiscard]] std::pair<ByteIterator, bool> find_crc_tail(ByteIterator begin, ByteIterator end, Fn &&crc_fn, N init, std::size_t block_size,
                                                              bool incremental_crc, BytesContainer const &valid_padding_bytes);
    /**
     * @brief Refer to @ref find_crc_tail.
     * In this case the padding bytes default to 0x00 and 0x80.
     */
    template <class ByteIterator, class N, class Fn>
    [[nodiscard]] std::pair<ByteIterator, bool> find_crc_tail(ByteIterator begin, ByteIterator end, Fn &&crc_fn, N init, std::size_t block_size,
                                                              bool incremental_crc);

}// namespace desfire

namespace mlab {
    /**
     * @addtogroup IOOperators
     * @{
     */
    bin_data &operator<<(bin_data &bd, desfire::randbytes const &rndb);
    /**
     * @}
     */
}// namespace mlab

namespace desfire {

    template <class It>
    void lshift_sequence(It begin, It end, unsigned lshift) {
        using value_type = typename std::iterator_traits<It>::value_type;
        static_assert(std::is_integral_v<value_type> and std::is_unsigned_v<value_type>);
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

    template <class ByteIterator, class N, class Fn, class BytesContainer>
    std::pair<ByteIterator, bool> find_crc_tail(ByteIterator begin, ByteIterator end, Fn &&crc_fn, N init,
                                                std::size_t block_size, bool incremental_crc,
                                                BytesContainer const &valid_padding_bytes) {
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

    template <class ByteIterator, class N, class Fn>
    std::pair<ByteIterator, bool> find_crc_tail(ByteIterator begin, ByteIterator end, Fn &&crc_fn, N init, std::size_t block_size,
                                                bool incremental_crc) {
        static constexpr std::array<std::uint8_t, 2> default_padding_bytes = {0x00, 0x80};
        return find_crc_tail(begin, end, std::forward<Fn>(crc_fn), init, block_size, incremental_crc, default_padding_bytes);
    }

    template <class Container>
    void set_key_version(Container &c, std::uint8_t v) {
        std::uint_fast8_t i = 0;
        for (auto &b : c) {
            static_assert(std::is_same_v<decltype(b), std::uint8_t &>);
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
