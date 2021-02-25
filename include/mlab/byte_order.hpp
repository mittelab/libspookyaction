//
// Created by spak on 2/25/21.
//

#ifndef MLAB_BYTE_ORDER_HPP
#define MLAB_BYTE_ORDER_HPP

#include <cstdint>
#include <tuple>
#include <type_traits>

namespace mlab {

    enum struct byte_order {
        msb_first,
        lsb_first
    };


    template <unsigned Bits>
    using uint_least_t = typename std::tuple_element<Bits / 8 - 1, std::tuple<std::uint8_t, std::uint16_t, std::uint32_t, std::uint32_t>>::type;

    template <unsigned Bits>
    using int_least_t [[maybe_unused]] = std::make_signed_t<uint_least_t<Bits>>;

    template <byte_order Order, unsigned Bits, class Num>
    std::array<std::uint8_t, Bits / 8> encode(Num n);

    template <byte_order Order, unsigned Bits, class Num>
    Num decode(std::array<std::uint8_t, Bits / 8> const &b);

    /**
     * @note There is apparently no better way to obtain this in C++14
     */
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    static constexpr byte_order local_byte_order = byte_order::msb_first;
#elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    static constexpr byte_order local_byte_order = byte_order::lsb_first;
#endif

    /**
     * @addtogroup RawConversion
     * Lower level functions which operate on an arbitrary unsigned integer.
     * @{
     */
    template <class Num, std::size_t NBytes, std::size_t I = NBytes - 1>
    void lsb_unsigned_decode(std::array<std::uint8_t, NBytes> const &b, Num &n);

    template <class Num, std::size_t NBytes, std::size_t I = NBytes - 1>
    void msb_unsigned_decode(std::array<std::uint8_t, NBytes> const &b, Num &n);

    template <class Num, std::size_t NBytes, std::size_t I = 0>
    void lsb_unsigned_encode(Num n, std::array<std::uint8_t, NBytes> &b);

    template <class Num, std::size_t NBytes, std::size_t I = 0>
    void msb_unsigned_encode(Num n, std::array<std::uint8_t, NBytes> &b);
    /**
     * @}
     */

}// namespace mlab

namespace mlab {
    template <class Num, std::size_t NBytes, std::size_t I>
    void lsb_unsigned_decode(std::array<std::uint8_t, NBytes> const &b, Num &n) {
        static_assert(std::is_integral_v<Num> and std::is_unsigned_v<Num> and sizeof(Num) >= NBytes, "Use a sufficiently large unsigned integer.");
        static_assert(I < NBytes);
        if constexpr (I > 0) {
            lsb_unsigned_decode<Num, NBytes, I - 1>(b, n);
        } else {
            n = Num(0);
        }
        n |= Num(b[I]) << (I * 8);
    }

    template <class Num, std::size_t NBytes, std::size_t I>
    void msb_unsigned_decode(std::array<std::uint8_t, NBytes> const &b, Num &n) {
        static_assert(std::is_integral_v<Num> and std::is_unsigned_v<Num> and sizeof(Num) >= NBytes, "Use a sufficiently large unsigned integer.");
        static_assert(I < NBytes);
        if constexpr (I > 0) {
            msb_unsigned_decode<Num, NBytes, I - 1>(b, n);
        } else {
            n = Num(0);
        }
        n = (n << 8) | Num(b[I]);
    }

    template <class Num, std::size_t NBytes, std::size_t I>
    void lsb_unsigned_encode(Num n, std::array<std::uint8_t, NBytes> &b) {
        static_assert(std::is_integral_v<Num> and std::is_unsigned_v<Num> and sizeof(Num) >= NBytes, "Use a sufficiently large unsigned integer.");
        static_assert(I < NBytes);
        b[I] = std::uint8_t(n & 0xff);
        if constexpr (I + 1 < NBytes) {
            lsb_unsigned_encode<Num, NBytes, I + 1>(n >> 8, b);
        }
    }

    template <class Num, std::size_t NBytes, std::size_t I>
    void msb_unsigned_encode(Num n, std::array<std::uint8_t, NBytes> &b) {
        static_assert(std::is_integral_v<Num> and std::is_unsigned_v<Num> and sizeof(Num) >= NBytes, "Use a sufficiently large unsigned integer.");
        static_assert(I < NBytes);
        b[NBytes - I - 1] = std::uint8_t(n & 0xff);
        if constexpr (I + 1 < NBytes) {
            msb_unsigned_encode<Num, NBytes, I + 1>(n >> 8, b);
        }
    }

    template <byte_order Order, unsigned Bits, class Num>
    std::array<std::uint8_t, Bits / 8> encode(Num n) {
        static_assert(std::is_integral_v<Num> and sizeof(Num) >= Bits / 8, "Use a sufficiently large (un)signed integer.");
        if constexpr (std::is_signed_v<Num>) {
            using UNum = std::make_unsigned_t<Num>;
            return encode<Order, Bits, UNum>(*reinterpret_cast<UNum const *>(&n));
        } else {
            std::array<std::uint8_t, Bits / 8> b{};
            if constexpr (Order == byte_order::lsb_first) {
                lsb_unsigned_encode(n, b);
            } else {
                msb_unsigned_encode(n, b);
            }
            return b;
        }
    }

    template <byte_order Order, unsigned Bits, class Num>
    Num decode(std::array<std::uint8_t, Bits / 8> const &b) {
        static_assert(std::is_integral_v<Num> and sizeof(Num) >= Bits / 8, "Use a sufficiently large (un)signed integer.");
        Num n{};
        if constexpr (std::is_signed_v<Num>) {
            using UNum = std::make_unsigned_t<Num>;
            *reinterpret_cast<UNum *>(&n) = decode<Order, Bits, UNum>(b);
        } else {
            if constexpr (Order == byte_order::lsb_first) {
                lsb_unsigned_decode(b, n);
            } else {
                msb_unsigned_decode(b, n);
            }
        }
        return n;
    }

}// namespace mlab

#endif//MLAB_BYTE_ORDER_HPP
