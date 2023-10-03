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

    namespace impl {
        template <unsigned Bits>
        auto get_uint_exact();

        template <unsigned Bits>
        auto get_uint_least();
    }// namespace impl

    template <unsigned Bits>
    using uint_least_t = decltype(impl::get_uint_least<Bits>());

    template <unsigned Bits>
    using uint_exact_t = decltype(impl::get_uint_exact<Bits>());

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
    template <class Num, std::size_t NBytes>
    [[nodiscard]] constexpr Num lsb_unsigned_decode(std::array<std::uint8_t, NBytes> b);

    template <class Num, std::size_t NBytes, std::size_t I = NBytes - 1>
    [[nodiscard]] constexpr Num msb_unsigned_decode(std::array<std::uint8_t, NBytes> b);

    template <class Num, std::size_t NBytes>
    [[nodiscard]] constexpr std::array<std::uint8_t, NBytes> lsb_unsigned_encode(Num n);

    template <class Num, std::size_t NBytes>
    [[nodiscard]] constexpr std::array<std::uint8_t, NBytes> msb_unsigned_encode(Num n);
    /**
     * @}
     */

}// namespace mlab

namespace mlab {

    namespace impl {
        template <unsigned Bits>
        auto get_uint_exact() {
            if constexpr (Bits == 8) {
                return std::uint8_t{};
            } else if constexpr (Bits == 16) {
                return std::uint16_t{};
            } else if constexpr (Bits == 32) {
                return std::uint32_t{};
            } else if constexpr (Bits == 64) {
                return std::uint64_t{};
            } else {
                static_assert(Bits % 8 == 0 and Bits > 0 and Bits <= 64);
            }
        }

        template <unsigned Bits>
        auto get_uint_least() {
            if constexpr (Bits <= 8) {
                return std::uint8_t{};
            } else if constexpr (Bits <= 16) {
                return std::uint16_t{};
            } else if constexpr (Bits <= 32) {
                return std::uint32_t{};
            } else if constexpr (Bits <= 64) {
                return std::uint64_t{};
            } else {
                static_assert(Bits > 0 and Bits <= 64);
            }
        }
    }// namespace impl

    template <class Num, std::size_t NBytes>
    constexpr Num lsb_unsigned_decode(std::array<std::uint8_t, NBytes> b) {
        static_assert(std::is_integral_v<Num> and std::is_unsigned_v<Num> and sizeof(Num) >= NBytes, "Use a sufficiently large unsigned integer.");
        Num n{};
        for (std::size_t i = 0; i < NBytes; ++i) {
            n |= Num(b[i]) << (i * 8);
        }
        return n;
    }

    template <class Num, std::size_t NBytes>
    constexpr Num msb_unsigned_decode(std::array<std::uint8_t, NBytes> b) {
        static_assert(std::is_integral_v<Num> and std::is_unsigned_v<Num> and sizeof(Num) >= NBytes, "Use a sufficiently large unsigned integer.");
        Num n{};
        for (std::size_t i = 0; i < NBytes; ++i) {
            n <<= 8;
            n |= Num(b[i]);
        }
        return n;
    }

    template <class Num, std::size_t NBytes>
    constexpr std::array<std::uint8_t, NBytes> lsb_unsigned_encode(Num n) {
        static_assert(std::is_integral_v<Num> and std::is_unsigned_v<Num> and sizeof(Num) >= NBytes, "Use a sufficiently large unsigned integer.");
        std::array<std::uint8_t, NBytes> a{};
        for (std::size_t i = 0; i < NBytes; ++i, n >>= 8) {
            a[i] = std::uint8_t(n & 0xff);
        }
        return a;
    }

    template <class Num, std::size_t NBytes>
    constexpr std::array<std::uint8_t, NBytes> msb_unsigned_encode(Num n) {
        static_assert(std::is_integral_v<Num> and std::is_unsigned_v<Num> and sizeof(Num) >= NBytes, "Use a sufficiently large unsigned integer.");
        std::array<std::uint8_t, NBytes> a{};
        for (std::size_t i = 0; i < NBytes; ++i, n >>= 8) {
            a[NBytes - i - 1] = std::uint8_t(n & 0xff);
        }
        return a;
    }

    template <byte_order Order, unsigned Bits, class Num>
    std::array<std::uint8_t, Bits / 8> encode(Num n) {
        static_assert(sizeof(Num) >= Bits / 8, "Use a sufficiently large number.");
        static_assert(std::is_integral_v<Num> or std::is_floating_point_v<Num>);
        if constexpr (std::is_floating_point_v<Num>) {
            using UNum = uint_exact_t<sizeof(Num) * 8>;
            return encode<Order, Bits, UNum>(*reinterpret_cast<UNum const *>(&n));
        } else if constexpr (std::is_signed_v<Num>) {
            using UNum = std::make_unsigned_t<Num>;
            return encode<Order, Bits, UNum>(*reinterpret_cast<UNum const *>(&n));
        } else {
            if constexpr (Order == byte_order::lsb_first) {
                return lsb_unsigned_encode<Num, Bits / 8>(n);
            } else {
                return msb_unsigned_encode<Num, Bits / 8>(n);
            }
        }
    }

    template <byte_order Order, unsigned Bits, class Num>
    Num decode(std::array<std::uint8_t, Bits / 8> const &b) {
        static_assert(sizeof(Num) >= Bits / 8, "Use a sufficiently large number.");
        static_assert(std::is_integral_v<Num> or std::is_floating_point_v<Num>);
        Num n{};
        if constexpr (std::is_floating_point_v<Num>) {
            using UNum = uint_exact_t<sizeof(Num) * 8>;
            *reinterpret_cast<UNum *>(&n) = decode<Order, Bits, UNum>(b);
        } else if constexpr (std::is_signed_v<Num>) {
            using UNum = std::make_unsigned_t<Num>;
            *reinterpret_cast<UNum *>(&n) = decode<Order, Bits, UNum>(b);
        } else {
            if constexpr (Order == byte_order::lsb_first) {
                return lsb_unsigned_decode<Num, Bits / 8>(b);
            } else {
                return msb_unsigned_decode<Num, Bits / 8>(b);
            }
        }
        return n;
    }

}// namespace mlab

#endif//MLAB_BYTE_ORDER_HPP
