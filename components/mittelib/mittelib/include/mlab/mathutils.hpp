//
// Created by spak on 2/1/23.
//

#ifndef MLAB_MATHUTILS_HPP
#define MLAB_MATHUTILS_HPP

namespace mlab {

    template <class N>
    [[nodiscard]] constexpr N next_multiple(N n, N d);

    template <class N>
    [[nodiscard]] constexpr std::pair<N, N> log2_remainder(N n);
}// namespace mlab

namespace mlab {

    template <class N>
    constexpr N next_multiple(N n, N d) {
        static_assert(std::is_integral_v<N>);
        if (d % 2 == 0) {
            return (n + d - 1) & -d;
        } else {
            return (n / d) * d + ((n % d) > 0 ? d : 0);
        }
    }

    template <class N>
    constexpr std::pair<N, N> log2_remainder(N n) {
        static_assert(std::is_integral_v<N> and std::is_unsigned_v<N>);
        N mask = ~N(0);
        for (N i = 0; i < sizeof(N) * 8; ++i) {
            mask >>= 1;
            if (const N remainder = n & mask; remainder != n) {
                return {sizeof(N) * 8 - i - 1, remainder};
            }
        }
        return {0, n};
    }
}// namespace mlab

#endif//MLAB_MATHUTILS_HPP
