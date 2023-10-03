//
// Created by spak on 7/14/23.
//

#ifndef MLAB_TYPE_NAME_HPP
#define MLAB_TYPE_NAME_HPP

#include <algorithm>
#include <string>
#include <string_view>

namespace mlab {

    struct null_terminated_tag {
    } constexpr null_terminated{};

    template <std::size_t N>
    struct fixed_size_string {
        char data[N];

        [[nodiscard]] std::size_t constexpr size() const;

        constexpr explicit fixed_size_string(const char s[N]);
        constexpr explicit fixed_size_string(null_terminated_tag, const char *s);

        template <std::size_t M>
        [[nodiscard]] constexpr std::size_t find(fixed_size_string<M> subs) const;

        [[nodiscard]] constexpr std::size_t find_last_of(std::initializer_list<char> cs) const;

        template <std::size_t Start, std::size_t End>
        [[nodiscard]] constexpr auto substr() const;

        [[nodiscard]] operator std::string() const;
    };

    template <class T, std::size_t BufSize = 256>
    [[nodiscard]] constexpr auto type_name();
}// namespace mlab

namespace mlab {
    template <std::size_t N>
    std::size_t constexpr fixed_size_string<N>::size() const {
        return N;
    }

    template <std::size_t N>
    constexpr fixed_size_string<N>::fixed_size_string(const char s[N]) : data{} {
        std::copy_n(s, size(), std::begin(data));
    }

    template <std::size_t N>
    constexpr fixed_size_string<N>::fixed_size_string(null_terminated_tag, const char *s) : data{} {
        std::size_t i = 0;
        for (; i < N - 1; ++i) {
            if (s[i] == '\0') {
                break;
            }
            data[i] = s[i];
        }
        for (; i < N; ++i) {
            data[i] = '\0';
        }
    }

    template <std::size_t N>
    template <std::size_t M>
    constexpr std::size_t fixed_size_string<N>::find(fixed_size_string<M> subs) const {
        return std::distance(std::begin(data), std::search(std::begin(data), std::end(data), std::begin(subs.data), std::end(subs.data)));
    }

    template <std::size_t N>
    constexpr std::size_t fixed_size_string<N>::find_last_of(std::initializer_list<char> cs) const {
        using iterator_t = decltype(std::begin(data));
        auto rbegin = std::reverse_iterator<iterator_t>(std::end(data));
        auto rend = std::reverse_iterator<iterator_t>(std::begin(data));
        auto it = std::find_first_of(rbegin, rend, std::begin(cs), std::end(cs));
        auto pos = std::distance(it, rend);
        return pos >= 1 ? pos - 1 : N;
    }

    template <std::size_t N>
    template <std::size_t Start, std::size_t End>
    constexpr auto fixed_size_string<N>::substr() const {
        static_assert(Start < End and End <= N);
        auto retval = fixed_size_string<End - Start + 1>{&data[Start]};
        retval.data[End - Start] = '\0';
        return retval;
    }

    template <std::size_t N>
    fixed_size_string<N>::operator std::string() const {
        return std::string{data, std::find(std::begin(data), std::end(data), '\0')};
    }

    template <class T, std::size_t BufSize>
    [[nodiscard]] constexpr auto type_name() {
        constexpr auto method_name = fixed_size_string<BufSize>{null_terminated, __PRETTY_FUNCTION__};
        constexpr std::size_t t_pos = method_name.find(fixed_size_string<4>{"T = "});
        constexpr std::size_t bufsize_pos = method_name.find(fixed_size_string<10>{"BufSize = "});
        if constexpr (t_pos >= BufSize or bufsize_pos >= BufSize or t_pos + 4 >= bufsize_pos) {
            return fixed_size_string<1>{""};
        } else {
            constexpr auto candidate = method_name.template substr<t_pos + 4, bufsize_pos>();
            constexpr std::size_t t_end = candidate.find_last_of({',', ';'});
            if constexpr (t_end >= candidate.size()) {
                return fixed_size_string<1>{""};
            } else {
                return candidate.template substr<0, t_end>();
            }
        }
    }
}// namespace mlab
#endif//MLAB_TYPE_NAME_HPP
