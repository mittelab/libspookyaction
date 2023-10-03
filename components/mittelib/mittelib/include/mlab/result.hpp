//
// Created by Pietro Saccardi on 22/12/2020.
//

#ifndef MLAB_RESULT_HPP
#define MLAB_RESULT_HPP

#include <esp_log.h>
#include <memory>
#include <mlab/any_of.hpp>
#include <type_traits>
#include <vector>

namespace mlab {

    enum struct result_content {
        error,
        data
    };

    /**
     * This is basically std::variant<E, T1, ...>, contextually convertible to bool if T is present.
     * Also, it can take ''void'' T; in that case it represents either a success state or carries the error data.
     * That is just an alias to ''result<E, result_success_type>''.
     *
     * All result classes holding data compare true to @ref result_success, and all result classes can be converted to
     * ''result<void, E>''.
     */

    template <class... Args>
    class result;

    namespace traits {
        template <class T>
        struct is_result : std::false_type {};
        template <class... Args>
        struct is_result<mlab::result<Args...>> : std::true_type {};
    }// namespace traits

    template <class T>
    concept is_result = traits::is_result<std::decay_t<T>>::value;


    /**
     * @brief Concatenates as many results as provided.
     * The returned object will contain all @ref result::value_type of the provided results, in the given order.
     * If any of the results provided has an error state, the error is returned. It is only returned the first
     * found error in the order in which the results are provided.
     * @tparam Rs A sequence of @ref result types, which all must share the same @ref result::error_type.
     * @param rs A sequence of @ref result types.
     * @return A result object having as value type all the concatenated values, and the same error type.
     */
    template <is_result R1, is_result... Rs>
    [[nodiscard]] decltype(auto) concat_result(R1 &&r1, Rs &&...rs);

    struct result_success_type {
        template <class E, class T>
        inline bool operator==(result<E, T> const &res) const;

        template <class E, class T>
        inline bool operator!=(result<E, T> const &res) const;
    };

    static constexpr result_success_type result_success{};

    /**
     * @note Since @ref any_of requires a matching ''template <result_content> class T'', we need so split the tiple
     * ''<E, T, result_content>'' in a two-level template, by means of a wrapping struct.
     */
    template <class E, class T>
    struct result_impl {
        template <result_content RC>
        struct content_wrap {
            using content_type = typename std::conditional<RC == result_content::error, E, T>::type;
            content_type content;
        };
    };

    template <class E, class T>
    class result<E, T> : private any_of<result_content, result_impl<E, T>::template content_wrap, result_content::error> {
        template <result_content RC>
        using content_wrap = typename result_impl<E, T>::template content_wrap<RC>;

        using base = any_of<result_content, result_impl<E, T>::template content_wrap, result_content::error>;

    public:
        result() = default;
        result(result &&) noexcept = default;

        using error_type = E;
        using value_type = T;
        static constexpr std::size_t value_size = 1;
        using value_type_as_tuple = std::tuple<T>;

        inline result(result const &other);

        inline result(E error);

        inline result(T data);

        result &operator=(E error);

        result &operator=(T data);

        result &operator=(result &&) noexcept = default;

        result &operator=(result const &other);

        [[nodiscard]] inline T &operator*();

        [[nodiscard]] inline T const &operator*() const;

        [[nodiscard]] inline T *operator->();

        [[nodiscard]] inline T const *operator->() const;

        [[nodiscard]] T const &release() const &;

        [[nodiscard]] T &release() &;

        [[nodiscard]] T &&release() &&;

        inline explicit operator bool() const;

        using base::type;

        [[nodiscard]] inline E error() const;
    };

    namespace impl {
        template <class... Args>
        struct tuple_container_type {
            using type = std::tuple<Args...>;
        };

        template <class T1, class T2>
        struct tuple_container_type<T1, T2> {
            using type = std::pair<T1, T2>;
        };

        template <class T>
        struct tuple_container_type<T> {};

        template <>
        struct tuple_container_type<> {};
    }// namespace impl

    template <class... Ts>
    using tuple_container_t = impl::tuple_container_type<Ts...>::type;

    template <class E, class... Ts>
    class result<E, Ts...> : private result<E, tuple_container_t<Ts...>> {
    public:
        using base = result<E, tuple_container_t<Ts...>>;

        using typename base::error_type;
        using typename base::value_type;
        static constexpr std::size_t value_size = sizeof...(Ts);
        using value_type_as_tuple = std::tuple<Ts...>;

        result() = default;
        result(result &&) noexcept = default;
        result(result const &other) = default;
        result &operator=(result const &other) = default;
        result &operator=(result &&other) = default;

        inline result(Ts... ts);
        inline result(base b);

        using base::base;
        using base::error;
        using base::type;
        using base::operator=;
        using base::operator*;
        using base::release;
        using base::operator->;
        using base::operator bool;
    };

    template <class E>
    class result<E, void> : public result<E, result_success_type> {
    public:
        using base = result<E, result_success_type>;
        using typename base::error_type;
        using typename base::value_type;
        static constexpr std::size_t value_size = 0;
        using value_type_as_tuple = std::tuple<>;

        template <class T, class = typename std::enable_if<// Disable copies of the same copy constructor
                                   not std::is_void<T>::value and not std::is_same<T, result_success_type>::value>::type>
        inline result(result<E, T> const &other);

        result() = default;
        result(result &&) noexcept = default;
        result(result const &other) = default;
        result &operator=(result const &other) = default;
        result &operator=(result &&other) = default;

        using base::base;
        using base::operator=;
        using base::error;
        using base::type;
        using base::operator bool;
    };

    template <class E>
    class result<E> : public result<E, void> {
    public:
        using base = result<E, void>;
        using base::value_size;
        using typename base::error_type;
        using typename base::value_type;
        using typename base::value_type_as_tuple;

        result() = default;
        result(result &&) noexcept = default;
        result(result const &other) = default;
        result &operator=(result const &other) = default;
        result &operator=(result &&other) = default;

        using base::base;
        using base::operator=;
        using base::error;
        using base::type;
        using base::operator bool;
    };

    template <class T, is_result R>
    [[nodiscard]] decltype(auto) get(R &&r);

    template <std::size_t I, is_result R>
    [[nodiscard]] decltype(auto) get(R &&r);

    template <is_result R>
    [[nodiscard]] auto result_to_tuple(R &&r);

    template <class E, class Tuple>
    [[nodiscard]] auto result_from_tuple(Tuple &&tpl);
}// namespace mlab

namespace mlab {

    template <class T, is_result R>
    decltype(auto) get(R &&r) {
        if constexpr (std::decay_t<R>::value_size == 1) {
            if constexpr (std::is_rvalue_reference_v<R &&>) {
                // Move the content
                return std::move(*r);
            } else {
                return *r;
            }
        } else {
            return std::get<T>(*r);
        }
    }

    template <std::size_t I, is_result R>
    decltype(auto) get(R &&r) {
        if constexpr (std::decay_t<R>::value_size == 1) {
            static_assert(I == 0);
            if constexpr (std::is_rvalue_reference_v<R &&>) {
                // Move the content
                return std::move(*r);
            } else {
                return *r;
            }
        } else {
            return std::get<I>(*r);
        }
    }

    template <class E, class T>
    result<E, T> &result<E, T>::operator=(E error) {
        base::template set<result_content::error>(content_wrap<result_content::error>{std::move(error)});
        return *this;
    }

    template <class E, class T>
    result<E, T> &result<E, T>::operator=(T data) {
        base::template set<result_content::data>(content_wrap<result_content::data>{std::move(data)});
        return *this;
    }

    template <class E, class T>
    result<E, T>::result(result<E, T> const &other) : base{other.type()} {
        *this = other;
    }

    template <class E, class T>
    result<E, T> &result<E, T>::operator=(result<E, T> const &other) {
        if (&other != this) {
            switch (other.type()) {
                case result_content::error:
                    base::template set<result_content::error>(content_wrap<result_content::error>{other.error()});
                    break;
                case result_content::data:
                    base::template set<result_content::data>(content_wrap<result_content::data>{*other});
                    break;
            }
        }
        return *this;
    }

    template <class E, class T>
    result<E, T>::operator bool() const {
        return type() == result_content::data;
    }

    template <class E, class T>
    T &result<E, T>::operator*() {
        return base::template get<result_content::data>().content;
    }

    template <class E, class T>
    T const &result<E, T>::release() const & {
        return **this;
    }

    template <class E, class T>
    T &result<E, T>::release() & {
        return **this;
    }

    template <class E, class T>
    T &&result<E, T>::release() && {
        return std::move(**this);
    }


    template <class E, class T>
    T const &result<E, T>::operator*() const {
        return base::template get<result_content::data>().content;
    }

    template <class E, class T>
    T *result<E, T>::operator->() {
        return &base::template get<result_content::data>().content;
    }

    template <class E, class T>
    T const *result<E, T>::operator->() const {
        return &base::template get<result_content::data>().content;
    }

    template <class E, class T>
    E result<E, T>::error() const {
        return base::template get<result_content::error>().content;
    }

    template <class E, class T>
    result<E, T>::result(E error) : base{content_wrap<result_content::error>{std::move(error)}} {}

    template <class E, class T>
    result<E, T>::result(T data) : base{content_wrap<result_content::data>{std::move(data)}} {}

    template <class E, class T>
    bool result_success_type::operator==(result<E, T> const &res) const { return bool(res); }

    template <class E, class T>
    bool result_success_type::operator!=(result<E, T> const &res) const { return not bool(res); }

    template <class E>
    template <class T, class>
    result<E, void>::result(result<E, T> const &other) : result<E, result_success_type>{} {
        if (other.type() == result_content::error) {
            *this = other.error();
        } else {
            *this = result_success;
        }
    }

    template <class E, class... Ts>
    result<E, Ts...>::result(Ts... ts) : base{tuple_container_t<Ts...>(std::forward<Ts>(ts)...)} {}

    template <class E, class... Ts>
    result<E, Ts...>::result(result<E, Ts...>::base b) : base{std::forward<base>(b)} {}

    namespace impl {
        template <std::size_t... Is, is_result R>
        [[nodiscard]] auto result_to_tuple(std::index_sequence<Is...>, R &&r) {
            return std::make_tuple(mlab::get<Is>(r)...);
        }

        template <class, class>
        struct tuple_to_result {};

        template <class E, class... Args>
        struct tuple_to_result<E, std::tuple<Args...>> {
            using type = result<E, Args...>;
        };

        template <class>
        struct result_to_tuple_container {};

        template <class E, class... Args>
        struct result_to_tuple_container<result<E, Args...>> {
            using type = tuple_container_t<Args...>;
        };

        template <class E, class T>
        struct result_to_tuple_container<result<E, T>> {
            using type = T;
        };

        template <class E>
        struct result_to_tuple_container<result<E>> {
            using type = result_success_type;
        };

        template <class E, std::size_t... Is, class Tuple>
        [[nodiscard]] auto result_from_tuple(std::index_sequence<Is...>, Tuple &&tpl) {
            using result_t = typename tuple_to_result<E, std::decay_t<Tuple>>::type;
            if constexpr (result_t::value_size == 0) {
                return result_t{result_success};
            } else {
                using tuple_t = result_to_tuple_container<result_t>::type;
                // Explicitly construct the tuple
                return result_t{tuple_t{std::get<Is>(tpl)...}};
            }
        }

        static_assert(std::is_same_v<result<char>, decltype(result_from_tuple<char>(std::make_index_sequence<0>{}, std::tuple<>{}))>);
        static_assert(std::is_same_v<result<char, int>, decltype(result_from_tuple<char>(std::make_index_sequence<1>{}, std::tuple<int>{}))>);

    }// namespace impl

    template <is_result R>
    auto result_to_tuple(R &&r) {
        return impl::result_to_tuple(std::make_index_sequence<std::decay_t<R>::value_size>{}, std::forward<R>(r));
    }

    template <class E, class Tuple>
    auto result_from_tuple(Tuple &&tpl) {
        return impl::result_from_tuple<E>(std::make_index_sequence<std::tuple_size_v<Tuple>>{}, tpl);
    }

    static_assert(std::is_same_v<result<char>, decltype(result_from_tuple<char>(std::tuple<>{}))>);
    static_assert(std::is_same_v<result<char, int>, decltype(result_from_tuple<char>(std::tuple<int>{}))>);

    template <is_result R1, is_result... Rs>
    decltype(auto) concat_result(R1 &&r1, Rs &&...rs) {
        if constexpr (sizeof...(Rs) == 0) {
            return std::forward<R1>(r1);
        } else {
            static_assert(std::conjunction_v<std::is_same<typename std::decay_t<R1>::error_type, typename std::decay_t<Rs>::error_type>...>,
                          "All result types to concatenate must have the same error type.");
            using error_t = typename std::decay_t<R1>::error_type;
            using result_t = decltype(result_from_tuple<error_t>(
                    std::tuple_cat(result_to_tuple(std::forward<R1>(r1)),
                                   result_to_tuple(std::forward<Rs>(rs))...)));

            auto all_viable_recursive = [](auto &self, auto const &refr1, auto const &...refrs) -> result<error_t> {
                if (not refr1) {
                    return refr1.error();
                } else {
                    if constexpr (sizeof...(refrs) == 0) {
                        return mlab::result_success;
                    } else {
                        return self(self, refrs...);
                    }
                }
            };

            if (const auto all_viable = all_viable_recursive(all_viable_recursive, r1, rs...); not all_viable) {
                return result_t{all_viable.error()};
            }

            return result_from_tuple<error_t>(
                    std::tuple_cat(result_to_tuple(std::forward<R1>(r1)),
                                   result_to_tuple(std::forward<Rs>(rs))...));
        }
    }

    static_assert(std::is_same_v<decltype(concat_result(std::declval<result<char>>(), std::declval<result<char>>())), result<char>>);
    static_assert(std::is_same_v<decltype(concat_result(std::declval<result<char, int>>(), std::declval<result<char>>())), result<char, int>>);
    static_assert(std::is_same_v<decltype(concat_result(std::declval<result<char>>(), std::declval<result<char, int>>())), result<char, int>>);
    static_assert(std::is_same_v<decltype(concat_result(std::declval<result<char, int>>(), std::declval<result<char, float>>())), result<char, int, float>>);
    static_assert(std::is_same_v<decltype(concat_result(std::declval<result<char, int, float>>(), std::declval<result<char, double>>())), result<char, int, float, double>>);
    static_assert(std::is_same_v<decltype(concat_result(std::declval<result<char, int, float>>(), std::declval<result<char, double, unsigned>>())), result<char, int, float, double, unsigned>>);
    static_assert(std::is_same_v<decltype(concat_result(std::declval<result<char, int, float, char>>(), std::declval<result<char, double, unsigned>>())), result<char, int, float, char, double, unsigned>>);
    static_assert(std::is_same_v<decltype(concat_result(std::declval<result<char, int, float, char>>(), std::declval<result<char, double, unsigned, char>>())), result<char, int, float, char, double, unsigned, char>>);
    static_assert(std::is_same_v<decltype(concat_result(std::declval<result<char, int, float, char>>(), std::declval<result<char, double>>(), std::declval<result<char, unsigned, char>>())), result<char, int, float, char, double, unsigned, char>>);

}// namespace mlab

#endif//MLAB_RESULT_HPP
