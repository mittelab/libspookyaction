//
// Created by Pietro Saccardi on 22/12/2020.
//

#ifndef MLAB_RESULT_HPP
#define MLAB_RESULT_HPP

#include <vector>
#include <memory>
#include <type_traits>
#include <esp_log.h>
#include "any_of.hpp"

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

    template <class ...Args>
    class result;

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
    class result<E, T> : private any_of<result_content, result_impl<E, T>::template content_wrap, result_content::error>
    {
        template <result_content RC>
        using content_wrap = typename result_impl<E, T>::template content_wrap<RC>;

        using base = any_of<result_content, result_impl<E, T>::template content_wrap, result_content::error>;

    public:
        result() = default;
        result(result &&) noexcept = default;

        inline result(result const &other);

        inline result(E error);

        inline result(T data);

        result &operator=(E error);

        result &operator=(T data);

        result &operator=(result &&) noexcept = default;

        result &operator=(result const &other);

        inline T &operator*();

        inline T const &operator*() const;

        inline T *operator->();

        inline T const *operator->() const;

        inline explicit operator bool() const;

        using base::type;

        inline E error() const;
    };


    template <class E, class T1, class T2>
    class result<E, T1, T2> : private result<E, std::pair<T1, T2>> {
    public:
        using base = result<E, std::pair<T1, T2>>;

        inline result(T1 data1, T2 data2);

        inline result(base b);

        using base::base;
        using base::type;
        using base::error;
        using base::operator=;
        using base::operator*;
        using base::operator->;
        using base::operator bool;
    };

    template <class E, class T1, class T2, class T3, class ...Tn>
    class result<E, T1, T2, T3, Tn...> : private result<E, std::tuple<T1, T2, T3, Tn...>> {
    public:
        using base = result<E, std::pair<T1, T2>>;

        inline result(T1 data1, T2 data2, T2 data3, Tn ...dataN);

        inline result(base b);

        using base::base;
        using base::type;
        using base::error;
        using base::operator=;
        using base::operator*;
        using base::operator->;
        using base::operator bool;
    };


    template <class E>
    class result<E, void> : public result<E, result_success_type> {
    public:
        using base = result<E, result_success_type>;

        template <class T, class = typename std::enable_if<  // Disable copies of the same copy constructor
                not std::is_void<T>::value and not std::is_same<T, result_success_type>::value>::type>
        inline result(result<E, T> const &other);

        using base::base;
        using base::operator=;
        using base::type;
        using base::error;
        using base::operator bool;
    };

    template <class E>
    class result<E> : public result<E, void> {
    public:
        using base = result<E, void>;

        using base::base;
        using base::operator=;
        using base::type;
        using base::error;
        using base::operator bool;
    };


}

namespace mlab {

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
        switch (other.type()) {
            case result_content::error:
                base::template set<result_content::error>(content_wrap<result_content::error>{other.error()});
                break;
            case result_content::data:
                base::template set<result_content::data>(content_wrap<result_content::data>{*other});
                break;
            default: break;
        }
        return *this;
    }

    /*
     * Nothing interesting happening in these methods:
     */

    template <class E, class T>
    result<E, T>::operator bool() const {
        return type() == result_content::data;
    }

    template <class E, class T>
    T &result<E, T>::operator*() {
        return base::template get<result_content::data>().content;
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

    template <class E, class T1, class T2>
    result<E, T1, T2>::result(T1 data1, T2 data2) :
            base{std::make_pair(data1, data2)} {}

    template <class E, class T1, class T2>
    result<E, T1, T2>::result(result<E, T1, T2>::base b) :
            base{std::move(b)} {}


    template <class E, class T1, class T2, class T3, class ...Tn>
    result<E, T1, T2, T3, Tn...>::result(T1 data1, T2 data2, T2 data3, Tn ...dataN) :
            base{std::make_tuple(data1, data2, data3, std::forward<Tn>(dataN)...)} {}

    template <class E, class T1, class T2, class T3, class ...Tn>
    result<E, T1, T2, T3, Tn...>::result(result<E, T1, T2, T3, Tn...>::base b) :
            base{std::move(b)} {}
}

#endif //MLAB_RESULT_HPP
