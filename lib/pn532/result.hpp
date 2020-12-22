//
// Created by Pietro Saccardi on 22/12/2020.
//

#ifndef APERTURAPORTA_RESULT_HPP
#define APERTURAPORTA_RESULT_HPP

#include <vector>
#include <memory>
#include <type_traits>
#include "log.h"

namespace pn532 {

    enum struct result_content {
        empty,
        data,
        error
    };

    template <class, class> class result;

    struct result_success_type {
        template <class T, class E>
        inline bool operator==(result<T, E> const &res) const;

        template <class T, class E>
        inline bool operator!=(result<T, E> const &res) const;
    };

    static constexpr result_success_type result_success{};

    /**
     * This is basically std::variant<T, E>, contextually convertible to bool if T is present.
     * Bonus points, if T or E fits into the size of a ''void *'', it's stored directly in the class (assuming it
     * can be trivially copy assigned, which is a reasonable requirement for something that small). Otherwise, it
     * behaves like a smart pointer (and thus allocates the object on the stack).
     * Also, it can take ''void'' T; in that case it represents either a success state or carries the error data.
     * That is just an alias to ''result<result_success_type, E>''.
     *
     * All result classes holding data compare true to @ref result_success, and all result classes can be converted to
     * ''result<void, E>''.
     */
    template <class T, class E>
    class result {
    public:
        inline result();
        inline result(result &&other) noexcept;
        inline result(result const &other);

        inline result(E error);
        inline result(T data);

        result &operator=(E error);
        result &operator=(T data);
        result &operator=(result &&other) noexcept;
        result &operator=(result const &other);

        inline T &operator*();
        inline T const &operator*() const;

        inline T *operator->();
        inline T const *operator->() const;

        inline explicit operator bool() const;

        inline result_content holds() const;

        inline bool empty() const;

        inline E error() const;

        inline ~result();
    private:
        result_content _content;
        void *_storage{};

        static T &dummy_data();
        static E &dummy_error();

        inline E &e();
        inline E const &e() const;
        inline T &d();
        inline T const &d() const;

        void release();
    };

}

namespace pn532 {

    namespace impl {

        template <class T>
        using can_be_efficiently_stored = typename std::integral_constant<bool,
                std::is_trivially_copy_assignable<T>::value and sizeof(T) == sizeof(void *)>;

        template <class, bool /* in place */>
        struct store {};

        template <class, bool /* in place */>
        struct retrieve {};

        template <class, bool /* in place */>
        struct destroy {};

        template <class T>
        struct store<T, true> {
            static_assert(can_be_efficiently_stored<T>::value, "Cannot store in place T if it's too large.");
            inline void operator()(void * &dest, T &orig) const {
                *reinterpret_cast<T *>(&dest) = orig;
            }
        };

        template <class T>
        struct store<T, false> {
            template <class U = T, class = typename std::enable_if<std::is_move_constructible<U>::value>::type>
            inline void operator()(void * &dest, U &orig) const {
                new (dest) U(std::move(orig));
            }
            template <class U = T, class = typename std::enable_if<not std::is_move_constructible<U>::value>::type>
            inline void operator()(void * &dest, U const &orig) const {
                new (dest) U(orig);
            }
        };

        template <class T>
        struct retrieve<T, true> {
            static_assert(can_be_efficiently_stored<T>::value, "Cannot retrieve in place T if it's too large.");
            inline T &operator()(void * &ptr) {
                return *reinterpret_cast<T *>(&ptr);
            }
            inline T const &operator()(void * const &ptr) {
                return *reinterpret_cast<T const *>(&ptr);
            }
        };

        template <class T>
        struct retrieve<T, false> {
            inline T &operator()(void * &ptr) {
                return *reinterpret_cast<T *>(ptr);
            }
            inline T const &operator()(void * const &ptr) {
                return *reinterpret_cast<T const *>(ptr);
            }
        };


        template <class T>
        struct destroy<T, true> {
            static_assert(can_be_efficiently_stored<T>::value, "Cannot destroy in place T if it's too large.");
            inline void operator()(void * &ptr) const {
                ptr = nullptr;
            }
        };

        template <class T>
        struct destroy<T, false> {
            inline void operator()(void * &ptr) const {
                std::default_delete<T>{}(reinterpret_cast<T *>(ptr));
                ptr = nullptr;
            }
        };

        template <class T>
        void store_efficiently(void * &dest, T &orig) {
            store<T, can_be_efficiently_stored<T>::value>{}(dest, orig);
        }

        template <class T>
        T &retrieve_efficiently(void * &ptr) {
            return retrieve<T, can_be_efficiently_stored<T>::value>{}(ptr);
        }

        template <class T>
        T const &retrieve_efficiently(void * const &ptr) {
            return retrieve<T, can_be_efficiently_stored<T>::value>{}(ptr);
        }

        template <class T>
        void destroy_efficiently(void * &ptr) {
            destroy<T, can_be_efficiently_stored<T>::value>{}(ptr);
        }

    }


    template <class T, class E>
    void result<T, E>::release() {
        switch (holds()) {
            case result_content::data:
                impl::destroy_efficiently<T>(_storage);
                break;
            case result_content::error:
                impl::destroy_efficiently<E>(_storage);
                break;
            default: break;
        }
        _content = result_content::empty;
    }

    template <class T, class E>
    E const &result<T, E>::e() const {
        if (holds() != result_content::error) {
            LOGE("Bad! Avoided EXC_BAD_ACCESS: attempt to retrieve the error from a result<> that holds data (or is empty)!");
            return dummy_error();
        }
        return impl::retrieve_efficiently<E>(_storage);
    }

    template <class T, class E>
    T const &result<T, E>::d() const {
        if (holds() != result_content::data) {
            LOGE("Bad! Avoided EXC_BAD_ACCESS: attempt to retrieve the data from a result<> that holds error (or is empty)!");
            return dummy_data();
        }
        return impl::retrieve_efficiently<T>(_storage);
    }

    template <class T, class E>
    result<T, E> &result<T, E>::operator=(E error) {
        if (holds() == result_content::error) {
            std::swap(e(), error);
        } else {
            release();
            _content = result_content::error;
            impl::store_efficiently<E>(_storage, error);
        }
        return *this;
    }

    template <class T, class E>
    result<T, E> &result<T, E>::operator=(T data) {
        if (holds() == result_content::data) {
            std::swap(d(), data);
        } else {
            release();
            _content = result_content::data;
            impl::store_efficiently<T>(_storage, data);
        }
        return *this;
    }

    template <class T, class E>
    result<T, E> &result<T, E>::operator=(result &&other) noexcept {
        std::swap(_content, other._content);
        std::swap(_storage, other._storage);
        return *this;
    }

    template <class T, class E>
    result<T, E> &result<T, E>::operator=(result const &other) {
        if (&other != this) {
            switch (other.holds()) {
                case result_content::empty:
                    release();
                    break;
                case result_content::data:
                    *this = other.d();  // Trigger copy
                    break;
                case result_content::error:
                    *this = other.e();  // Trigger copy
                    break;
                default: break;
            }
        }
        return *this;
    }

    template <class T, class E>
    result<T, E>::~result() {
        release();
    }

    /*
     * Nothing interesting happening in these methods:
     */

    template <class T, class E>
    bool result<T, E>::empty() const {
        return holds() == result_content::empty;
    }

    template <class T, class E>
    result<T, E>::operator bool() const {
        return holds() == result_content::data;
    }

    template <class T, class E>
    T &result<T, E>::operator*() {
        return d();
    }

    template <class T, class E>
    T const &result<T, E>::operator*() const {
        return d();
    }

    template <class T, class E>
    T *result<T, E>::operator->() {
        return &d();
    }

    template <class T, class E>
    T const *result<T, E>::operator->() const {
        return &d();
    }

    template <class T, class E>
    E result<T, E>::error() const {
        return e();
    }

    template <class T, class E>
    T &result<T, E>::dummy_data() {
        static T _d{};
        return _d;
    }

    template <class T, class E>
    E &result<T, E>::dummy_error() {
        static E _e{};
        return _e;
    }

    template <class T, class E>
    E &result<T, E>::e() {
        // Allowed
        return const_cast<E &>(static_cast<result const *>(this)->e());
    }

    template <class T, class E>
    T &result<T, E>::d() {
        // Allowed
        return const_cast<T &>(static_cast<result const *>(this)->d());
    }

    template <class T, class E>
    result<T, E>::result() : _content{result_content::empty}, _storage{nullptr} {}

    template <class T, class E>
    result<T, E>::result(result &&other) noexcept : _content{result_content::empty}, _storage{nullptr} {
        *this = std::forward<result>(other);
    }

    template <class T, class E>
    result<T, E>::result(result const &other) : _content{result_content::empty}, _storage{nullptr} {
        *this = other;
    }

    template <class T, class E>
    result<T, E>::result(E error) : _content{result_content::empty}, _storage{nullptr} {
        *this = std::move(error);
    }

    template <class T, class E>
    result<T, E>::result(T data) : _content{result_content::empty}, _storage{nullptr} {
        *this = std::move(data);
    }

    template <class T, class E>
    result_content result<T, E>::holds() const {
        return _content;
    }

    /*
     * Specialization for holding "void" (aka it's a boolean + error code)
     */

    template <class E>
    class result<void, E> : public result<result_success_type, E> {
    public:
        using base = result<result_success_type, E>;

        template <class T,class = typename std::enable_if<  // Disable copies of the same copy constructor
                not std::is_void<T>::value and not std::is_same<T, result_success_type>::value>::type>
        inline result(result<T, E> const &other) : result<result_success_type, E>{} {
            if (other.holds() == result_content::error) {
                *this = other.error();
            } else {
                *this = result_success;
            }
        }

        using base::base;
        using base::operator=;
        using base::holds;
        using base::error;
        using base::operator bool;
        using base::empty;
    };

    template <class T, class E>
    bool result_success_type::operator==(result<T, E> const &res) const { return bool(res); }

    template <class T, class E>
    bool result_success_type::operator!=(result<T, E> const &res) const { return not bool(res); }
}

#endif //APERTURAPORTA_RESULT_HPP
