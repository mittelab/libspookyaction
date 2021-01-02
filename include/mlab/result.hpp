//
// Created by Pietro Saccardi on 22/12/2020.
//

#ifndef APERTURAPORTA_RESULT_HPP
#define APERTURAPORTA_RESULT_HPP

#include <vector>
#include <memory>
#include <type_traits>
#include <esp_log.h>

namespace mlab {


    /**
     * This is basically std::variant<E, T1, ...>, contextually convertible to bool if T is present.
     * Bonus points, if T or E fits into the size of a ''void *'', it's stored directly in the class (assuming it
     * can be trivially copy assigned, which is a reasonable requirement for something that small). Otherwise, it
     * behaves like a smart pointer (and thus allocates the object on the stack).
     * Also, it can take ''void'' T; in that case it represents either a success state or carries the error data.
     * That is just an alias to ''result<E, result_success_type>''.
     *
     * All result classes holding data compare true to @ref result_success, and all result classes can be converted to
     * ''result<void, E>''.
     */

    enum struct result_content {
        empty,
        data,
        error
    };

    template <class ...Args>
    class result;

    struct result_success_type {
        template <class E, class T>
        inline bool operator==(result<E, T> const &res) const;

        template <class E, class T>
        inline bool operator!=(result<E, T> const &res) const;
    };

    static constexpr result_success_type result_success{};

    template <class E, class T>
    class result<E, T> {
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


    template <class E, class T1, class T2>
    class result<E, T1, T2> : private result<E, std::pair<T1, T2>> {
    public:
        using base = result<E, std::pair<T1, T2>>;

        inline result(T1 data1, T2 data2);

        inline result(base b);

        using base::base;
        using base::holds;
        using base::error;
        using base::empty;
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
        using base::holds;
        using base::error;
        using base::empty;
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
        using base::holds;
        using base::error;
        using base::operator bool;
        using base::empty;
    };

    template <class E>
    class result<E> : public result<E, void> {
    public:
        using base = result<E, void>;

        using base::base;
        using base::operator=;
        using base::holds;
        using base::error;
        using base::operator bool;
        using base::empty;
    };


}

namespace mlab {

    namespace impl {

        template <class T>
        using can_be_efficiently_stored = typename std::integral_constant<bool,
                                                                          std::is_trivially_copy_assignable<
                                                                                  T>::value and
                                                                          sizeof(T) == sizeof(void *)>;

        template <class, bool /* in place */>
        struct store {
        };

        template <class, bool /* in place */>
        struct retrieve {
        };

        template <class, bool /* in place */>
        struct destroy {
        };

        template <class T>
        struct store<T, true> {
            static_assert(can_be_efficiently_stored<T>::value, "Cannot store in place T if it's too large.");

            inline void operator()(void *&dest, T &orig) const {
                *reinterpret_cast<T *>(&dest) = orig;
            }
        };

        template <class T>
        struct store<T, false> {
            template <class U = T, class = typename std::enable_if<std::is_move_constructible<U>::value>::type>
            inline void operator()(void *&dest, U &orig) const {
                dest = new U(std::move(orig));
            }

            template <class U = T, class = typename std::enable_if<not std::is_move_constructible<U>::value>::type>
            inline void operator()(void *&dest, U const &orig) const {
                dest = new U(orig);
            }
        };

        template <class T>
        struct retrieve<T, true> {
            static_assert(can_be_efficiently_stored<T>::value, "Cannot retrieve in place T if it's too large.");

            inline T &operator()(void *&ptr) {
                return *reinterpret_cast<T *>(&ptr);
            }

            inline T const &operator()(void *const &ptr) {
                return *reinterpret_cast<T const *>(&ptr);
            }
        };

        template <class T>
        struct retrieve<T, false> {
            inline T &operator()(void *&ptr) {
                return *reinterpret_cast<T *>(ptr);
            }

            inline T const &operator()(void *const &ptr) {
                return *reinterpret_cast<T const *>(ptr);
            }
        };


        template <class T>
        struct destroy<T, true> {
            static_assert(can_be_efficiently_stored<T>::value, "Cannot destroy in place T if it's too large.");

            inline void operator()(void *&ptr) const {
                ptr = nullptr;
            }
        };

        template <class T>
        struct destroy<T, false> {
            inline void operator()(void *&ptr) const {
                std::default_delete<T>{}(reinterpret_cast<T *>(ptr));
                ptr = nullptr;
            }
        };

        template <class T>
        void store_efficiently(void *&dest, T &orig) {
            store<T, can_be_efficiently_stored<T>::value>{}(dest, orig);
        }

        template <class T>
        T &retrieve_efficiently(void *&ptr) {
            return retrieve<T, can_be_efficiently_stored<T>::value>{}(ptr);
        }

        template <class T>
        T const &retrieve_efficiently(void *const &ptr) {
            return retrieve<T, can_be_efficiently_stored<T>::value>{}(ptr);
        }

        template <class T>
        void destroy_efficiently(void *&ptr) {
            destroy<T, can_be_efficiently_stored<T>::value>{}(ptr);
        }

    }


    template <class E, class T>
    void result<E, T>::release() {
        switch (holds()) {
            case result_content::data:
                impl::destroy_efficiently<T>(_storage);
                break;
            case result_content::error:
                impl::destroy_efficiently<E>(_storage);
                break;
            default:
                break;
        }
        _content = result_content::empty;
    }

    template <class E, class T>
    E const &result<E, T>::e() const {
        if (holds() != result_content::error) {
            ESP_LOGE("mlab::result<>", "Bad! Avoided EXC_BAD_ACCESS: attempt to retrieve the error from a result<> that holds data (or is empty)!");
            return dummy_error();
        }
        return impl::retrieve_efficiently<E>(_storage);
    }

    template <class E, class T>
    T const &result<E, T>::d() const {
        if (holds() != result_content::data) {
            ESP_LOGE("mlab::result<>", "Bad! Avoided EXC_BAD_ACCESS: attempt to retrieve the data from a result<> that holds error (or is empty)!");
            return dummy_data();
        }
        return impl::retrieve_efficiently<T>(_storage);
    }

    template <class E, class T>
    result<E, T> &result<E, T>::operator=(E error) {
        if (holds() == result_content::error) {
            std::swap(e(), error);
        } else {
            release();
            _content = result_content::error;
            impl::store_efficiently<E>(_storage, error);
        }
        return *this;
    }

    template <class E, class T>
    result<E, T> &result<E, T>::operator=(T data) {
        if (holds() == result_content::data) {
            std::swap(d(), data);
        } else {
            release();
            _content = result_content::data;
            impl::store_efficiently<T>(_storage, data);
        }
        return *this;
    }

    template <class E, class T>
    result<E, T> &result<E, T>::operator=(result<E, T> &&other) noexcept {
        std::swap(_content, other._content);
        std::swap(_storage, other._storage);
        return *this;
    }

    template <class E, class T>
    result<E, T> &result<E, T>::operator=(result<E, T> const &other) {
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
                default:
                    break;
            }
        }
        return *this;
    }

    template <class E, class T>
    result<E, T>::~result() {
        release();
    }

    /*
     * Nothing interesting happening in these methods:
     */

    template <class E, class T>
    bool result<E, T>::empty() const {
        return holds() == result_content::empty;
    }

    template <class E, class T>
    result<E, T>::operator bool() const {
        return holds() == result_content::data;
    }

    template <class E, class T>
    T &result<E, T>::operator*() {
        return d();
    }

    template <class E, class T>
    T const &result<E, T>::operator*() const {
        return d();
    }

    template <class E, class T>
    T *result<E, T>::operator->() {
        return &d();
    }

    template <class E, class T>
    T const *result<E, T>::operator->() const {
        return &d();
    }

    template <class E, class T>
    E result<E, T>::error() const {
        return e();
    }

    template <class E, class T>
    T &result<E, T>::dummy_data() {
        static T _d{};
        return _d;
    }

    template <class E, class T>
    E &result<E, T>::dummy_error() {
        static E _e{};
        return _e;
    }

    template <class E, class T>
    E &result<E, T>::e() {
        // Allowed
        return const_cast<E &>(static_cast<result const *>(this)->e());
    }

    template <class E, class T>
    T &result<E, T>::d() {
        // Allowed
        return const_cast<T &>(static_cast<result const *>(this)->d());
    }

    template <class E, class T>
    result<E, T>::result() : _content{result_content::empty}, _storage{nullptr} {}

    template <class E, class T>
    result<E, T>::result(result<E, T> &&other) noexcept : _content{result_content::empty}, _storage{nullptr} {
        *this = std::forward<result>(other);
    }

    template <class E, class T>
    result<E, T>::result(result<E, T> const &other) : _content{result_content::empty}, _storage{nullptr} {
        *this = other;
    }

    template <class E, class T>
    result<E, T>::result(E error) : _content{result_content::empty}, _storage{nullptr} {
        *this = std::move(error);
    }

    template <class E, class T>
    result<E, T>::result(T data) : _content{result_content::empty}, _storage{nullptr} {
        *this = std::move(data);
    }

    template <class E, class T>
    result_content result<E, T>::holds() const {
        return _content;
    }

    template <class E, class T>
    bool result_success_type::operator==(result<E, T> const &res) const { return bool(res); }

    template <class E, class T>
    bool result_success_type::operator!=(result<E, T> const &res) const { return not bool(res); }

    template <class E>
    template <class T, class>
    result<E, void>::result(result<E, T> const &other) : result<E, result_success_type>{} {
        if (other.holds() == result_content::error) {
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

#endif //APERTURAPORTA_RESULT_HPP
