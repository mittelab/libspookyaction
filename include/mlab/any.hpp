//
// Created by Pietro Saccardi on 24/12/2020.
//

#ifndef MLAB_ANY_HPP
#define MLAB_ANY_HPP

#include <memory>
#include <functional>
#include <esp_log.h>

namespace mlab {

    namespace ctti {
        using id_type = std::uintptr_t;

        template <class>
        struct void_t {
            using type = void;
        };

        template <class T>
        struct type_info {
            static_assert(
                    std::is_same<void, typename void_t<T>::type>::value,
                    "You must customize ctti::type_info with a static constexpr id_type value member for your types.");
        };

        template <class T>
        id_type id() { return type_info<T>::value; }
    }

    class any {
        std::unique_ptr<void, std::function<void(void *)>> _p;
        ctti::id_type _t;
    public:
        inline any();

        any(any const &) = delete;

        any &operator=(any const &) = delete;

        inline any(any &&) noexcept;

        inline any &operator=(any &&) noexcept;

        inline ctti::id_type const &type() const;

        inline bool empty() const;

        template <class T, class = typename std::enable_if<not std::is_same<T, any>::value>::type>
        explicit any(T &&t);

        template <class T, class = typename std::enable_if<not std::is_same<T, any>::value>::type>
        any &operator=(T &&t);

        template <class T>
        bool test_type() const;

        template <class T>
        T &get();

        template <class T>
        T const &get() const;
    };

}

namespace mlab {

    any::any() : _p{nullptr}, _t{} {}

    any::any(any &&other) noexcept: any{} {
        *this = std::move(other);
    }

    any &any::operator=(any &&other) noexcept {
        std::swap(_p, other._p);
        std::swap(_t, other._t);
        return *this;
    }

    ctti::id_type const &any::type() const {
        return _t;
    }

    bool any::empty() const {
        return _p == nullptr;
    }

    template <class T, class>
    any::any(T &&t) : any{} {
        *this = std::forward<T>(t);
    }

    template <class T, class>
    any &any::operator=(T &&t) {
        // Magic erased type deleter that remembers what was the original type
        std::function<void(void *)> deleter = [](void *ptr) {
            std::default_delete<T>{}(reinterpret_cast<T *>(ptr));
        };
        _p = std::unique_ptr<void, std::function<void(void *)>>(new T(std::forward<T>(t)), std::move(deleter));
        _t = ctti::id<T>();
        return *this;
    }

    template <class T>
    bool any::test_type() const {
        return not empty() and ctti::id<T>() == _t;
    }

    template <class T>
    T &any::get() {
        return const_cast<T &>(static_cast<any const *>(this)->get<T>());
    }

    template <class T>
    T const &any::get() const {
        if (test_type<T>()) {
            return *reinterpret_cast<T const *>(_p.get());
        }
        ESP_LOGE("mlab::any", "Requested incorrect type from an any.");
        return *static_cast<T const *>(nullptr);
    }
}

#endif //MLAB_ANY_HPP
