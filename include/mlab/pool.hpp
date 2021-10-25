//
// Created by spak on 5/25/21.
//

#ifndef MLAB_POOL_HPP
#define MLAB_POOL_HPP

#include <mlab/bin_data.hpp>

namespace mlab {

    template <class T, class Policy>
    class borrowed;

    template <class T>
    struct no_policy {
        void on_take(T &) {}
        void on_give(T &) {}
    };

    template <class Container>
    struct clear_container_policy {
        void on_take(Container &) {}
        void on_give(Container &c) { c.clear(); }
    };

    namespace impl {
        template <class T>
        struct is_clearable_container {
            template <class U>
            static constexpr decltype(std::begin(std::declval<U const &>()) != std::end(std::declval<U const &>()),
                                      *std::begin(std::declval<U const &>()),
                                      std::next(std::begin(std::declval<U const &>())),
                                      std::declval<U &>().clear(),
                                      bool())
            test_get(int) {
                return true;
            }

            template <class>
            static constexpr bool test_get(...) {
                return false;
            }

            static constexpr bool value = test_get<T>(int());
        };

        template <class T>
        static constexpr bool is_clearable_container_v = is_clearable_container<T>::value;
    }// namespace impl

    template <class T>
    using default_borrow_policy = std::conditional_t<impl::is_clearable_container_v<T>, clear_container_policy<T>, no_policy<T>>;

    template <class T, class Policy = default_borrow_policy<T>>
    class pool : public std::enable_shared_from_this<pool<T, Policy>> {
        std::vector<T> _queue{};
        Policy _policy;

    public:
        using std::enable_shared_from_this<pool<T, Policy>>::weak_from_this;

        inline pool();
        explicit inline pool(Policy policy);

        pool(pool const &) = delete;
        pool &operator=(pool const &) = delete;
        pool(pool &&) noexcept = default;
        pool &operator=(pool &&) noexcept = default;

        template <class... Args>
        [[nodiscard]] borrowed<T, Policy> take(Args &&...args);

        inline void give(borrowed<T, Policy> &&obj);

        void give(T &&obj);

        [[nodiscard]] inline bool empty() const;
    };

    template <class T, class Policy>
    class borrowed {
        std::weak_ptr<pool<T, Policy>> _owner{};
        T _obj;
        bool _was_released;

        [[nodiscard]] bool assert_not_released() const;

    public:
        borrowed(borrowed const &) = delete;
        borrowed &operator=(borrowed const &) = delete;
        borrowed(borrowed &&) noexcept = default;
        borrowed &operator=(borrowed &&) noexcept = default;

        explicit borrowed(std::weak_ptr<pool<T, Policy>> owner);
        explicit borrowed(std::weak_ptr<pool<T, Policy>> owner, T &&obj);

        inline T &operator*();
        inline T const &operator*() const;

        inline T *operator->();
        inline T const *operator->() const;

        explicit inline operator bool() const;

        bool give_back();
        T release();

        ~borrowed();
    };

    template <class T, class Policy, class U>
    decltype(auto) operator<<(borrowed<T, Policy> &borrowed_obj, U &&rhs) {
        return *borrowed_obj << rhs;
    }

    template <class T, class Policy, class U>
    decltype(auto) operator<<(borrowed<T, Policy> const &borrowed_obj, U &&rhs) {
        return *borrowed_obj << rhs;
    }
    template <class T, class Policy, class U>
    decltype(auto) operator>>(borrowed<T, Policy> &borrowed_obj, U &&rhs) {
        return *borrowed_obj << rhs;
    }

    template <class T, class Policy, class U>
    decltype(auto) operator>>(borrowed<T, Policy> const &borrowed_obj, U &&rhs) {
        return *borrowed_obj << rhs;
    }

}// namespace mlab

namespace mlab {

    template <class T, class Policy>
    borrowed<T, Policy>::borrowed(std::weak_ptr<pool<T, Policy>> owner) : _owner{std::move(owner)}, _obj{}, _was_released{false} {}

    template <class T, class Policy>
    borrowed<T, Policy>::borrowed(std::weak_ptr<pool<T, Policy>> owner, T &&obj) : _owner{std::move(owner)}, _obj{std::move(obj)}, _was_released{false} {}

    template <class T, class Policy>
    borrowed<T, Policy>::operator bool() const {
        return not _was_released;
    }

    template <class T, class Policy>
    T &borrowed<T, Policy>::operator*() {
        static_cast<void>(assert_not_released());
        return _obj;
    }

    template <class T, class Policy>
    T const &borrowed<T, Policy>::operator*() const {
        static_cast<void>(assert_not_released());
        return _obj;
    }

    template <class T, class Policy>
    T *borrowed<T, Policy>::operator->() {
        static_cast<void>(assert_not_released());
        return &_obj;
    }

    template <class T, class Policy>
    T const *borrowed<T, Policy>::operator->() const {
        static_cast<void>(assert_not_released());
        return &_obj;
    }

    template <class T, class Policy>
    T borrowed<T, Policy>::release() {
        if (assert_not_released()) {
            _was_released = true;
            _owner.reset();
            return std::move(_obj);
        }
        return T{};
    }

    template <class T, class Policy>
    bool borrowed<T, Policy>::assert_not_released() const {
        if (not bool(*this)) {
            ESP_LOGE("MLAB", "Attempt at referencing a borrowed object that was already released or returned.");
            return false;
        }
        return true;
    }

    template <class T, class Policy>
    bool borrowed<T, Policy>::give_back() {
        if (not _owner.expired()) {
            _owner.lock()->give(release());
            return true;
        }
        return false;
    }

    template <class T, class Policy>
    pool<T, Policy>::pool() : _queue{}, _policy{} {}

    template <class T, class Policy>
    pool<T, Policy>::pool(Policy policy) : _queue{}, _policy{std::move(policy)} {}

    template <class T, class Policy>
    void pool<T, Policy>::give(borrowed<T, Policy> &&obj) {
        give(obj.release());
    }

    template <class T, class Policy>
    borrowed<T, Policy>::~borrowed() {
        give_back();
    }

    template <class T, class Policy>
    bool pool<T, Policy>::empty() const {
        return _queue.empty();
    }

    template <class T, class Policy>
    void pool<T, Policy>::give(T &&obj) {
        _queue.emplace_back(std::move(obj));
        _policy.on_give(_queue.back());
    }

    template <class T, class Policy>
    template <class... Args>
    borrowed<T, Policy> pool<T, Policy>::take(Args &&...args) {
        if (empty()) {
            borrowed retval{weak_from_this(), T{std::forward<Args>(args)...}};
            _policy.on_take(*retval);
            return retval;
        } else {
            borrowed retval{weak_from_this(), std::move(_queue.back())};
            _queue.pop_back();
            _policy.on_take(*retval);
            return retval;
        }
    }
}// namespace mlab

#endif//MLAB_POOL_HPP
