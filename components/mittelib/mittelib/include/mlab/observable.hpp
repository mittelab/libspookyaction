//
// Created by spak on 10/29/21.
//

#ifndef MITTELIB_OBSERVABLE_HPP
#define MITTELIB_OBSERVABLE_HPP

#include <functional>
#include <mutex>
#include <vector>

namespace mlab {

    template <class T>
    class observe;

    template <class T>
    class observable_ref;

    template <class T>
    class observable_cref;

    template <class T>
    class observable {
    public:
        using read_value_type = std::conditional_t<std::is_trivially_copyable_v<T>, T, T const &>;
        using read_observer_fn = std::function<void(read_value_type)>;
        using write_observer_fn = std::function<void(read_value_type, read_value_type)>;

        inline observable();

        inline explicit observable(T t);

        inline operator read_value_type() const;

        inline observable &operator=(T t);

        friend class observe<T>;

        [[nodiscard]] observe<T> do_observe(read_observer_fn read_fn, write_observer_fn write_fn);

        [[nodiscard]] observable_ref<T> ref();
        [[nodiscard]] observable_cref<T> cref() const;

    private:
        [[nodiscard]] std::size_t append_observer(std::pair<read_observer_fn, write_observer_fn> observers);
        void delete_observer(std::size_t idx);

        T _value;
        mutable std::recursive_mutex _lock;
        std::vector<std::pair<read_observer_fn, write_observer_fn>> _observers;
    };

    template <class T>
    class observable_cref {
    protected:
        observable<T> const &_ref;

    public:
        friend class observe<T>;

        using read_value_type = typename observable<T>::read_value_type;

        inline explicit observable_cref(observable<T> const &ref);

        inline operator read_value_type() const;
    };

    template <class T>
    class observable_ref : public observable_cref<T> {
        using observable_cref<T>::_ref;

    public:
        friend class observe<T>;

        using read_value_type = typename observable_cref<T>::read_value_type;
        using read_observer_fn = typename observable<T>::read_observer_fn;
        using write_observer_fn = typename observable<T>::write_observer_fn;

        using observable_cref<T>::operator read_value_type;

        inline explicit observable_ref(observable<T> &ref);

        inline observable_ref<T> &operator=(T t);

        [[nodiscard]] observe<T> do_observe(read_observer_fn read_fn, write_observer_fn write_fn);
    };


    template <class T>
    class observe {
        observable<T> *_obs_value = nullptr;
        std::size_t _idx = std::numeric_limits<std::size_t>::max();

    public:
        observe() = default;
        observe(observe const &) = delete;
        observe(observe &&other) noexcept;
        observe &operator=(observe const &) = delete;
        observe &operator=(observe &&other) noexcept;
        ~observe();

        void deregister();

        observe(observable<T> &obs_value,
                typename observable<T>::read_observer_fn read_fn,
                typename observable<T>::write_observer_fn write_fn);
        observe(observable_ref<T> &obs_value_ref,
                typename observable<T>::read_observer_fn read_fn,
                typename observable<T>::write_observer_fn write_fn);
    };
}// namespace mlab

namespace mlab {

    template <class T>
    observable<T>::observable(T t) : _value{std::forward<T>(t)} {}

    template <class T>
    observable<T>::observable() : _value{} {}

    template <class T>
    std::size_t observable<T>::append_observer(std::pair<read_observer_fn, write_observer_fn> observers) {
        auto guard = std::scoped_lock{_lock};
        _observers.template emplace_back(std::move(observers));
        return _observers.size() - 1;
    }

    template <class T>
    void observable<T>::delete_observer(std::size_t idx) {
        auto guard = std::scoped_lock{_lock};
        _observers.at(idx) = {nullptr, nullptr};
    }

    template <class T>
    observable<T>::operator read_value_type() const {
        auto guard = std::scoped_lock{_lock};
        for (auto &[r_fn, w_fn] : _observers) {
            if (r_fn) {
                r_fn(_value);
            }
        }
        return _value;
    }

    template <class T>
    observable<T> &observable<T>::operator=(T t) {
        auto guard = std::scoped_lock{_lock};
        for (auto &[r_fn, w_fn] : _observers) {
            if (w_fn) {
                w_fn(_value, t);
            }
        }
        if constexpr (std::is_trivially_copyable_v<T>) {
            _value = t;
        } else {
            _value = std::move(t);
        }
        return *this;
    }

    template <class T>
    observe<T>::~observe() {
        deregister();
    }

    template <class T>
    observe<T> observable<T>::do_observe(read_observer_fn read_fn, write_observer_fn write_fn) {
        return {*this, std::move(read_fn), std::move(write_fn)};
    }

    template <class T>
    void observe<T>::deregister() {
        if (_obs_value != nullptr and _idx < std::numeric_limits<std::size_t>::max()) {
            _obs_value->delete_observer(_idx);
            _idx = std::numeric_limits<std::size_t>::max();
            _obs_value = nullptr;
        }
    }

    template <class T>
    observe<T>::observe(observe &&other) noexcept : observe{} {
        *this = std::move(other);
    }

    template <class T>
    observe<T> &observe<T>::operator=(observe &&other) noexcept {
        std::swap(_obs_value, other._obs_value);
        std::swap(_idx, other._idx);
        return *this;
    }

    template <class T>
    observe<T>::observe(observable<T> &obs_value, typename observable<T>::read_observer_fn read_fn,
                        typename observable<T>::write_observer_fn write_fn) : _obs_value{&obs_value},
                                                                              _idx{obs_value.append_observer({std::move(read_fn), std::move(write_fn)})} {}

    template <class T>
    observe<T>::observe(observable_ref<T> &obs_value_ref, typename observable<T>::read_observer_fn read_fn,
                        typename observable<T>::write_observer_fn write_fn) : _obs_value{&obs_value_ref._ref},
                                                                              _idx{obs_value_ref._ref.append_observer({std::move(read_fn), std::move(write_fn)})} {}


    template <class T>
    observable_ref<T> observable<T>::ref() {
        return observable_ref<T>{*this};
    }

    template <class T>
    observable_cref<T> observable<T>::cref() const {
        return observable_cref<T>{*this};
    }

    template <class T>
    observable_cref<T>::observable_cref(observable<T> const &ref) : _ref{ref} {}

    template <class T>
    observable_ref<T>::observable_ref(observable<T> &ref) : observable_cref<T>{ref} {}

    template <class T>
    observable_cref<T>::operator read_value_type() const {
        return _ref;
    }

    template <class T>
    observable_ref<T> &observable_ref<T>::operator=(T t) {
        const_cast<observable<T> &>(_ref) = std::forward<T>(t);
        return *this;
    }

    template <class T>
    observe<T> observable_ref<T>::do_observe(read_observer_fn read_fn, write_observer_fn write_fn) {
        return const_cast<observable<T> &>(_ref).do_observe(std::move(read_fn), std::move(write_fn));
    }
}// namespace mlab

#endif//MITTELIB_OBSERVABLE_HPP
