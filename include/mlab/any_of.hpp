//
// Created by spak on 2/9/21.
//

#ifndef MLAB_ANY_OF_HPP
#define MLAB_ANY_OF_HPP

#include <type_traits>

namespace mlab {

    template <class Enum, template<Enum> class T, Enum Default = Enum{}>
    class any_of {
    public:
        template <Enum E>
        using value_type = T<E>;
        using enum_type = Enum;
        static constexpr enum_type default_type = Default;

        any_of();

        template <enum_type E>
        any_of(T<E> obj);

        any_of(any_of &&) = default;
        any_of &operator=(any_of &&) noexcept = default;

        any_of(any_of const &) = delete;
        any_of &operator=(any_of const &) = delete;

        ~any_of();

        enum_type type() const;

        template <enum_type E>
        T<E> const &get() const;

        template <enum_type E>
        T<E> &get();

        template <enum_type E>
        any_of &operator=(T<E> obj);

    protected:

        template <enum_type E, class U>
        T<E> &set(U &&obj);

    private:

        /**
         * @addtogroup FlagsToSelectOverload
         * This integral constant mechanism is syntactic sugar that replaces C++17's ''if constexpr''.
         * @{
         */

        enum struct storage_type {
            allocated_ptr,
            in_place_obj
        };

        using allocated_ptr_storage_type = std::integral_constant<storage_type, storage_type::allocated_ptr>;
        using in_place_obj_storage_type = std::integral_constant<storage_type, storage_type::in_place_obj>;

        /**
         * We store ''T<E>'' within a ''std::uintptr_t'' if and only of it fits, it's trivial (we do not call
         * constructors or destructors in such a case) and it has a less strict align requirement.
         */
        template <enum_type E>
        using storage_for = typename std::conditional<
                sizeof(T<E>) <= sizeof(std::uintptr_t) and alignof(T<E>) <= alignof(std::uintptr_t) and std::is_trivial<T<E>>::value,
                in_place_obj_storage_type,
                allocated_ptr_storage_type
        >::type;

        template <enum_type E>
        T<E> get_impl(in_place_obj_storage_type) const;

        template <enum_type E>
        T<E> const &get_impl(allocated_ptr_storage_type) const;

        template <enum_type E>
        T<E> &get_impl(in_place_obj_storage_type);

        template <enum_type E>
        T<E> &get_impl(allocated_ptr_storage_type);

        template <enum_type E, class U>
        T<E> &set_impl(U &&obj, in_place_obj_storage_type);

        template <enum_type E, class U>
        T<E> &set_impl(U &&obj, allocated_ptr_storage_type);

        /**
         * @}
         */

        /**
         * Pointer to a ''void delete_this_pointer(void *)'' function.
         */
        using deleter_type = void (*)(void *);

        template <enum_type E>
        static void default_deleter_fn(void *ptr);

        template <enum_type E>
        static constexpr deleter_type get_default_deleter();

        /**
         * True if there is any memory in the heap associated to this object.
         */
        bool holds_memory() const;

        /**
         * Invokes once the deleter for the pointer storage, if necessary, thus releasing the memory.
         * Afterwards the storage is set to a nullptr with no deleter.
         */
        void free();

        template <enum_type E, class U>
        void store_as_ptr(U &&arg);

        template <enum_type E, class U>
        void store_as_obj(U &&arg);

        /**
         * @addtogroup StoreOnHeap
         * These methods allow to use @ref _storage as a regular pointer. The const variants simply return a copy of the
         * pointer.
         * @{
         */

        void * &stored_ptr();

        void const *stored_ptr() const;

        template <Enum E>
        T<E> * &stored_ptr();

        template <Enum E>
        T<E> const *stored_ptr() const;

        /**
         * @}
         */

        /**
         * @addtogroup StoreOnStack
         * These methods use @ref _storage as the container, on stack, for the type ''T<E>''. This only makes sense
         * when @ref storage_for is @ref in_place_obj for ''T<E>''. In that case the content of @ref _storage is
         * reinterpreted as a ''T<E>''. For this trick to be possible, we must have that ''T<E>'' is trivial, therefore
         * we return a copy to it on the const variant of @ref stored_obj.
         * @{
         */

        template <Enum E>
        T<E> stored_obj() const;

        template <Enum E>
        T<E> &stored_obj();

        /**
         * @}
         */

        enum_type _active;
        std::uintptr_t _storage;
        deleter_type _deleter;
    };
}

namespace mlab {

    template <class Enum, template<Enum> class T, Enum Default>
    template <Enum E>
    any_of<Enum, T, Default>::any_of(T<E> obj) : _active{E}, _storage{}, _deleter{nullptr} {
        set<E>(std::move(obj));
    }

    template <class Enum, template<Enum> class T, Enum Default>
    any_of<Enum, T, Default>::any_of() : any_of{T<Default>{}} {}

    template <class Enum, template<Enum> class T, Enum Default>
    any_of<Enum, T, Default>::~any_of() {
        free();
    }

    template <class Enum, template<Enum> class T, Enum Default>
    Enum any_of<Enum, T, Default>::type() const {
        return _active;
    }

    template <class Enum, template<Enum> class T, Enum Default>
    template <Enum E>
    T<E> const &any_of<Enum, T, Default>::get() const {
        return get_impl<E>(storage_for<E>{});
    }

    template <class Enum, template<Enum> class T, Enum Default>
    template <Enum E>
    T<E> &any_of<Enum, T, Default>::get() {
        return get_impl<E>(storage_for<E>{});
    }

    template <class Enum, template<Enum> class T, Enum Default>
    template <Enum E>
    any_of<Enum, T, Default> &any_of<Enum, T, Default>::operator=(T<E> obj) {
        set<E>(std::move(obj));
        return *this;
    }


    template <class Enum, template<Enum> class T, Enum Default>
    template <Enum E, class U>
    T<E> &any_of<Enum, T, Default>::set(U &&obj) {
        return set_impl<E>(std::forward<U>(obj), storage_for<E>{});
    }


    template <class Enum, template<Enum> class T, Enum Default>
    template <Enum E>
    T<E> any_of<Enum, T, Default>::get_impl(in_place_obj_storage_type) const {
        if (type() != E) {
            ESP_LOGE("MLAB", "any_of holds <type %d> but <type %d> was requested!",
                     static_cast<unsigned>(type()), static_cast<unsigned>(E));
            set_impl<E>(T<E>{}, in_place_obj_storage_type{});
        }
        return stored_obj<E>();
    }


    template <class Enum, template<Enum> class T, Enum Default>
    template <Enum E>
    T<E> const &any_of<Enum, T, Default>::get_impl(allocated_ptr_storage_type) const {
        if (type() != E) {
            ESP_LOGE("MLAB", "any_of holds <type %d> but <type %d> was requested!",
                     static_cast<unsigned>(type()), static_cast<unsigned>(E));
            set_impl<E>(T<E>{}, allocated_ptr_storage_type{});
        }
        return *stored_ptr<E>();
    }

    template <class Enum, template<Enum> class T, Enum Default>
    template <Enum E>
    T<E> &any_of<Enum, T, Default>::get_impl(in_place_obj_storage_type) {
        if (type() != E) {
            ESP_LOGE("MLAB", "any_of holds <type %d> but <type %d> was requested!",
                     static_cast<unsigned>(type()), static_cast<unsigned>(E));
            set_impl<E>(T<E>{}, in_place_obj_storage_type{});
        }
        return stored_obj<E>();
    }


    template <class Enum, template<Enum> class T, Enum Default>
    template <Enum E>
    T<E> &any_of<Enum, T, Default>::get_impl(allocated_ptr_storage_type) {
        if (type() != E) {
            ESP_LOGE("MLAB", "any_of holds <type %d> but <type %d> was requested!",
                     static_cast<unsigned>(type()), static_cast<unsigned>(E));
            set_impl<E>(T<E>{}, allocated_ptr_storage_type{});
        }
        return *stored_ptr<E>();
    }


    template <class Enum, template<Enum> class T, Enum Default>
    template <Enum E, class U>
    T<E> &any_of<Enum, T, Default>::set_impl(U &&obj, in_place_obj_storage_type) {
        store_as_obj<E>(std::forward<U>(obj));
        return get_impl<E>(in_place_obj_storage_type{});
    }


    template <class Enum, template<Enum> class T, Enum Default>
    template <Enum E, class U>
    T<E> &any_of<Enum, T, Default>::set_impl(U &&obj, allocated_ptr_storage_type) {
        store_as_ptr<E>(std::forward<U>(obj));
        return get_impl<E>(allocated_ptr_storage_type{});
    }

    template <class Enum, template<Enum> class T, Enum Default>
    template <Enum E>
    constexpr typename any_of<Enum, T, Default>::deleter_type any_of<Enum, T, Default>::get_default_deleter() {
        return &default_deleter_fn<E>;
    }

    template <class Enum, template<Enum> class T, Enum Default>
    template <Enum E>
    void any_of<Enum, T, Default>::default_deleter_fn(void *ptr) {
        static const std::default_delete<T<E>> deleter_impl{};
        deleter_impl(reinterpret_cast<T<E> *>(ptr));
    }

    template <class Enum, template<Enum> class T, Enum Default>
    bool any_of<Enum, T, Default>::holds_memory() const {
        return bool(_deleter);
    }

    template <class Enum, template<Enum> class T, Enum Default>
    void any_of<Enum, T, Default>::free() {
        // Deleter is defined only if we stored a pointer
        if (holds_memory()) {
            assert(_deleter);
            _deleter(stored_ptr());
            _deleter = nullptr;
        }
        // Always set this to nullptr so we being with a consistent state
        stored_ptr() = nullptr;
    }

    template <class Enum, template<Enum> class T, Enum Default>
    template <Enum E, class U>
    void any_of<Enum, T, Default>::store_as_ptr(U &&arg) {
        static_assert(storage_for<E>::value == storage_type::allocated_ptr, "Use store_as_obj.");
        if (type() == E and holds_memory()) {
            // Can call assignment operator
            stored_ptr<E>() = std::forward<U>(arg);
        } else {
            // We must allocate the memory anew, because the E in T<E> changed
            free();
            stored_ptr() = new T<E>(std::forward<U>(arg));
            _deleter = get_default_deleter<E>();
        }
    }

    template <class Enum, template<Enum> class T, Enum Default>
    template <Enum E, class U>
    void any_of<Enum, T, Default>::store_as_obj(U &&arg) {
        static_assert(storage_for<E>::value == storage_type::in_place_obj, "Use store_as_ptr.");
        // Make sure the memory that may have been allocated by other T<E>s is freed, we will use the storage in place
        free();
        stored_obj<E>() = std::forward<U>(arg);
    }

    template <class Enum, template<Enum> class T, Enum Default>
    void * &any_of<Enum, T, Default>::stored_ptr() {
        return *reinterpret_cast<void * *>(&_storage);
    }

    template <class Enum, template<Enum> class T, Enum Default>
    void const *any_of<Enum, T, Default>::stored_ptr() const {
        return *reinterpret_cast<void const * const *>(&_storage);
    }


    template <class Enum, template<Enum> class T, Enum Default>
    template <Enum E>
    T<E> * &any_of<Enum, T, Default>::stored_ptr() {
        static_assert(storage_for<E>::value == storage_type::allocated_ptr, "Use stored_obj.");
        return reinterpret_cast<T<E> *&>(stored_ptr());
    }


    template <class Enum, template<Enum> class T, Enum Default>
    template <Enum E>
    T<E> const *any_of<Enum, T, Default>::stored_ptr() const {
        static_assert(storage_for<E>::value == storage_type::allocated_ptr, "Use stored_obj.");
        return reinterpret_cast<T<E> const *>(stored_ptr());
    }


    template <class Enum, template<Enum> class T, Enum Default>
    template <Enum E>
    T<E> any_of<Enum, T, Default>::stored_obj() const {
        static_assert(storage_for<E>::value == storage_type::in_place_obj, "Use stored_ptr.");
        return *reinterpret_cast<T<E> const *>(&_storage);
    }

    template <class Enum, template<Enum> class T, Enum Default>
    template <Enum E>
    T<E> &any_of<Enum, T, Default>::stored_obj() {
        static_assert(storage_for<E>::value == storage_type::in_place_obj, "Use stored_ptr.");
        return *reinterpret_cast<T<E> *>(&_storage);
    }

}

#endif//MLAB_ANY_OF_HPP
