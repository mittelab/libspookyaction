//
// Created by spak on 2/9/21.
//

#ifndef MLAB_ANY_OF_HPP
#define MLAB_ANY_OF_HPP

#include <cassert>
#include <type_traits>
#include <esp_log.h>

namespace mlab {

    namespace any_of_impl {
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
         * @}
         */

    }

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

        any_of(any_of &&other) noexcept;

        any_of &operator=(any_of &&other) noexcept;

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

        /**
         * Create uninitialized @ref any_of with type set as @p e. No memory is allocated and in-place storages are
         * zero-initialized. This is suitable to be called as a base constructor when the type is know only at runtime
         * but assignment is just about to take place, e.g. for implementing copy constructors in subclasses.
         *
         * @code
         * enum struct bar { a, b };
         * template <bar> struct foo {};
         *
         * struct any_of_foo : public any_of<bar, foo> {
         *     // Implement custom copy cctor. Requires full enumeration of bar, which is not possible at compile time.
         *     any_of_foo(any_of_foo const &other) : any_of<bar, foo>{other.type()} {
         *         switch (other.type()) {
         *             case bar::a: set<bar::a>(other.get<bar::a>()); break;
         *             case bar::b: set<bar::b>(other.get<bar::b>()); break;
         *         }
         *     }
         * }
         * @endcode
         */
        explicit any_of(enum_type e);

        template <enum_type E, class U>
        void set(U &&obj);

    private:
        /**
         * Pointer to a ''void delete_this_pointer(void *)'' function.
         */
        using deleter_type = void (*)(void *);

        /**
         * We store ''T<E>'' within a ''std::uintptr_t'' if and only of it fits, it's trivial (we do not call
         * constructors or destructors in such a case) and it has a less strict align requirement.
         */
        template <enum_type E>
        using storage_for = typename std::conditional<
                sizeof(T<E>) <= sizeof(std::uintptr_t) and alignof(T<E>) <= alignof(std::uintptr_t) and std::is_trivial<T<E>>::value,
                any_of_impl::in_place_obj_storage_type,
                any_of_impl::allocated_ptr_storage_type
        >::type;

        /**
         * @addtogroup MemberVariables
         * @{
         */

        enum_type _active;
        std::uintptr_t _storage;
        deleter_type _deleter;

        /**
         * @}
         */

        template <enum_type E>
        static void default_deleter_fn(void *ptr);

        template <enum_type E>
        static constexpr deleter_type get_default_deleter();

        /**
         * True if there is any memory in the heap associated to this object.
         */
        bool holds_memory() const;

        void assert_type_is(enum_type e) const;
        void assert_holds_memory() const;


        /**
         * Invokes once the deleter for the pointer storage, if necessary, thus releasing the memory.
         * Afterwards the storage is set to a nullptr with no deleter.
         */
        void free();

        /**
         * @addtogroup StoreOnHeap
         * These methods allow to use @ref _storage as a regular pointer. The const variants simply return a copy of the
         * pointer.
         * @{
         */

        void const *storage_allocated() const;

        /**
         * @note This method allows overwriting the pointer, which is different from the stack case because there the
         * pointer to the storage is defined by ''this''. Here we allocate that manually.
         */
        void *&storage_allocated();

        template <enum_type E>
        T<E> const &get_impl(any_of_impl::allocated_ptr_storage_type) const;

        template <enum_type E>
        T<E> &get_impl(any_of_impl::allocated_ptr_storage_type);

        template <enum_type E, class U>
        void set_impl(U &&obj, any_of_impl::allocated_ptr_storage_type);

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

        void const *storage_in_place() const;

        void *storage_in_place();

        template <enum_type E>
        T<E> const &get_impl(any_of_impl::in_place_obj_storage_type) const;


        template <enum_type E>
        T<E> &get_impl(any_of_impl::in_place_obj_storage_type);


        template <enum_type E, class U>
        void set_impl(U &&obj, any_of_impl::in_place_obj_storage_type);

        /**
         * @}
         */

    };
}

namespace mlab {

    template <class Enum, template<Enum> class T, Enum Default>
    any_of<Enum, T, Default>::any_of(any_of &&other) noexcept : any_of{} {
        *this = std::move(other);
    }

    template <class Enum, template<Enum> class T, Enum Default>
    any_of<Enum, T, Default> &any_of<Enum, T, Default>::operator=(any_of &&other) noexcept {
        if (&other != this) {
            std::swap(_deleter, other._deleter);
            std::swap(_storage, other._storage);
            std::swap(_active, other._active);
        }
        return *this;
    }

    template <class Enum, template<Enum> class T, Enum Default>
    any_of<Enum, T, Default>::any_of(enum_type e) : _active{e}, _storage{}, _deleter{nullptr} {}

    template <class Enum, template<Enum> class T, Enum Default>
    template <Enum E>
    any_of<Enum, T, Default>::any_of(T<E> obj) : any_of{E} {
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
    void any_of<Enum, T, Default>::set(U &&obj) {
        set_impl<E>(std::forward<U>(obj), storage_for<E>{});
    }


    template <class Enum, template<Enum> class T, Enum Default>
    void any_of<Enum, T, Default>::assert_type_is(Enum e) const {
        if (type() != e) {
            ESP_LOGE("MLAB", "any_of holds <type %d>, cannot get reference to <type %d>.",
                     static_cast<unsigned>(type()), static_cast<unsigned>(e));
        }
    }

    template <class Enum, template<Enum> class T, Enum Default>
    void any_of<Enum, T, Default>::assert_holds_memory() const {
        if (not holds_memory()) {
            ESP_LOGE("MLAB", "any_of is empty, cannot get reference.");
        }
    }

    template <class Enum, template<Enum> class T, Enum Default>
    template <Enum E>
    T<E> const &any_of<Enum, T, Default>::get_impl(any_of_impl::in_place_obj_storage_type) const {
        static_assert(std::is_same<storage_for<E>, any_of_impl::in_place_obj_storage_type>::value, "Use allocated storage.");
        assert_type_is(E);
        return *reinterpret_cast<T<E> const *>(storage_in_place());
    }

    template <class Enum, template<Enum> class T, Enum Default>
    template <Enum E>
    T<E> const &any_of<Enum, T, Default>::get_impl(any_of_impl::allocated_ptr_storage_type) const {
        static_assert(std::is_same<storage_for<E>, any_of_impl::allocated_ptr_storage_type>::value, "Use in-place storage.");
        assert_type_is(E);
        assert_holds_memory();
        return *reinterpret_cast<T<E> const *>(storage_allocated());
    }

    template <class Enum, template<Enum> class T, Enum Default>
    template <Enum E>
    T<E> &any_of<Enum, T, Default>::get_impl(any_of_impl::in_place_obj_storage_type) {
        static_assert(std::is_same<storage_for<E>, any_of_impl::in_place_obj_storage_type>::value, "Use allocated storage.");
        assert_type_is(E);
        return *reinterpret_cast<T<E> *>(storage_in_place());
    }

    template <class Enum, template<Enum> class T, Enum Default>
    template <Enum E>
    T<E> &any_of<Enum, T, Default>::get_impl(any_of_impl::allocated_ptr_storage_type) {
        static_assert(std::is_same<storage_for<E>, any_of_impl::allocated_ptr_storage_type>::value, "Use in-place storage.");
        assert_type_is(E);
        assert_holds_memory();
        return *reinterpret_cast<T<E> *>(storage_allocated());
    }

    template <class Enum, template<Enum> class T, Enum Default>
    template <Enum E, class U>
    void any_of<Enum, T, Default>::set_impl(U &&obj, any_of_impl::in_place_obj_storage_type) {
        static_assert(std::is_same<storage_for<E>, any_of_impl::in_place_obj_storage_type>::value, "Use allocated storage.");
        // Make sure the memory that may have been allocated by other T<E>s is freed, we will use the storage in place
        free();
        // Can call trivial assignment operator
        *reinterpret_cast<T<E> *>(storage_in_place()) = std::forward<U>(obj);
        _active = E;
    }

    template <class Enum, template<Enum> class T, Enum Default>
    template <Enum E, class U>
    void any_of<Enum, T, Default>::set_impl(U &&obj, any_of_impl::allocated_ptr_storage_type) {
        static_assert(std::is_same<storage_for<E>, any_of_impl::allocated_ptr_storage_type>::value, "Use in-place storage.");
        // It is critical to check that memory is being held before actually getting that pointer
        if (type() == E and holds_memory()) {
            // Can call assignment operator
            *reinterpret_cast<T<E> *>(storage_allocated()) = std::forward<U>(obj);
        } else {
            // We must allocate the memory anew, because the E in T<E> changed or we are being called in the cctor
            free();
            storage_allocated() = new T<E>(std::forward<U>(obj));
            _deleter = get_default_deleter<E>();
            _active = E;
        }
    }

    template <class Enum, template<Enum> class T, Enum Default>
    void any_of<Enum, T, Default>::free() {
        // Deleter is defined only if we stored a pointer
        if (holds_memory()) {
            assert(_deleter);
            _deleter(storage_allocated());
            _deleter = nullptr;
        }
        // Always set this to nullptr so we being with a consistent state
        storage_allocated() = nullptr;
    }

    template <class Enum, template<Enum> class T, Enum Default>
    template <Enum E>
    constexpr typename any_of<Enum, T, Default>::deleter_type any_of<Enum, T, Default>::get_default_deleter() {
        return &default_deleter_fn<E>;
    }

    template <class Enum, template<Enum> class T, Enum Default>
    template <Enum E>
    void any_of<Enum, T, Default>::default_deleter_fn(void *ptr) {
        auto *typed_ptr = reinterpret_cast<T<E> *>(ptr);
        delete typed_ptr;
    }

    template <class Enum, template<Enum> class T, Enum Default>
    bool any_of<Enum, T, Default>::holds_memory() const {
        return _deleter != nullptr;
    }

    template <class Enum, template<Enum> class T, Enum Default>
    void const *any_of<Enum, T, Default>::storage_allocated() const {
        return *reinterpret_cast<void const * const *>(&_storage);
    }

    template <class Enum, template<Enum> class T, Enum Default>
    void * &any_of<Enum, T, Default>::storage_allocated() {
        return *reinterpret_cast<void * *>(&_storage);
    }

    template <class Enum, template<Enum> class T, Enum Default>
    void const *any_of<Enum, T, Default>::storage_in_place() const {
        return reinterpret_cast<void const *>(&_storage);
    }

    template <class Enum, template<Enum> class T, Enum Default>
    void *any_of<Enum, T, Default>::storage_in_place() {
        return reinterpret_cast<void *>(&_storage);
    }
}

#endif//MLAB_ANY_OF_HPP
