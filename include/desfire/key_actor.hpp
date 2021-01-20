//
// Created by Pietro Saccardi on 20/01/2021.
//

#ifndef APERTURAPORTA_KEY_ACTOR_HPP
#define APERTURAPORTA_KEY_ACTOR_HPP

#include "bits.hpp"

namespace desfire {

    struct no_key_t{};
    static constexpr no_key_t no_key{};

    template <class UIntT, unsigned LShift, class SpecialT, class Subclass>
    class key_actor_base {
        static constexpr std::uint8_t max_key_index = 0xd;
        static constexpr std::uint8_t special_value = 0xe;
        static constexpr std::uint8_t no_key_value = 0xf;
        static constexpr UIntT mask = UIntT{0b1111} << LShift;

        static_assert(bits::max_keys_per_app == max_key_index + 1, "Implementation uses 0xE and 0xF for special purposes.");
        static_assert(LShift <= (sizeof(UIntT) * 8 - 4) and std::is_unsigned<UIntT>::value, "Too large LShift or not unsigned");

        UIntT _repr;

    protected:
        inline void set(std::uint8_t v);
        inline std::uint8_t get() const;

    public:

        inline key_actor_base(std::uint8_t key_index = 0);
        inline key_actor_base(SpecialT);
        inline key_actor_base(no_key_t);

        inline Subclass &operator=(std::uint8_t key_index);
        inline Subclass &operator=(SpecialT);
        inline Subclass &operator=(no_key_t);

        inline bool operator==(Subclass const &other) const;
        inline bool operator!=(Subclass const &other) const;
    };

    template <class UIntT, unsigned LShift, class SpecialT>
    struct key_actor_mask : public key_actor_base<UIntT, LShift, SpecialT, key_actor_mask<UIntT, LShift, SpecialT>> {
        using base = key_actor_base<UIntT, LShift, SpecialT, key_actor_mask<UIntT, LShift, SpecialT>>;
        using base::base;
        using base::operator=;
        using base::operator==;
        using base::operator!=;
    };


}

namespace desfire {

    template <class UIntT, unsigned LShift, class SpecialT, class Subclass>
    key_actor_base<UIntT, LShift, SpecialT, Subclass>::key_actor_base(std::uint8_t key_index) : _repr{} {
        *this = key_index;
    }

    template <class UIntT, unsigned LShift, class SpecialT, class Subclass>
    key_actor_base<UIntT, LShift, SpecialT, Subclass>::key_actor_base(SpecialT special) : _repr{} {
        *this = special;
    }

    template <class UIntT, unsigned LShift, class SpecialT, class Subclass>
    key_actor_base<UIntT, LShift, SpecialT, Subclass>::key_actor_base(no_key_t) : _repr{} {
        *this = no_key;
    }

    template <class UIntT, unsigned LShift, class SpecialT, class Subclass>
    void key_actor_base<UIntT, LShift, SpecialT, Subclass>::set(std::uint8_t v) {
        _repr = (_repr & ~mask) | ((UIntT(v) << LShift) & mask);
    }

    template <class UIntT, unsigned LShift, class SpecialT, class Subclass>
    std::uint8_t key_actor_base<UIntT, LShift, SpecialT, Subclass>::get() const {
        return std::uint8_t((_repr & mask) >> LShift);
    }

    template <class UIntT, unsigned LShift, class SpecialT, class Subclass>
    Subclass &key_actor_base<UIntT, LShift, SpecialT, Subclass>::operator=(std::uint8_t key_index) {
        static_assert(std::is_base_of<key_actor_base, Subclass>::value, "Must subclass!");
        if (key_index > max_key_index) {
            DESFIRE_LOGE("Specified key index %u is not valid, master key (0) assumed.", key_index);
            key_index = 0;
        }
        set(key_index);
        return reinterpret_cast<Subclass &>(*this);
    }

    template <class UIntT, unsigned LShift, class SpecialT, class Subclass>
    Subclass &key_actor_base<UIntT, LShift, SpecialT, Subclass>::operator=(SpecialT) {
        static_assert(std::is_base_of<key_actor_base, Subclass>::value, "Must subclass!");
        set(special_value);
        return reinterpret_cast<Subclass &>(*this);
    }

    template <class UIntT, unsigned LShift, class SpecialT, class Subclass>
    Subclass &key_actor_base<UIntT, LShift, SpecialT, Subclass>::operator=(no_key_t) {
        static_assert(std::is_base_of<key_actor_base, Subclass>::value, "Must subclass!");
        set(no_key_value);
        return reinterpret_cast<Subclass &>(*this);
    }

    template <class UIntT, unsigned LShift, class SpecialT, class Subclass>
    bool key_actor_base<UIntT, LShift, SpecialT, Subclass>::operator==(Subclass const &other) const {
        return get() == other.get();
    }

    template <class UIntT, unsigned LShift, class SpecialT, class Subclass>
    bool key_actor_base<UIntT, LShift, SpecialT, Subclass>::operator!=(Subclass const &other) const {
        return get() != other.get();
    }
}

#endif //APERTURAPORTA_KEY_ACTOR_HPP
