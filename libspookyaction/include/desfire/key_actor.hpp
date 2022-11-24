//
// Created by Pietro Saccardi on 20/01/2021.
//

#ifndef DESFIRE_KEY_ACTOR_HPP
#define DESFIRE_KEY_ACTOR_HPP

#include "bits.hpp"
#include <desfire/log.h>

namespace desfire {

    struct no_key_t {};
    static constexpr no_key_t no_key{};

    template <class SpecialT>
    class key_actor {
        static constexpr std::uint8_t max_key_index = 0xd;
        static constexpr std::uint8_t special_value = 0xe;
        static constexpr std::uint8_t no_key_value = 0xf;

        static_assert(bits::max_keys_per_app == max_key_index + 1, "Implementation uses 0xE and 0xF for special purposes.");

        unsigned _repr : 4;

    public:
        inline void set_nibble(std::uint8_t v);
        [[nodiscard]] inline std::uint8_t get_nibble() const;

        constexpr key_actor();
        constexpr key_actor(std::uint8_t key_index);
        constexpr key_actor(SpecialT);
        constexpr key_actor(no_key_t);

        inline key_actor &operator=(std::uint8_t key_index);
        inline key_actor &operator=(SpecialT);
        inline key_actor &operator=(no_key_t);

        inline bool operator==(key_actor const &other) const;
        inline bool operator!=(key_actor const &other) const;
    };

}// namespace desfire

namespace desfire {

    template <class SpecialT>
    constexpr key_actor<SpecialT>::key_actor(std::uint8_t key_index) : _repr{unsigned(key_index & 0b1111)} {
        // TODO: when C++20 is enabled, used is_constant_evaluated to issue a warning if key_index is out of range
    }

    template <class SpecialT>
    constexpr key_actor<SpecialT>::key_actor() : _repr{0} {}

    template <class SpecialT>
    constexpr key_actor<SpecialT>::key_actor(SpecialT) : _repr{special_value} {}

    template <class SpecialT>
    constexpr key_actor<SpecialT>::key_actor(no_key_t) : _repr{no_key_value} {}

    template <class SpecialT>
    void key_actor<SpecialT>::set_nibble(std::uint8_t v) {
        _repr = v & 0b1111;
    }

    template <class SpecialT>
    std::uint8_t key_actor<SpecialT>::get_nibble() const {
        return _repr;
    }

    template <class SpecialT>
    key_actor<SpecialT> &key_actor<SpecialT>::operator=(std::uint8_t key_index) {
        if (key_index > max_key_index) {
            DESFIRE_LOGE("Specified key index %u is not valid, master key (0) assumed.", key_index);
            key_index = 0;
        }
        set_nibble(key_index);
        return *this;
    }

    template <class SpecialT>
    key_actor<SpecialT> &key_actor<SpecialT>::operator=(SpecialT) {
        _repr = no_key_value;
        return *this;
    }

    template <class SpecialT>
    key_actor<SpecialT> &key_actor<SpecialT>::operator=(no_key_t) {
        _repr = no_key_value;
        return *this;
    }

    template <class SpecialT>
    bool key_actor<SpecialT>::operator==(key_actor const &other) const {
        return get_nibble() == other.get_nibble();
    }

    template <class SpecialT>
    bool key_actor<SpecialT>::operator!=(key_actor const &other) const {
        return get_nibble() != other.get_nibble();
    }
}// namespace desfire

#endif//DESFIRE_KEY_ACTOR_HPP
