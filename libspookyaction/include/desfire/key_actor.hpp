//
// Created by Pietro Saccardi on 20/01/2021.
//

#ifndef DESFIRE_KEY_ACTOR_HPP
#define DESFIRE_KEY_ACTOR_HPP

#include <desfire/bits.hpp>
#include <desfire/log.h>

namespace desfire {

    /**
     * @brief Monostate structure which implies that no key has the given right.
     * It is used through the unique instance @ref no_key in @ref key_actor.
     */
    struct no_key_t {};

    /**
     * Used in @ref key_actor to represent that no key has the given right.
     */
    static constexpr no_key_t no_key{};

    /**
     * Variant structure that at a given time represents either one key index, or one of two special values,
     * one of which being @ref no_key (i.e. no key has the given right) or a custom meaning implied by the template parameter.
     * This class can be packed into a nibble (i.e. a 4 bits sequence).
     * @tparam SpecialT Monostate structure type which represents the other special value used in alternative to the
     *  @ref no_key special value, e.g. @ref free_access_t or @ref same_key_t.
     */
    template <class SpecialT>
    class key_actor {
        static constexpr std::uint8_t max_key_index = 0xd;
        static constexpr std::uint8_t special_value = 0xe;
        static constexpr std::uint8_t no_key_value = 0xf;

        static_assert(bits::max_keys_per_app == max_key_index + 1, "Implementation uses 0xE and 0xF for special purposes.");

        unsigned _repr : 4;

    public:
        /**
         * Sets the value of this class based on the lower nibble of @p v.
         * @param v Value representing the key actor.
         */
        inline void set_nibble(std::uint8_t v);
        /**
         * Returns a byte whose lower nibble contains a numeric representation of this class.
         * @return A byte masked by 0xF, the lower 4 bits contain the representation of the key actor.
         */
        [[nodiscard]] inline std::uint8_t get_nibble() const;

        /**
         * Default-constructs this class with the key index 0.
         */
        constexpr key_actor();

        /**
         * Creates a key actor referencing the given @p key_index.
         * @param key_index A value between 0 and 13 (included).
         */
        constexpr key_actor(std::uint8_t key_index);

        /**
         * Prevent accidental conversions from bool.
         */
        key_actor(bool) = delete;

        /**
         * Constructs a key actor using the special value.
         */
        constexpr key_actor(SpecialT);

        /**
         * Constructs a key actor with the @ref no_key special value.
         */
        constexpr key_actor(no_key_t);

        /**
         * @name Assignment operators mimicking constructors
         * @{
         */
        inline key_actor &operator=(std::uint8_t key_index);
        key_actor &operator=(bool) = delete;
        inline key_actor &operator=(SpecialT);
        inline key_actor &operator=(no_key_t);
        /**
         * @}
         */

        /**
         * Returns a single character representing the actor for description purpose.
         * @return A hex value for the key index, or "N" for @ref no_key, or "S" for the special value.
         */
        [[nodiscard]] constexpr char describe() const;

        /**
         * @name Comparison operators
         * @{
         */
        inline bool operator==(key_actor const &other) const;
        inline bool operator!=(key_actor const &other) const;
        /**
         * @}
         */
    };

}// namespace desfire

namespace desfire {

    template <class SpecialT>
    constexpr key_actor<SpecialT>::key_actor(std::uint8_t key_index) : _repr{unsigned(key_index & 0b1111)} {
        if (not std::is_constant_evaluated()) {
            if (key_index >= desfire::bits::max_keys_per_app) {
                ESP_LOGW(DESFIRE_LOG_PREFIX, "Invalid key number %d", key_index);
            }
        }
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
        _repr = special_value;
        return *this;
    }

    template <class SpecialT>
    key_actor<SpecialT> &key_actor<SpecialT>::operator=(no_key_t) {
        _repr = no_key_value;
        return *this;
    }

    template <class SpecialT>
    constexpr char key_actor<SpecialT>::describe() const {
        if (_repr == special_value) {
            return 'S';
        } else if (_repr == no_key_value) {
            return 'N';
        } else {
            return "0123456789ABCDEF"[_repr];
        }
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
