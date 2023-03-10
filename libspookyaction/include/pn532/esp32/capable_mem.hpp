//
// Created by spak on 3/26/21.
//

#ifndef PN532_ESP32_CAPABLE_MEM_HPP
#define PN532_ESP32_CAPABLE_MEM_HPP

#include <cstdint>
#include <esp_heap_caps.h>
#include <limits>
#include <type_traits>

/**
 * Data structures used in implementing @ref pn532::channel for the ESP32 platform.
 */
namespace pn532::esp32 {

    /**
     * @brief An allocator class that wraps `heap_caps_malloc`, to add capabilities to the allocated memory.
     * This can be used to allocate e.g. DMA-accessible memory (`MALLOC_CAP_DMA`).
     * @tparam T Type to allocate
     */
    template <class T>
    class capable_allocator {
        std::uint32_t _caps = 0;

    public:
        using value_type = T;

        /**
         * @return The capabilities with which this allocator was constructed via @ref capable_allocator(std::uint32_t).
         */
        [[nodiscard]] constexpr std::uint32_t capabilities() const;

        /**
         * Constructs a new allocator with @ref capabilities set to 0.
         */
        constexpr capable_allocator() = default;

        /**
         * Construct a new allocator which passed @p caps to `heap_caps_malloc`.
         * @param caps Any combination of the `MALLOC_CAP_*` defines from `esp_heap_caps.h`.
         */
        constexpr explicit capable_allocator(std::uint32_t caps);

        /**
         * Copies or converts the allocator to a different type, inheriting the same capabilities.
         * @tparam U Another allocator type
         * @param other Another allocator.
         */
        template <class U>
        constexpr explicit capable_allocator(capable_allocator<U> const &other) noexcept;

        /**
         * @name Comparison operators
         * Two allocators are said to be the same if and only if they have the same type and the same @ref capabilities.
         */
        ///@{
        template <class U>
        constexpr bool operator==(capable_allocator<U> const &) noexcept;

        template <class U>
        constexpr bool operator!=(capable_allocator<U> const &) noexcept;
        ///@}

        /**
         * @name Allocator interface
         * Methods to allocate and deallocate memory.
         */
        ///@{
        [[nodiscard]] T *allocate(std::size_t n);

        void deallocate(T *p, std::size_t n) noexcept;
        ///@}
    };


}// namespace pn532::esp32

namespace pn532::esp32 {
    template <class T>
    constexpr capable_allocator<T>::capable_allocator(uint32_t caps) : _caps{caps} {}

    template <class T>
    constexpr std::uint32_t capable_allocator<T>::capabilities() const {
        return _caps;
    }

    template <class T>
    template <class U>
    constexpr capable_allocator<T>::capable_allocator(capable_allocator<U> const &other) noexcept
        : _caps{other._caps} {}

    template <class T>
    T *capable_allocator<T>::allocate(std::size_t n) {
        if (n < std::numeric_limits<std::size_t>::max() / sizeof(T)) {
            return reinterpret_cast<T *>(heap_caps_malloc(sizeof(T) * n, _caps));
        }
        return nullptr;
    }

    template <class T>
    void capable_allocator<T>::deallocate(T *p, std::size_t n) noexcept {
        heap_caps_free(p);
    }


    template <class T>
    template <class U>
    constexpr bool capable_allocator<T>::operator==(capable_allocator<U> const &other) noexcept {
        return std::is_same_v<T, U> and _caps == other._caps;
    }


    template <class T>
    template <class U>
    constexpr bool capable_allocator<T>::operator!=(capable_allocator<U> const &other) noexcept {
        return not std::is_same_v<T, U> or _caps != other._caps;
    }

}// namespace pn532::esp32

#endif//PN532_ESP32_CAPABLE_MEM_HPP
