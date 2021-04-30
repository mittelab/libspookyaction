//
// Created by spak on 3/26/21.
//

#ifndef PN532_ESP32_CAPABLE_MEM_HPP
#define PN532_ESP32_CAPABLE_MEM_HPP

#include <cstdint>
#include <esp_heap_caps.h>
#include <limits>
#include <type_traits>

namespace pn532::esp32 {

    template <class T>
    class capable_allocator {
        std::uint32_t _default_caps = 0;

    public:
        using value_type = T;

        capable_allocator() = default;

        explicit capable_allocator(std::uint32_t default_caps);

        template <class U>
        constexpr explicit capable_allocator(capable_allocator<U> const &other) noexcept;

        template <class U>
        constexpr bool operator==(capable_allocator<U> const &) noexcept;

        template <class U>
        constexpr bool operator!=(capable_allocator<U> const &) noexcept;

        [[nodiscard]] T *allocate(std::size_t n);

        void deallocate(T *p, std::size_t n) noexcept;
    };


}// namespace pn532::esp32

namespace pn532::esp32 {
    template <class T>
    capable_allocator<T>::capable_allocator(uint32_t default_caps) : _default_caps{default_caps} {}

    template <class T>
    template <class U>
    constexpr capable_allocator<T>::capable_allocator(capable_allocator<U> const &other) noexcept
        : _default_caps{other._default_caps} {}

    template <class T>
    T *capable_allocator<T>::allocate(std::size_t n) {
        if (n < std::numeric_limits<std::size_t>::max() / sizeof(T)) {
            return reinterpret_cast<T *>(heap_caps_malloc(sizeof(T) * n, _default_caps));
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
        return std::is_same_v<T, U>;
    }


    template <class T>
    template <class U>
    constexpr bool capable_allocator<T>::operator!=(capable_allocator<U> const &other) noexcept {
        return not std::is_same_v<T, U>;
    }

}// namespace pn532::esp32

#endif//PN532_ESP32_CAPABLE_MEM_HPP
