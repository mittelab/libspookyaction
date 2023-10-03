//
// Created by spak on 9/23/21.
//

#ifndef MLAB_UNIQUE_TRACKER
#define MLAB_UNIQUE_TRACKER

#include <atomic>
#include <esp_log.h>
#include <memory>

namespace mlab {

    class uniquely_tracked_swap_hold;

    class [[deprecated("Wrap the object in a std::unique_ptr instead.")]] uniquely_tracked {
        std::unique_ptr<std::atomic<std::uintptr_t>> _stored_ptr_to_self;
        friend class uniquely_tracked_swap_hold;

    protected:
        [[nodiscard]] uniquely_tracked_swap_hold swap(uniquely_tracked & other);

        [[nodiscard]] void *tracker() const;

    public:
        uniquely_tracked();

        [[nodiscard]] static std::uintptr_t track_base(void *tracker);

        template <class T>
        [[nodiscard]] static T *track(void *tracker);

        uniquely_tracked(uniquely_tracked &&) noexcept = delete;
        uniquely_tracked &operator=(uniquely_tracked &&) noexcept = delete;
        uniquely_tracked(uniquely_tracked const &) = delete;
        uniquely_tracked &operator=(uniquely_tracked const &) = delete;
    };

    class [[deprecated("Wrap the object in a std::unique_ptr instead.")]] uniquely_tracked_swap_hold {
        friend class uniquely_tracked;
        uniquely_tracked *_l = nullptr;
        uniquely_tracked *_r = nullptr;

        uniquely_tracked_swap_hold(uniquely_tracked & l, uniquely_tracked & r);

    public:
        uniquely_tracked_swap_hold() = default;
        uniquely_tracked_swap_hold(uniquely_tracked_swap_hold const &) noexcept = delete;
        uniquely_tracked_swap_hold &operator=(uniquely_tracked_swap_hold const &) noexcept = delete;
        uniquely_tracked_swap_hold(uniquely_tracked_swap_hold &&) noexcept = default;
        uniquely_tracked_swap_hold &operator=(uniquely_tracked_swap_hold &&) noexcept = default;

        ~uniquely_tracked_swap_hold();
    };

}// namespace mlab

namespace mlab {


    template <class T>
    T *uniquely_tracked::track(void *tracker) {
        /**
         * @note It is not possible to get at compile time the offset between a certain class type and its base class.
         * There are some workaround with compiler support, but that gets pretty tricky. So we would like to compute
         * that at runtime. Ideally we would make offset_in_t a `static` storage duration, but observe that this will
         * actually introduce locking around the variable! Which implies that this method cannot be called from
         * weird places, e.g. interrupts. Therefore we evaluate this locally. I'm hoping the compiler can figure this
         * out and set it to a const.
         */
        const std::size_t offset_in_t = []() {
            // Reinterpret_cast not allowed in constexpr
            auto *dummy_t = reinterpret_cast<T *>(sizeof(T));
            auto *dummy_uniquely_tracked = static_cast<uniquely_tracked *>(dummy_t);
            return reinterpret_cast<std::uintptr_t>(dummy_uniquely_tracked) - reinterpret_cast<std::uintptr_t>(dummy_t);
        }();
        const std::uintptr_t base = track_base(tracker);
        if (base == 0x0 or base < offset_in_t) {
            ESP_LOGE("MLAB", "Unable to track typed object of size %d, the base pointer is 0x%x with an offset of %d.",
                     sizeof(T), base, offset_in_t);
            return nullptr;
        }
        return reinterpret_cast<T *>(base - offset_in_t);
    }
}// namespace mlab

#endif//MLAB_UNIQUE_TRACKER
