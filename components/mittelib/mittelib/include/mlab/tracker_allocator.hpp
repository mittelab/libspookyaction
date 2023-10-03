//
// Created by spak on 9/20/22.
//

#ifndef MITTELIB_TRACKER_ALLOCATOR_HPP
#define MITTELIB_TRACKER_ALLOCATOR_HPP

#include <array>
#include <atomic>
#include <memory>

namespace mlab {

    class mem_counter {
        std::atomic<std::size_t> _current;
        std::atomic<std::size_t> _peak;

    public:
        [[nodiscard]] std::size_t current() const;
        [[nodiscard]] std::size_t peak() const;

        mem_counter();

        void update_peak(std::size_t new_current);

        mem_counter &operator++();

        mem_counter &operator--();

        mem_counter &operator+=(std::size_t bytes);

        mem_counter &operator-=(std::size_t bytes);

        [[nodiscard]] static std::string format_mem(std::size_t bytes);
    };

    class mem_stats {
        std::array<mem_counter, 20> _blocks;
        mem_counter _total;

        [[nodiscard]] mem_counter const &by_size(std::size_t bytes) const;
        [[nodiscard]] mem_counter &by_size(std::size_t bytes);

    public:
        [[nodiscard]] mem_counter const &total() const;
        [[nodiscard]] mem_counter const &block_by_size(std::size_t bytes) const;

        void print_stats() const;

        [[nodiscard]] static mem_stats &instance();

        void allocate(std::size_t bytes);

        void deallocate(std::size_t bytes);
    };

    template <class T>
    struct tracker_allocator {
        using value_type = T;

        tracker_allocator() noexcept = default;
        tracker_allocator(tracker_allocator &&) noexcept = default;
        tracker_allocator(tracker_allocator const &) noexcept = default;

        template <class U>
        tracker_allocator(tracker_allocator<U> const &) noexcept {}

        value_type *allocate(std::size_t n) {
            mem_stats::instance().allocate(sizeof(value_type) * n);
            return static_cast<value_type *>(::operator new(n * sizeof(value_type)));
        }

        void deallocate(value_type *p, std::size_t n) {
            mem_stats::instance().deallocate(sizeof(value_type) * n);
            ::operator delete(p);
        }
    };


    template <class T, class U>
    bool operator==(tracker_allocator<T> const &, tracker_allocator<U> const &) noexcept {
        return true;
    }

    template <class T, class U>
    bool operator!=(tracker_allocator<T> const &x, tracker_allocator<U> const &y) noexcept {
        return !(x == y);
    }


}// namespace mlab

#endif//MITTELIB_TRACKER_ALLOCATOR_HPP
