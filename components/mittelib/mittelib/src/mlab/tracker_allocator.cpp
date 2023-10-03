//
// Created by spak on 9/20/22.
//

#include <esp_log.h>
#include <mlab/tracker_allocator.hpp>

namespace mlab {

    mem_counter::mem_counter() : _current{0}, _peak{0} {}

    std::size_t mem_counter::current() const {
        return _current.load();
    }

    std::size_t mem_counter::peak() const {
        return _peak.load();
    }

    void mem_counter::update_peak(std::size_t new_current) {
        // https://stackoverflow.com/a/16190791/1749822
        std::size_t prev_value = _peak;
        while (prev_value < new_current and
               not _peak.compare_exchange_weak(prev_value, new_current)) {}
    }

    mem_counter &mem_counter::operator++() {
        update_peak(++_current);
        return *this;
    }

    mem_counter &mem_counter::operator--() {
        if (_current == 0) {
            ESP_LOGE("MLAB", "Double free!");
        } else {
            --_current;
        }
        return *this;
    }

    mem_counter &mem_counter::operator+=(std::size_t bytes) {
        update_peak(_current += bytes);
        return *this;
    }

    mem_counter &mem_counter::operator-=(std::size_t bytes) {
        if (_current < bytes) {
            ESP_LOGE("MLAB", "Double free!");
            _current = 0;
        } else {
            _current -= bytes;
        }
        return *this;
    }

    std::string mem_counter::format_mem(std::size_t bytes) {
        static auto constexpr bufsize = 32;
        char buffer[bufsize];
        if (bytes < 1024) {
            std::snprintf(buffer, bufsize, "%u B", bytes);
        } else if (bytes < 1024 * 1024) {
            std::snprintf(buffer, bufsize, "%1.1f KB", double(bytes) / (1024));
        } else {
            std::snprintf(buffer, bufsize, "%1.2f MB", double(bytes) / (1024 * 1024));
        }
        std::string retval{buffer};
        return retval;
    }

    void mem_stats::print_stats() const {
        const auto use_mem = mem_counter::format_mem(_total.current());
        const auto peak_mem = mem_counter::format_mem(_total.peak());
        std::size_t total_mem_worst_case = 0;
        ESP_LOGI("MLAB", "Total memory in use: %s (peak: %s)", use_mem.c_str(), peak_mem.c_str());
        for (std::size_t i = 0; i < _blocks.size(); ++i) {
            if (i < _blocks.size() - 1) {
                total_mem_worst_case += (1 << i) * _blocks[i].peak();
                const auto bound = mem_counter::format_mem(1 << i);
                const auto block_use_mem = mem_counter::format_mem(_blocks[i].current() * (1 << i));
                const auto block_peak_mem = mem_counter::format_mem(_blocks[i].peak() * (1 << i));
                ESP_LOGI("MLAB", "Blocks <= %s: %u (peak: %u), < %s (peak < %s)",
                         bound.c_str(), _blocks[i].current(), _blocks[i].peak(), block_use_mem.c_str(), block_peak_mem.c_str());
            } else {
                const auto bound = mem_counter::format_mem(1 << (i - 1));
                ESP_LOGI("MLAB", "Blocks  > %s: %u (peak: %u)",
                         bound.c_str(), _blocks[i].current(), _blocks[i].peak());
            }
        }
        const auto total_mem_worst_peak = mem_counter::format_mem(1 << (_blocks.size() - 2));
        const auto total_mem_formatted = mem_counter::format_mem(total_mem_worst_case);
        ESP_LOGI("MLAB", "Total memory required to accommodate all peaks <= %s: %s",
                 total_mem_worst_peak.c_str(), total_mem_formatted.c_str());
    }

    mem_counter const &mem_stats::by_size(std::size_t alloc_size) const {
        // Silly but safe
        for (std::size_t i = 0; i < _blocks.size(); ++i) {
            if (alloc_size <= (1 << i)) {
                return _blocks[i];
            }
        }
        return _blocks.back();
    }

    mem_counter &mem_stats::by_size(std::size_t alloc_size) {
        return const_cast<mem_counter &>(static_cast<const mem_stats *>(this)->by_size(alloc_size));
    }

    mem_stats &mem_stats::instance() {
        static mem_stats _instance{};
        return _instance;
    }

    void mem_stats::allocate(std::size_t bytes) {
        _total += bytes;
        ++by_size(bytes);
    }

    void mem_stats::deallocate(std::size_t bytes) {
        _total -= bytes;
        --by_size(bytes);
    }
    mem_counter const &mem_stats::total() const {
        return _total;
    }
    mem_counter const &mem_stats::block_by_size(std::size_t bytes) const {
        return by_size(bytes);
    }
}// namespace mlab
