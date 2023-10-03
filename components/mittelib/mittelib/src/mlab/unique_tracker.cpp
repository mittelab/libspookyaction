//
// Created by spak on 9/23/21.
//

#include <chrono>
#include <esp_log.h>
#include <thread>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <mlab/unique_tracker.hpp>

namespace mlab {

    uniquely_tracked::uniquely_tracked() : _stored_ptr_to_self{
                                                   std::make_unique<std::atomic<std::uintptr_t>>(reinterpret_cast<std::uintptr_t>(this))} {}

    void *uniquely_tracked::tracker() const {
        return reinterpret_cast<void *>(_stored_ptr_to_self.get());
    }

    std::uintptr_t uniquely_tracked::track_base(void *tracker) {
        auto &container = *reinterpret_cast<std::atomic<std::uintptr_t> *>(tracker);
        // Ensure the object is not incomplete due to being moved
        for (unsigned i = 0; container.load() == 0x0 and i < 10; ++i) {
            // Wait 0, 2ms, 4ms, 8ms, ... 512ms
            std::this_thread::sleep_for(std::chrono::milliseconds{std::min(i, 1u) * 1u << i});
        }
        if (container.load() == 0x0) {
            // Has waited at least 1s
            ESP_LOGE("MLAB", "Waiting indefinitely: uniquely_tracked was not not notified move is complete in 1s");
        }
        return container.load();
    }

    uniquely_tracked_swap_hold uniquely_tracked::swap(uniquely_tracked &other) {
        if (_stored_ptr_to_self->load() == 0x0 or other._stored_ptr_to_self->load() == 0x0) {
            ESP_LOGE("MLAB", "Attempt to perform multiple swaps of uniquely_tracked without completion");
            return {};
        }
        // Flag that a move is ongoing
        _stored_ptr_to_self->store(0x0);
        other._stored_ptr_to_self->store(0x0);
        // Important: we need to swap the pointers otherwise the corresponding memory locations (i.e. the trackers)
        // do not match.
        _stored_ptr_to_self.swap(other._stored_ptr_to_self);
        return {*this, other};
    }

    uniquely_tracked_swap_hold::uniquely_tracked_swap_hold(uniquely_tracked &l, uniquely_tracked &r) : _l{&l}, _r{&r} {}

    uniquely_tracked_swap_hold::~uniquely_tracked_swap_hold() {
        // Move is complete: update each pointer with the corresponding new address.
        if (_l != nullptr) {
            *_l->_stored_ptr_to_self = reinterpret_cast<std::uintptr_t>(_l);
        }
        if (_r != nullptr) {
            *_r->_stored_ptr_to_self = reinterpret_cast<std::uintptr_t>(_r);
        }
    }
}// namespace mlab

#pragma GCC diagnostic pop
