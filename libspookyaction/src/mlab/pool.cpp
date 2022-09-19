//
// Created by spak on 5/6/21.
//

#include <mlab/pool.hpp>

namespace mlab {

    namespace {
        [[nodiscard]] shared_buffer_pool &default_buffer_pool_internal() {
            static shared_buffer_pool _pool{std::make_shared<pool<bin_data>>()};
            return _pool;
        }
    }// namespace

    shared_buffer_pool default_buffer_pool() {
        // Use atomic variants for updating shared_ptr. In C++20, just replace with std::atomic<shared_buffer_pool>
        return std::atomic_load(&default_buffer_pool_internal());
    }

    void change_default_buffer_pool(shared_buffer_pool new_pool) {
        if (new_pool != nullptr) {
            // Use atomic variants for updating shared_ptr. In C++20, just replace with std::atomic<shared_buffer_pool>
            std::atomic_store(&default_buffer_pool_internal(), std::move(new_pool));
        }
    }

}