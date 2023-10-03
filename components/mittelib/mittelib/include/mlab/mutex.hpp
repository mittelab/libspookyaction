//
// Created by spak on 10/6/21.
//

#ifndef MLAB_MUTEX_HPP
#define MLAB_MUTEX_HPP

#include <mutex>

namespace mlab {

    template <class Mutex>
    struct [[deprecated("Use std::unique_lock with std::try_to_lock.")]] scoped_try_lock {
        Mutex &mutex;
        const bool did_lock;

        explicit operator bool() const {
            return did_lock;
        }

        explicit scoped_try_lock(Mutex & mutex_) : mutex{mutex_}, did_lock{mutex.try_lock()} {}

        ~scoped_try_lock() {
            if (did_lock) {
                mutex.unlock();
            }
        }
    };
}// namespace mlab
#endif//MLAB_MUTEX_HPP
