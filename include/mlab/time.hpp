//
// Created by spak on 3/7/21.
//

#ifndef MLAB_TIME_HPP
#define MLAB_TIME_HPP

#include <chrono>

namespace mlab {
    using ms = std::chrono::milliseconds;
    using namespace std::chrono_literals;

    class timer {
        std::chrono::time_point<std::chrono::high_resolution_clock> _timestamp;

    public:
        inline timer();

        [[nodiscard]] inline ms elapsed() const;
    };

    class reduce_timeout {
        ms _timeout;
        timer _timer;

    public:
        inline explicit reduce_timeout(ms timeout);

        [[nodiscard]] inline ms remaining() const;

        [[nodiscard]] inline ms elapsed() const;

        inline explicit operator bool() const;
    };

}// namespace mlab

namespace mlab {

    reduce_timeout::reduce_timeout(ms timeout) : _timeout{timeout},
                                                 _timer{} {}

    timer::timer() : _timestamp{std::chrono::high_resolution_clock::now()} {}

    ms reduce_timeout::remaining() const {
        if (*this) {
            return _timeout - _timer.elapsed();
        }
        return 0s;
    }

    ms reduce_timeout::elapsed() const {
        return _timer.elapsed();
    }

    reduce_timeout::operator bool() const {
        return _timer.elapsed() < _timeout;
    }

    ms timer::elapsed() const {
        const auto elapsed = std::chrono::high_resolution_clock::now() - _timestamp;
        return std::chrono::duration_cast<ms>(elapsed);
    }

}// namespace mlab

#endif//MLAB_TIME_HPP
