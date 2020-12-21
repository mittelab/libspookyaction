//
// Created by Pietro Saccardi on 21/12/2020.
//

#ifndef APERTURAPORTA_CHANNEL_HPP
#define APERTURAPORTA_CHANNEL_HPP

#include <chrono>
#include <algorithm>
#include "bin_data.hpp"

namespace pn532 {
    class bin_data;

    static auto constexpr one_sec = std::chrono::milliseconds{1000};

    class reduce_timeout {
        std::chrono::milliseconds _timeout;
        std::chrono::time_point<std::chrono::high_resolution_clock> _timestamp;
        inline std::chrono::milliseconds elapsed() const;
    public:
        inline explicit reduce_timeout(std::chrono::milliseconds timeout);
        inline std::chrono::milliseconds remaining() const;
        inline explicit operator bool() const;
    };

    class channel {
    public:
        inline virtual std::pair<bin_data, bool> read(std::size_t length, std::chrono::milliseconds timeout);
        virtual bool read(bin_data &data, std::size_t length, std::chrono::milliseconds timeout) = 0;
        virtual bool write(bin_data const &data, std::chrono::milliseconds timeout) = 0;
        virtual std::pair<std::uint8_t, bool> read(std::chrono::milliseconds timeout) = 0;

        template <std::size_t Length>
        bool await_sequence(std::array<std::uint8_t, Length> const &match_seq, std::chrono::milliseconds timeout);
        template <std::size_t Length>
        bool read(std::array<std::uint8_t, Length> &buffer, std::chrono::milliseconds timeout);


        virtual ~channel() = default;
    };


    std::pair<bin_data, bool> channel::read(std::size_t length, std::chrono::milliseconds timeout) {
        std::pair<bin_data, bool> retval{bin_data{}, false};
        retval.second = read(retval.first, length, timeout);
        return retval;
    }

    reduce_timeout::reduce_timeout(std::chrono::milliseconds timeout) :
        _timeout{timeout},
        _timestamp{std::chrono::high_resolution_clock::now()}
    {}

    std::chrono::milliseconds reduce_timeout::remaining() const {
        if (*this) {
            return _timeout - elapsed();
        }
        return std::chrono::milliseconds{0};
    }

    reduce_timeout::operator bool() const {
        return elapsed() < _timeout;
    }
    std::chrono::milliseconds reduce_timeout::elapsed() const {
        const auto elapsed = std::chrono::high_resolution_clock::now() - _timestamp;
        return std::chrono::duration_cast<std::chrono::milliseconds>(elapsed);
    }


    template <std::size_t Length>
    bool channel::await_sequence(std::array<std::uint8_t, Length> const &match_seq, std::chrono::milliseconds timeout) {
        reduce_timeout rt{timeout};
        std::size_t seq_length = 0;
        std::array<std::uint8_t, Length> read_seq{};
        while (rt) {
            const auto byte_success = read(rt.remaining());
            if (byte_success.second) {
                if (seq_length < Length) {
                    read_seq[seq_length++] = byte_success.first;
                } else {
                    // Shift and push
                    std::rotate(std::begin(read_seq), std::begin(read_seq) + 1, std::end(read_seq));
                    read_seq[Length - 1] = byte_success.first;
                    // Compare
                    if (read_seq == match_seq) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    template <std::size_t Length>
    bool channel::read(std::array<std::uint8_t, Length> &buffer, std::chrono::milliseconds timeout) {
        reduce_timeout rt{timeout};
        auto it = std::begin(buffer);
        while (rt and it != std::end(buffer)) {
            const auto byte_success = read(rt.remaining());
            if (byte_success.first) {
                *(it++) = byte_success.second;
            }
        }
        return it == std::end(buffer);
    }

}


#endif //APERTURAPORTA_CHANNEL_HPP
