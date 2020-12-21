//
// Created by Pietro Saccardi on 21/12/2020.
//

#ifndef APERTURAPORTA_CHANNEL_HPP
#define APERTURAPORTA_CHANNEL_HPP

#include <chrono>
#include <algorithm>
#include <array>
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
        bool _ready_to_receive = false;
    protected:
        inline bool is_ready_to_receive() const;
        inline void set_ready_to_receive(bool v);

        /**
         * Should just wait for the channel to be ready for receiving, should not check for @ref is_ready_to_receive
         * nor set @ref set_ready_to_receive; this is called only once when necessary by @ref ensure_ready_to_receive.
         */
        virtual bool prepare_receive(std::chrono::milliseconds timeout) = 0;

        /**
         * Should put the channel in the appropriate state and send the data. Does not need to call
         * @ref set_ready_to_receive, the methods calling @ref send_raw must take care of marking the class as not
         * ready to receive.
         */
        virtual bool send_raw(bin_data const &data, std::chrono::milliseconds timeout) = 0;

        /** Overwrites the content of @p data with a sequence of length @p length.
         * Should receive data from the channel, can assume @ref prepare_receive has been called once and since then
         * only receive operations have been performed.
         */
        virtual bool receive_raw(bin_data &data, std::size_t length, std::chrono::milliseconds timeout) = 0;

        /**
         * Calls @ref prepare_receive if and only if @ref is_ready_to_receive is false; if @ref prepare_receive does
         * not time out, it sets the class as ready to receive with @ref set_ready_to_receive;
         */
        bool ensure_ready_to_receive(std::chrono::milliseconds timeout);
    public:

        std::pair<bin_data, bool> receive(std::size_t length, std::chrono::milliseconds timeout);
        std::pair<std::uint8_t, bool> receive(std::chrono::milliseconds timeout);
        /**
         * Overwrites @p data with a sequence of length @p length
         */
        bool receive(bin_data &data, std::size_t length, std::chrono::milliseconds timeout);
        bool send(bin_data const &data, std::chrono::milliseconds timeout);

        template <std::size_t Length>
        bool await_sequence(std::array<std::uint8_t, Length> const &match_seq, std::chrono::milliseconds timeout);
        template <std::size_t Length>
        bool receive(std::array<std::uint8_t, Length> &buffer, std::chrono::milliseconds timeout);

        virtual ~channel() = default;
    };

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

    bool channel::is_ready_to_receive() const {
        return _ready_to_receive;
    }
    void channel::set_ready_to_receive(bool v) {
        _ready_to_receive = v;
    }

    template <std::size_t Length>
    bool channel::await_sequence(std::array<std::uint8_t, Length> const &match_seq, std::chrono::milliseconds timeout) {
        reduce_timeout rt{timeout};
        std::size_t seq_length = 0;
        std::array<std::uint8_t, Length> read_seq{};
        while (rt) {
            const auto byte_success = receive(rt.remaining());
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
    bool channel::receive(std::array<std::uint8_t, Length> &buffer, std::chrono::milliseconds timeout) {
        reduce_timeout rt{timeout};
        auto it = std::begin(buffer);
        while (rt and it != std::end(buffer)) {
            const auto byte_success = receive(rt.remaining());
            if (byte_success.first) {
                *(it++) = byte_success.second;
            }
        }
        return it == std::end(buffer);
    }

}


#endif //APERTURAPORTA_CHANNEL_HPP
