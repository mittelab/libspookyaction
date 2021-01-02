//
// Created by Pietro Saccardi on 21/12/2020.
//

#include "pn532/channel.hpp"

namespace pn532 {

    std::pair<bin_data, bool> channel::receive(std::size_t length, std::chrono::milliseconds timeout) {
        std::pair<bin_data, bool> retval{bin_data{}, false};
        retval.second = receive(retval.first, length, timeout);
        return retval;
    }

    std::pair<std::uint8_t, bool> channel::receive(std::chrono::milliseconds timeout) {
        static bin_data _buffer = {std::uint8_t(0)};
        reduce_timeout rt{timeout};
        if (not ensure_ready_to_receive(rt.remaining())) {
            return {0, false};
        }
        if (not receive_raw(_buffer, 1, rt.remaining())) {
            return {0, false};
        }
        return {_buffer[0], true};
    }

    bool channel::receive(bin_data &data, std::size_t length, std::chrono::milliseconds timeout) {
        reduce_timeout rt{timeout};
        if (not ensure_ready_to_receive(rt.remaining())) {
            return false;
        }
        return receive_raw(data, length, rt.remaining());
    }

    bool channel::send(bin_data const &data, std::chrono::milliseconds timeout) {
        set_ready_to_receive(false);
        return send_raw(data, timeout);
    }

    bool channel::ensure_ready_to_receive(std::chrono::milliseconds timeout) {
        if (not is_ready_to_receive()) {
            if (prepare_receive(timeout)) {
                set_ready_to_receive(true);
                return true;
            }
            return false;
        }
        return true;
    }

}