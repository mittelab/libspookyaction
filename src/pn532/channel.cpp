//
// Created by spak on 3/3/21.
//

#include "pn532/channel.hpp"
#include <pn532/bits_algo.hpp>

namespace pn532 {
    using mlab::bin_stream;
    using mlab::prealloc;
    using mlab::reduce_timeout;
    using mlab::result_success;

    using namespace std::chrono_literals;

    namespace {

        [[nodiscard]] bin_data &get_clean_buffer() {
            static bin_data _buffer{prealloc(384)};
            _buffer.clear();
            return _buffer;
        }

        std::size_t advance_past_start_of_packet_code(bin_stream &s) {
            auto const data = s.peek();
            auto it = std::search(std::begin(data), std::end(data),
                                  std::begin(bits::start_of_packet_code), std::end(bits::start_of_packet_code));
            if (it == std::end(data)) {
                PN532_LOGE("Unable to identify start of packet.");
                s.set_bad();
                return 0;
            }
            // Advance the stream to discard past the start of packet code
            const auto skipped_data = std::distance(std::begin(data), it) + bits::start_of_packet_code.size();
            s.seek(skipped_data, mlab::stream_ref::pos);
            return skipped_data;
        }

    }// namespace

    bin_data &operator<<(bin_data &bd, frame<frame_type::ack> const &) {
        return bd << prealloc(6)
                  << bits::preamble
                  << bits::start_of_packet_code
                  << bits::ack_packet_code
                  << bits::postamble;
    }

    bin_data &operator<<(bin_data &bd, frame<frame_type::nack> const &) {
        return bd << prealloc(6)
                  << bits::preamble
                  << bits::start_of_packet_code
                  << bits::nack_packet_code
                  << bits::postamble;
    }

    bin_data &operator<<(bin_data &bd, frame<frame_type::error> const &) {
        return bd << prealloc(6)
                  << bits::preamble
                  << bits::start_of_packet_code
                  << bits::length_and_checksum_short(1)
                  << bits::specific_app_level_err_code
                  << bits::compute_checksum(bits::specific_app_level_err_code)
                  << bits::postamble;
    }

    bin_data &operator<<(bin_data &bd, frame<frame_type::info> const &f) {
        const bool use_extended = f.data.size() > (0xff - 2 /* transport info + command code */);
        const std::uint8_t checksum_init = static_cast<std::uint8_t>(bits::transport::host_to_pn532) + static_cast<std::uint8_t>(f.command);
        if (use_extended) {
            auto const truncated_data = f.data.view(0, std::min(f.data.size(), bits::max_firmware_data_length));
            return bd << prealloc(12 + f.data.size())
                      << bits::preamble << bits::start_of_packet_code
                      << bits::fixed_extended_packet_length
                      << bits::length_and_checksum_long(truncated_data.size() + 2)
                      << f.transport
                      << f.command
                      << truncated_data
                      << bits::compute_checksum(checksum_init, std::begin(truncated_data), std::end(truncated_data))
                      << bits::postamble;
        } else {
            return bd << prealloc(9 + f.data.size())
                      << bits::preamble << bits::start_of_packet_code
                      << bits::length_and_checksum_short(f.data.size() + 2)
                      << f.transport
                      << f.command
                      << f.data
                      << bits::compute_checksum(checksum_init, std::begin(f.data), std::end(f.data))
                      << bits::postamble;
        }
    }
    bin_data &operator<<(bin_data &bd, any_frame const &f) {
        switch (f.type()) {
            case frame_type::ack:
                return bd << f.get<frame_type::ack>();
            case frame_type::nack:
                return bd << f.get<frame_type::nack>();
            case frame_type::info:
                return bd << f.get<frame_type::info>();
            case frame_type::error:
                return bd << f.get<frame_type::error>();
        }
        PN532_LOGE("Unhandled frame type.");
        return bd;
    }

    bin_stream &operator>>(bin_stream &s, frame_id &id) {
        id.type = frame_type::error;
        id.info_frame_data_size = 0;

        // Identify the start of packet
        const auto begin_of_frame_code = advance_past_start_of_packet_code(s);
        // Preamble is anything that precedes that packet.
        id.has_preamble = begin_of_frame_code > bits::start_of_packet_code.size();
        id.frame_total_length = begin_of_frame_code + 2 /* size of frame code */;

        if (id.has_preamble) {
            // If it has a preamble, it will have a postamble (of 1 byte)
            ++id.frame_total_length;
        }

        // Check if it has enough space to read the code.
        if (not s.good() or s.remaining() < 2) {
            return s;
        }

        // Read the code or length
        std::array<std::uint8_t, 2> code_or_length{0x00, 0x00};
        s >> code_or_length;

        // Check for special packet codes
        if (code_or_length == bits::ack_packet_code) {
            id.type = frame_type::ack;
            return s;
        }
        if (code_or_length == bits::nack_packet_code) {
            id.type = frame_type::ack;
            return s;
        }

        // Info or error frame.
        id.type = frame_type::info;
        bool checksum_pass = true;
        std::size_t info_frame_data_size = 0;

        if (code_or_length == bits::fixed_extended_packet_length) {
            id.frame_total_length += 3;
            if (s.remaining() < 3) {
                return s;
            }
            // Parse the length from the following bytes
            std::array<std::uint8_t, 3> ext_length_checksum{0x00, 0x00, 0x00};
            s >> ext_length_checksum;
            std::tie(info_frame_data_size, checksum_pass) = bits::check_length_checksum(ext_length_checksum);
        } else {
            std::tie(info_frame_data_size, checksum_pass) = bits::check_length_checksum(code_or_length);
        }
        if (not checksum_pass) {
            PN532_LOGE("Length checksum failed.");
            s.set_bad();
            return s;
        }
        // Ok now we know the length
        id.frame_total_length += info_frame_data_size + 1 /* checksum */;
        id.info_frame_data_size = info_frame_data_size;
        return s;
    }

    bin_stream &operator>>(std::tuple<bin_stream &, frame_id const &> s_id, any_frame &f) {
        // Unpack stream and frame id from tuple
        bin_stream &s = std::get<bin_stream &>(s_id);
        frame_id const &id = std::get<frame_id const &>(s_id);
        if (s.bad()) {
            return s;
        }
        // Knowing the frame id, parse now the frame body
        if (id.type == frame_type::ack) {
            f = frame<frame_type::ack>{};
        } else if (id.type == frame_type::nack) {
            f = frame<frame_type::nack>{};
        } else {
            // Check checksum of the remaining data
            if (s.remaining() < id.info_frame_data_size + 1 /* checksum */) {
                PN532_LOGE("Unable to parse info frame body, need at least %d bytes.", id.frame_total_length);
                s.set_bad();
                return s;
            }
            if (auto const &view = s.peek(); not bits::checksum(std::begin(view), std::begin(view) + id.info_frame_data_size + 1)) {
                PN532_LOGE("Frame body checksum failed.");
                s.set_bad();
                return s;
            }
            // This could be a special error frame
            if (id.info_frame_data_size == 1 and s.peek_one() == bits::specific_app_level_err_code) {
                PN532_LOGW("Received failure from controller.");
                f = frame<frame_type::error>{};
            } else {
                // All info known frames must have the transport and the command
                if (id.info_frame_data_size < 2) {
                    PN532_LOGE("Cannot parse frame body if frame length %u is less than 2.", id.info_frame_data_size);
                    s.set_bad();
                    return s;
                }
                // Finally, parse the body
                frame<frame_type::info> info_frame{};
                s >> info_frame.transport;
                if (info_frame.transport == bits::transport::pn532_to_host) {
                    info_frame.command = bits::pn532_to_host_command(s.pop());
                } else {
                    s >> info_frame.command;
                }
                info_frame.data << prealloc(id.info_frame_data_size - 2) << s.read(id.info_frame_data_size - 2);
                f = std::move(info_frame);
            }
            // Remove checksum
            s.pop();
        }
        if (id.has_preamble) {
            // Remove postamble
            if (not s.good()) {
                PN532_LOGW("Could not read postamble.");
            } else if (const auto postamble = s.pop(); postamble != bits::postamble) {
                PN532_LOGW("Invalid postamble: %02x.", postamble);
            }
        }
        return s;
    }

    bin_stream &operator>>(bin_stream &s, any_frame &f) {
        frame_id id{};
        s >> id;
        return std::tie(s, id) >> f;
    }


    channel::comm_operation::comm_operation(channel &owner, comm_mode event, ms timeout) : _owner{owner}, _event{event}, _result{result_success} {
        if (_owner._has_operation) {
            PN532_LOGE("Nested comm_operation instantiated: a channel can only run one at a time.");
        }
        _owner._has_operation = true;
        bool prepare_success = true;
        switch (_event) {
            case comm_mode::send:
                prepare_success = _owner.on_send_prepare(timeout);
                break;
            case comm_mode::receive:
                prepare_success = _owner.on_receive_prepare(timeout);
                break;
        }
        if (not prepare_success) {
            _result = error::comm_timeout;
        }
    }

    channel::comm_operation::~comm_operation() {
        switch (_event) {
            case comm_mode::send:
                _owner.on_send_complete(_result);
                break;
            case comm_mode::receive:
                _owner.on_receive_complete(_result);
                break;
        }
        _owner._has_operation = false;
    }

    channel::r<any_frame> channel::receive(ms timeout) {
        switch (raw_receive_mode()) {
            case receive_mode::stream:
                return receive_stream(timeout);
            case receive_mode::buffered:
                return receive_restart(timeout);
        }
        return error::comm_error;
    }


    channel::r<> channel::send(any_frame const &frame, ms timeout) {
        reduce_timeout rt{timeout};
        bin_data &buffer = get_clean_buffer();
        buffer << frame;
        if (comm_operation op{*this, comm_mode::send, rt.remaining()}; op.ok()) {
            return op.update(raw_send(buffer.view(), rt.remaining()));
        } else {
            return op.error();
        }
    }

    channel::r<> channel::receive_ack(bool ack_value, ms timeout) {
        if (auto const res_recv = receive(timeout); res_recv) {
            if (res_recv->type() == (ack_value ? frame_type::ack : frame_type::nack)) {
                return result_success;
            } else {
                PN532_LOGE("Expected %s, got %s.", (ack_value ? "ack" : "nack"), to_string(res_recv->type()));
                return error::comm_error;
            }
        } else {
            return res_recv.error();
        }
    }

    channel::r<> channel::send_ack(bool ack_value, ms timeout) {
        if (ack_value) {
            return send(frame<frame_type::ack>{}, timeout);
        } else {
            return send(frame<frame_type::nack>{}, timeout);
        }
    }

    channel::r<any_frame> channel::receive_restart(ms timeout) {
        reduce_timeout rt{timeout};
        bin_data &buffer = get_clean_buffer();
        bin_stream s{buffer};
        // Repeatedly fetch the data until you have determined the frame length
        frame_id id{};

        while (buffer.size() < id.frame_total_length) {
            // Prepare the buffer and receive the whole frame
            if (buffer.empty()) {
                // Read more than the minimum frame length, we will exploit this to reuce the number of nacks
                buffer.resize(frame_id::max_min_info_frame_header_length);
            } else {
                buffer.resize(id.frame_total_length);
            }
            if (comm_operation op{*this, comm_mode::receive, rt.remaining()}; op.ok()) {
                if (auto const res_recv = raw_receive(buffer.view(), rt.remaining()); res_recv) {
                    // Attempt to reparse the frame
                    s.seek(0);
                    s >> id;
                    if (s.bad()) {
                        PN532_LOGE("Could not identify frame from received data.");
                        return op.update(error::comm_malformed);
                    }
                    // Do we finally have enough?
                    if (buffer.size() >= id.frame_total_length) {
                        // Truncate any leftover data we may have read extra
                        buffer.resize(id.frame_total_length);
                        // Now we have enough data to read the command entirely.
                        any_frame f{};
                        std::tie(s, id) >> f;
                        if (s.bad()) {
                            PN532_LOGE("Could not parse frame from data.");
                            ESP_LOG_BUFFER_HEX_LEVEL(PN532_TAG, buffer.data(), buffer.size(), ESP_LOG_DEBUG);
                            return op.update(error::comm_malformed);
                        } else if (not s.eof()) {
                            PN532_LOGW("Stray data in frame (%d bytes)", s.remaining());
                            auto const view = s.peek();
                            ESP_LOG_BUFFER_HEX_LEVEL(PN532_TAG, view.data(), view.size(), ESP_LOG_WARN);
                        }
                        return op.update<any_frame>(std::move(f));
                    }
                } else {
                    return op.update(res_recv.error());
                }
            } else {
                return op.error();
            }
            // Send NACK
            if (const auto res_nack = send_ack(false, rt.remaining()); not res_nack) {
                return res_nack.error();
            }
        }
        PN532_LOGE("Control reached impossible location.");
        return error::comm_error;
    }

    channel::r<any_frame> channel::receive_stream(ms timeout) {
        reduce_timeout rt{timeout};
        if (comm_operation op{*this, comm_mode::receive, rt.remaining()}; op.ok()) {
            bin_data &buffer = get_clean_buffer();
            bin_stream s{buffer};
            // Repeatedly fetch the data until you have determined the frame length
            frame_id id{};
            while (rt and buffer.size() < id.frame_total_length) {
                // Repeatedly request more bytes
                const std::size_t old_size = buffer.size();
                buffer.resize(id.frame_total_length);
                if (auto res_recv = raw_receive(buffer.view(old_size), rt.remaining()); not res_recv) {
                    return op.update(res_recv.error());
                }
                // Attempt to reparse the frame
                s.seek(0);
                s >> id;
                if (s.bad()) {
                    PN532_LOGE("Could not identify frame from received data.");
                    return op.update(error::comm_malformed);
                }
            }
            // Now we have enough data to read the command entirely.
            any_frame f{};
            std::tie(s, id) >> f;
            if (s.bad()) {
                PN532_LOGE("Could not parse frame from data.");
                ESP_LOG_BUFFER_HEX_LEVEL(PN532_TAG, buffer.data(), buffer.size(), ESP_LOG_DEBUG);
                return op.update(error::comm_malformed);
            } else if (not s.eof()) {
                PN532_LOGW("Stray data in frame (%d bytes)", s.remaining());
                auto const view = s.peek();
                ESP_LOG_BUFFER_HEX_LEVEL(PN532_TAG, view.data(), view.size(), ESP_LOG_WARN);
            }
            return op.update<any_frame>(std::move(f));
        } else {
            return op.error();
        }
    }


    channel::r<> channel::command(bits::command cmd, bin_data data, ms timeout) {
        reduce_timeout rt{timeout};
        frame<frame_type::info> f{bits::transport::host_to_pn532, cmd, std::move(data)};
        if (auto const res_send = send(std::move(f), rt.remaining()); not res_send) {
            return res_send.error();
        } else {
            return receive_ack(true, rt.remaining());
        }
    }

    channel::r<bin_data> channel::response(bits::command cmd, ms timeout) {
        reduce_timeout rt{timeout};
        r<bin_data> retval = error::comm_timeout;
        if (auto res_recv = receive(rt.remaining()); res_recv) {
            if (res_recv->type() == frame_type::error) {
                PN532_LOGW("Command %s failed.", to_string(cmd));
                retval = error::failure;
            } else if (res_recv->type() != frame_type::info) {
                PN532_LOGE("Received ack/nack instead of info/error frame to %s?", to_string(cmd));
                retval = error::comm_malformed;
            } else {
                frame<frame_type::info> f = std::move(res_recv->get<frame_type::info>());
                // Check that f matches
                if (f.command != cmd) {
                    PN532_LOGE("Mismatch command, sent %s, received %s.", to_string(cmd), to_string(f.command));
                    retval = error::comm_malformed;
                } else {
                    if (f.transport != bits::transport::pn532_to_host) {
                        PN532_LOGW("Incorrect transport in response, ignoring...");
                    }
                    // Finally we got the right conditions
                    retval = std::move(f.data);
                }
            }
        } else {
            if (res_recv.error() == error::comm_timeout) {
                PN532_LOGW("Command %s timed out.", to_string(cmd));
            } else {
                PN532_LOGE("Command %s: %s", to_string(cmd), to_string(res_recv.error()));
            }
            retval = res_recv.error();
        }
        // Make sure to send a final ACK to clear the PN532
        send_ack(true, 1s /* allow large timeout here */);
        return retval;
    }

    channel::r<bin_data> channel::command_response(bits::command cmd, bin_data data, ms timeout) {
        reduce_timeout rt{timeout};
        if (auto const res_cmd = command(cmd, std::move(data), rt.remaining()); not res_cmd) {
            return res_cmd.error();
        }
        return response(cmd, rt.remaining());
    }

}// namespace pn532