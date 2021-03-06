//
// Created by spak on 3/3/21.
//

#include "pn532/channel_repl.hpp"
#include <pn532/bits_algo.hpp>
#include <pn532/channel.hpp>

namespace pn532::repl {
    using mlab::bin_stream;
    using mlab::prealloc;
    using mlab::result_success;

    using namespace std::chrono_literals;

    namespace {
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
        id.complete = false;
        id.info_frame_data_size = 0;
        id.frame_total_length = advance_past_start_of_packet_code(s);

        if (not s.good()) {
            return s;
        }
        if (s.remaining() < 2) {
            PN532_LOGE("Unable to parse frame header, not enough data.");
            s.set_bad();
            return s;
        }

        std::array<std::uint8_t, 2> code_or_length{0x00, 0x00};
        id.frame_total_length += code_or_length.size();
        s >> code_or_length;

        // Check for special packet codes
        if (code_or_length == bits::ack_packet_code) {
            id.type = frame_type::ack;
            id.complete = true;
            return s;
        }
        if (code_or_length == bits::nack_packet_code) {
            id.type = frame_type::ack;
            id.complete = true;
            return s;
        }

        // Info or error frame.
        id.type = frame_type::info;
        bool checksum_pass = true;
        std::size_t info_frame_data_size = 0;

        if (code_or_length == bits::fixed_extended_packet_length) {
            id.frame_total_length += 3;
            if (s.remaining() < 3) {
                PN532_LOGE("Unable to parse ext info frame length, not enough data.");
                s.set_bad();
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
        id.complete = s.remaining() >= info_frame_data_size + 1;
        return s;
    }

    bin_stream &operator>>(std::tuple<bin_stream &, frame_id const &> s_id, any_frame &f) {
        // Unpack stream and frame id from tuple
        bin_stream &s = std::get<bin_stream &>(s_id);
        frame_id const &id = std::get<frame_id const &>(s_id);
        // Knowing the frame id, parse now the frame body
        if (not s.good()) {
            return s;
        } else if (not id.complete) {
            PN532_LOGE("Unable to parse frame, need at least %d bytes.", id.frame_total_length);
            s.set_bad();
            return s;
        }
        if (id.type == frame_type::ack) {
            f = frame<frame_type::ack>{};
            return s;
        } else if (id.type == frame_type::nack) {
            f = frame<frame_type::nack>{};
            return s;
        }
        // Check checksum of the remaining data
        if (auto const &view = s.peek(); not bits::checksum(std::begin(view), std::begin(view) + id.info_frame_data_size + 1)) {
            PN532_LOGE("Frame body checksum failed.");
            s.set_bad();
            return s;
        }
        // This could be a special error frame
        if (id.info_frame_data_size == 1 and s.peek_one() == bits::specific_app_level_err_code) {
            PN532_LOGW("Received error from controller.");
            f = frame<frame_type::error>{};
            return s;
        }
        // All info known frames must have the transport and the command
        if (id.info_frame_data_size < 2) {
            PN532_LOGE("Cannot parse frame body if frame length %u is less than 2.", id.info_frame_data_size);
            s.set_bad();
            return s;
        }
        // Finally, parse the body
        frame<frame_type::info> info_frame{};
        s >> info_frame.transport >> info_frame.command;
        info_frame.data << prealloc(id.info_frame_data_size - 2) << s.read(id.info_frame_data_size - 2);
        // Remove checksum
        s.pop();
        f = std::move(info_frame);
        return s;
    }

    bin_stream &operator>>(bin_stream &s, any_frame &f) {
        frame_id id{};
        s >> id;
        return std::tie(s, id) >> f;
    }


    class channel::comm_operation {
        channel &_owner;
        comm_mode _event;
        r<> _result;

    public:
        [[nodiscard]] inline bool ok() const {
            return bool(_result);
        }

        [[nodiscard]] inline decltype(auto) error() const {
            return _result.error();
        }

        [[nodiscard]] inline enum error update(enum error e) {
            _result = e;
            return e;
        }

        [[nodiscard]] inline r<> update(bool operation_result) {
            if (operation_result) {
                _result = result_success;
            } else {
                _result = error::comm_timeout;
            }
            return _result;
        }

        template <class... Tn, class... Args>
        [[nodiscard]] inline r<Tn...> update(Args &&... args) {
            r<Tn...> retval{std::forward<Args>(args)...};
            if (retval) {
                _result = result_success;
            } else {
                _result = retval.error();
            }
            return std::move(retval);
        }

        comm_operation(channel &owner, comm_mode event, ms timeout) : _owner{owner}, _event{event}, _result{result_success} {
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

        ~comm_operation() {
            switch (_event) {
                case comm_mode::send:
                    _owner.on_send_complete(_result);
                    break;
                case comm_mode::receive:
                    _owner.on_receive_complete(_result);
                    break;
            }
        }
    };

    channel::r<any_frame> channel::receive(ms timeout) {
        if (supports_multiple_raw_receive()) {
            return receive_stream(timeout);
        } else {
            return receive_restart(timeout);
        }
    }


    channel::r<> channel::send(any_frame const &frame, ms timeout) {
        reduce_timeout rt{timeout};
        static bin_data buffer;
        buffer.clear();
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
        static bin_data buffer;
        std::size_t offset = 0;
        frame_id id{};

        // First comm operation: receive X bytes and try to identify frame
        if (comm_operation op{*this, comm_mode::receive, rt.remaining()}; op.ok()) {
            buffer.clear();
            if (auto res_id_ofs = raw_receive_identify(buffer, rt.remaining()); res_id_ofs) {
                std::tie(id, offset) = *res_id_ofs;
            } else {
                return op.update(res_id_ofs.error());
            }
        } else {
            return op.error();
        }

        // Is the body complete?
        if (not id.complete) {
            // Request the answer again by sending a NACK
            if (auto const res_nack = send_ack(false, rt.remaining()); not res_nack) {
                return res_nack.error();
            }
            // Now read the whole thing again.
            if (comm_operation op{*this, comm_mode::receive, rt.remaining()}; op.ok()) {
                // This time allocate all the buffer requested
                buffer.resize(id.frame_total_length);
                if (auto res_recv = raw_receive(buffer.view(), rt.remaining()); not res_recv) {
                    return op.update(res_recv.error());
                }
            } else {
                return op.error();
            }
        }

        // Now we have enough data in the buffer
        bin_stream s{buffer};
#ifndef NDEBUG
        {
            // In debug mode, assert that we get the same info
            frame_id test_id{};
            s >> test_id;
            assert(test_id == id);
        }
#endif
        s.seek(offset);
        // Extract the frame
        any_frame f{};
        std::tie(s, id) >> f;
        if (s.good()) {
            return std::move(f);
        } else {
            return error::comm_malformed;
        }
    }

    channel::r<any_frame> channel::receive_stream(ms timeout) {
        reduce_timeout rt{timeout};
        if (comm_operation op{*this, comm_mode::receive, rt.remaining()}; op.ok()) {
            static bin_data buffer;
            buffer.clear();
            if (auto res_id_ofs = raw_receive_identify(buffer, rt.remaining()); res_id_ofs) {
                auto const &[id, offset] = *res_id_ofs;
                if (not id.complete) {
                    // Retrieve the remaining data
                    const std::size_t new_data_offset = buffer.size();
                    buffer.resize(id.frame_total_length);
                    if (auto res_body = raw_receive(buffer.view(new_data_offset), rt.remaining()); not res_body) {
                        PN532_LOGE("Could not parse frame body.");
                        return op.update(res_body.error());
                    }
                }
                // Now we have enough data to read the command entirely.
                any_frame f{};
                bin_stream s{buffer};
                s.seek(offset);
                std::tie(s, id) >> f;
                if (s.good()) {
                    return op.update<any_frame>(std::move(f));
                } else {
                    return op.update(error::comm_malformed);
                }
            } else {
                return op.update(res_id_ofs.error());
            }
        } else {
            return op.error();
        }
    }


    channel::r<frame_id, std::size_t> channel::raw_receive_identify(bin_data &buffer, ms timeout) {
        static constexpr std::size_t min_length = 8;
        buffer.clear();
        buffer.resize(min_length);
        // Receive first the data necessary to identify frame length
        if (auto res_header = raw_receive(buffer.view(), timeout); not res_header) {
            return res_header.error();
        }
        // Attempt at identifying the frame
        bin_stream s{buffer};
        frame_id id{};
        s >> id;
        if (not s.good()) {
            PN532_LOGE("Could not identify frame from received data.");
            return error::comm_malformed;
        }
        return {id, s.tell()};
    }

    const char *to_string(frame_type type) {
        switch (type) {
            case frame_type::ack:
                return "ack";
            case frame_type::nack:
                return "nack";
            case frame_type::error:
                return "error";
            case frame_type::info:
                return "info";
            default:
                return "UNKNOWN";
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
        while (rt) {
            if (auto res_recv = receive(rt.remaining()); res_recv) {
                if (res_recv->type() == frame_type::error) {
                    PN532_LOGW("Received application error from the controller.");
                    retval = error::failure;
                    break;
                }
                if (res_recv->type() != frame_type::info) {
                    PN532_LOGE("Received ack/nack instead of info/error frame?");
                    retval = error::comm_malformed;
                    break;
                }
                frame<frame_type::info> f = std::move(res_recv->get<frame_type::info>());
                // Check that f matches
                if (f.command != cmd) {
                    PN532_LOGE("Mismatch command, sent %s, received %s.", to_string(cmd), to_string(f.command));
                    retval = error::comm_malformed;
                    break;
                }
                if (f.transport != bits::transport::pn532_to_host) {
                    PN532_LOGW("Incorrect transport in response, ignoring...");
                }
                // Finally we got the right conditions
                retval = std::move(f.data);
                break;
            }
            PN532_LOGW("Receive incorrect response, retrying...");
            if (not send_ack(false, rt.remaining())) {
                PN532_LOGE("Could not send nack, giving up on this one.");
                retval = error::comm_error;
                break;
            }
        }
        if (not retval and not rt) {
            PN532_LOGE("Timeout before receiving valid response.");
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

}// namespace pn532::repl