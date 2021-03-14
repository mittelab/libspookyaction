//
// Created by spak on 3/3/21.
//

#ifndef PN532_CHANNEL_REPL_HPP
#define PN532_CHANNEL_REPL_HPP

#include "mlab/bin_data.hpp"
#include "mlab/result.hpp"
#include "mlab/time.hpp"
#include <chrono>
#include <pn532/bits.hpp>
#include <pn532/log.h>
#include <pn532/msg.hpp>

namespace pn532 {
    using mlab::bin_data;
    using mlab::bin_stream;
    using mlab::reduce_timeout;

    using ms = std::chrono::milliseconds;

    enum struct frame_type {
        ack,
        nack,
        info,
        error
    };


    template <frame_type>
    struct frame {};

    template <>
    struct frame<frame_type::info> {
        bits::transport transport = bits::transport::host_to_pn532;
        bits::command command = bits::command::diagnose;
        bin_data data;
    };

    class any_frame : public mlab::any_of<frame_type, frame, frame_type::error> {
    public:
        using mlab::any_of<frame_type, frame, frame_type::error>::any_of;
    };

    struct frame_id {
        /**
         * This is the absolute minimum frame length, that is just the start of packet code and the frame code.
         */
        static constexpr std::size_t min_frame_length =
                bits::start_of_packet_code.size() + std::max(std::max(bits::ack_packet_code.size(), bits::nack_packet_code.size()), bits::fixed_extended_packet_length.size());
        /**
         * Minimum frame length that in all cases allows to determine the frame length.
         */
        static constexpr std::size_t max_min_info_frame_header_length = min_frame_length + 1 /* preamble */ + 3 /* extended info frame length */;

        frame_type type = frame_type::error;
        bool has_preamble = false;
        std::size_t frame_total_length = min_frame_length;
        std::size_t info_frame_data_size = 0;
    };

    bin_data &operator<<(bin_data &bd, frame<frame_type::ack> const &);
    bin_data &operator<<(bin_data &bd, frame<frame_type::nack> const &);
    bin_data &operator<<(bin_data &bd, frame<frame_type::error> const &);
    bin_data &operator<<(bin_data &bd, frame<frame_type::info> const &f);
    bin_data &operator<<(bin_data &bd, any_frame const &f);

    bin_stream &operator>>(bin_stream &s, any_frame &f);

    /**
     * @code
     * bin_stream s{d};
     * frame_id id{};
     * s >> id;
     * any_frame f{};
     * std::tie(s, id) >> f;
     * @endcode
     */
    bin_stream &operator>>(std::tuple<bin_stream &, frame_id const &> s_id, any_frame &f);

    /**
     * Needs at least 5 bytes (ack, nack, standard info frame), better 8 (to determine length in extended info frames)
     * @param s
     * @param id
     * @return
     */
    bin_stream &operator>>(bin_stream &s, frame_id &id);


    class channel {
    public:
        enum struct error {
            comm_timeout,
            comm_error,
            comm_malformed,
            failure
        };

        template <class... Tn>
        using r = mlab::result<error, Tn...>;

    protected:
        enum struct comm_mode {
            send,
            receive
        };

        class comm_operation;

        /**
         * Mode in which @ref raw_receive is used to handle variable-length frames.
         *   - @ref receive_mode::stream Multiple @ref raw_receive calls of short length are performed
         *     within @ref on_receive_prepare and @ref on_receive_complete. These are used to progressively
         *     read the parts of the received frame. Each byte is read only once thus, and no reading beyond
         *     the frame boundary is performed. This is the typical scenario for e.g. High Speed UART on ESP32.
         *   - @ref receive_mode::buffered At most a single call to @ref raw_receive can be performed
         *     in-between @ref on_receive_prepare and @ref on_receive_complete. In order to determine the full
         *     length of a response info frame, an INFO frame is requested multiple times, by sending an
         *     application-level NACK. Since this technique only works for INFO frames (the PN532 would not
         *     resend an ACK/NACK/ERROR frame), every @ref raw_receive call will request at least as many bytes
         *     as necessary to parse an ACK/NACK/ERROR frame (i.e. @ref frame_id::max_min_info_frame_header_length).
         * @see raw_receive
         */
        enum struct receive_mode {
            stream,  ///< Data in the RX stream is progressively consumed by each @ref raw_receive
            buffered,///< Only one @ref raw_receive can be performed on a frame;
        };


        virtual r<> raw_send(mlab::range<bin_data::const_iterator> const &buffer, ms timeout) = 0;

        /**
         * @param buffer
         * @param timeout
         * @note in @ref receive_mode::buffered, the caller may request to fill a @p buffer that is larger than
         *  the frame payload data. Subclasses must be prepared for this and not crash. It is not relevant what
         *  the buffer contains past the frame boundary (i.e. it could be garbage data), however we suggest setting
         *  that to something deterministic; note that the buffer will come prefilled with zeroes.
         * @return
         * @see receive_mode
         */
        virtual r<> raw_receive(mlab::range<bin_data::iterator> const &buffer, ms timeout) = 0;

        /**
         * Determines whether multiple calls to @ref raw_receive can be performed as part of a single
         * receive operation (in-between @ref on_receive_prepare and @ref on_receive_complete) and whether
         * it is possible to read past the frame boundary.
         */
        [[nodiscard]] virtual receive_mode raw_receive_mode() const = 0;

        /**
         * @addtogroup Events
         * Guaranteed to always be called in pairs; each `prepare` is followed by one `complete`.
         * If @ref supports_streaming is true, multiple @ref raw_receive calls may be performed subsequently
         * in-between a @ref on_receive_prepare and a @ref on_receive_complete; otherwise, at most one call is
         * performed.
         * For sending data, there is always a single call to @ref raw_send in-between @ref on_send_prepare and its
         * counterpart @ref on_send_complete.
         * @{
         */
        virtual bool on_receive_prepare(ms timeout) { return true; }
        virtual void on_receive_complete(r<> const &outcome) {}
        virtual bool on_send_prepare(ms timeout) { return true; }
        virtual void on_send_complete(r<> const &outcome) {}
        /**
         * @}
         */

        r<> send(any_frame const &frame, ms timeout);

        r<any_frame> receive(ms timeout);

    public:
        virtual bool wake() = 0;

        /**
         * @brief send_ack ACK or NACK frame
         * @internal
         * @param ack_value true for sending ACK, otherwise sends NACK
         * @param timeout maximum time for getting a response
         * @return No data, but can return the following errors: @ref error::comm_timeout.
         */
        r<> send_ack(bool ack_value, ms timeout);

        /**
         * @brief Wait for an ACK or NACK
         * @internal
         * @param timeout maximum time for getting a response
         * @returns true if ACK otherwhise false if NACK or the following errors: @ref error::comm_error,
         *  @ref error::comm_malformed, @ref error::comm_timeout
         */
        r<> receive_ack(bool ack_value, ms timeout);

        /**
         * @brief Command without response
         * @internal
         * @param cmd Command code
         * @param data Max 263 bytes, will be truncated
         * @param timeout maximum time for getting a response
         * @return No data, but can return the following errors: @ref error::comm_timeout, @ref error::nack,
         *   @ref error::comm_malformed
         */
        r<> command(bits::command cmd, bin_data data, ms timeout);

        /**
         * @brief Wait for a response frame of a command
         * @internal
         * @param cmd Command code
         * @param timeout maximum time for getting a response
         * @return Either the received data, or one of the following errors: @ref error::comm_malformed,
         *  @ref error::comm_checksum_fail, or @ref error::comm_timeout. No other error codes are produced.
         */
        r<bin_data> response(bits::command cmd, ms timeout);

        /**
         * @brief Command with response
         * @internal
         * @param cmd Command code
         * @param payload Max 263 bytes, will be truncated
         * @param timeout maximum time for getting a response
         * @return Either the received data, or one of the following errors:
         *         - @ref error::comm_malformed
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<bin_data> command_response(bits::command cmd, bin_data data, ms timeout);

        /**
         * @brief Get data from a command response
         * @internal
         * @param cmd Command code
         * @param payload Max 263 bytes, will be truncated
         * @param timeout maximum time for getting a response
         * @return Either Data, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        template <class Data, class = typename std::enable_if<bin_stream::is_extractable<Data>::value>::type>
        r<Data> command_parse_response(bits::command cmd, bin_data data, ms timeout);

    private:
        /**
         * Receives the frame one piece at a time.
         */
        r<any_frame> receive_stream(ms timeout);

        /**
         * Receives the frame but restarts every time it needs to read a new chunk.
         */
        r<any_frame> receive_restart(ms timeout);

        bool _has_operation = false;
    };

    [[nodiscard]] const char *to_string(frame_type type);

    [[nodiscard]] const char *to_string(channel::error e);

    class channel::comm_operation {
        channel &_owner;
        comm_mode _event;
        r<> _result;

    public:
        comm_operation(channel &owner, comm_mode event, ms timeout);
        ~comm_operation();

        [[nodiscard]] inline bool ok() const;

        [[nodiscard]] inline decltype(auto) error() const;

        [[nodiscard]] inline enum error update(enum error e);

        [[nodiscard]] inline r<> update(bool operation_result);

        template <class... Tn, class... Args>
        [[nodiscard]] inline r<Tn...> update(Args &&... args);
    };

}// namespace pn532

namespace pn532 {

    template <class Data, class>
    channel::r<Data> channel::command_parse_response(bits::command cmd, bin_data data, ms timeout) {
        if (const auto res_cmd = command_response(cmd, std::move(data), timeout); res_cmd) {
            bin_stream s{*res_cmd};
            auto retval = Data();
            s >> retval;
            if (s.bad()) {
                PN532_LOGE("%s: could not parse result from response data.", to_string(cmd));
                return error::comm_malformed;
            }
            if (not s.eof()) {
                PN532_LOGW("%s: stray data in response (%d bytes).", to_string(cmd), s.remaining());
            }
            return retval;
        } else {
            return res_cmd.error();
        }
    }

    bool channel::comm_operation::ok() const {
        return bool(_result);
    }

    decltype(auto) channel::comm_operation::error() const {
        return _result.error();
    }

    channel::error channel::comm_operation::update(enum error e) {
        _result = e;
        return e;
    }

    channel::r<> channel::comm_operation::update(bool operation_result) {
        if (operation_result) {
            _result = mlab::result_success;
        } else {
            _result = error::comm_timeout;
        }
        return _result;
    }

    template <class... Tn, class... Args>
    channel::r<Tn...> channel::comm_operation::update(Args &&... args) {
        r<Tn...> retval{std::forward<Args>(args)...};
        if (retval) {
            _result = mlab::result_success;
        } else {
            _result = retval.error();
        }
        return std::move(retval);
    }
}// namespace pn532
#endif//PN532_CHANNEL_REPL_HPP
