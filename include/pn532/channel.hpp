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
    namespace {
        using mlab::bin_data;
        using mlab::bin_stream;
        using mlab::reduce_timeout;
    }// namespace

    using ms = std::chrono::milliseconds;

    /**
     * @brief Types of frames transmitted from/to the PN532
     */
    enum struct frame_type {
        ack, ///< Previous communication was acknowledged.
        nack,///< Previous communication has to be repeated, or trasmission completed.
        info,///< Frame containing data.
        error///< Application-level error
    };


    /**
     * @brief Data structure holding data for the PN532 frame.
     * For @ref frame_type::ack, @ref frame_type::nack, @ref frame_type::error, the type carries all the information.
     * The only relevant template specialization is @ref frame<frame_type::info>
     */
    template <frame_type>
    struct frame {};

    /**
     * @brief A (possibly extended) info frame.
     */
    template <>
    struct frame<frame_type::info> {
        bits::transport transport = bits::transport::host_to_pn532;
        bits::command command = bits::command::diagnose;
        bin_data data;
    };

    /**
     * @brief Any frame trasmitted by the PN532, i.e. one of @ref frame
     * @note In order to know what which frame has to be extracted, parse first a @ref frame_id, and then
     * tie the stream and the @ref frame_id together.
     * @code
     *  bin_stream s{d};
     *  frame_id id{};
     *  s >> id;
     *  any_frame f{};
     *  std::tie(s, id) >> f;
     * @endcode
     */
    class any_frame : public mlab::any_of<frame_type, frame, frame_type::error> {
    public:
        using mlab::any_of<frame_type, frame, frame_type::error>::any_of;
    };

    /**
     * @brief Helper data structure used to progressively identify frame size.
     * Frame length is dynamically determined by the presence of preamble/postamble and by the frame type.
     * Only some channels support reading one byte at a time in order to determine the full frame length. Others
     * require to request the frame over and over again by sending a NACK. This data structure helps in tracking
     * what is known about a frame while it is being received.
     * @see channel::receive_mode
     */
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

        /**
         * The frame type (if known).
         */
        frame_type type = frame_type::error;

        /**
         * True if and only if a preamble has been detected (and thus a postamble is expected)
         */
        bool has_preamble = false;

        /**
         * Determined total frame length (so far).
         */
        std::size_t frame_total_length = min_frame_length;

        /**
         * @brief Determined data length for an info frame.
         * This includes @ref frame<frame_type::info>::transport and @ref frame<frame_type::info>::command, not
         * just @ref frame<frame_type::info>::data.
         */
        std::size_t info_frame_data_size = 0;
    };

    bin_data &operator<<(bin_data &bd, frame<frame_type::ack> const &);
    bin_data &operator<<(bin_data &bd, frame<frame_type::nack> const &);
    bin_data &operator<<(bin_data &bd, frame<frame_type::error> const &);
    bin_data &operator<<(bin_data &bd, frame<frame_type::info> const &f);
    bin_data &operator<<(bin_data &bd, any_frame const &f);

    bin_stream &operator>>(bin_stream &s, any_frame &f);

    /**
     * Special extraction operator that operates on a @ref bin_stream, once a @ref frame_id has been parsed.
     * @param s_id Stream and @ref frame_id. Note that this has to be the same stream from which the @ref frame_id
     *  was extracted, in particular it must point at the first position that is _not_ part of @ref frame_id.
     * @param f Target @ref any_frame structure.
     * @return The stream of @p s_id after the extraction of @p f.
     * @code
     *  bin_stream s{d};
     *  frame_id id{};
     *  s >> id;
     *  any_frame f{};
     *  std::tie(s, id) >> f;
     * @endcode
     */
    bin_stream &operator>>(std::tuple<bin_stream &, frame_id const &> s_id, any_frame &f);

    /**
     * Extractor for @ref frame_id.
     * This supports also extracting partial information, and will just leave the members it cannot
     * prefill as they are.
     * @param s Stream from which the @ref frame_id is extracted. Needs at least 5 bytes (ack, nack,
     *  standard info frame), better 8 (to determine length in extended info frames without having
     *  to request further extractions).
     * @param id @ref frame_id to fill.
     * @return The stream @p s after the extraction of @p id.
     */
    bin_stream &operator>>(bin_stream &s, frame_id &id);


    /**
     * @brief Abstract class for the PN532 communication channel.
     * Each channel class must support send and receive over a hardware channel. Only one operation
     * among @ref comm_mode::send and @ref comm_mode::receive can be performed at a given time. Before
     * another communication operation is performed, the previous one is guaranteed to be completed;
     * note that the PN532 always uses half-duplex communication mode.
     *
     * Subclasses must implement the following methods (see corresponding documentation):
     *  - @ref raw_send
     *  - @ref raw_receive
     *  - @ref wake
     *  - @ref receive_mode
     * and may implement one or more of these event handlers:
     *  - @ref on_receive_prepare
     *  - @ref on_receive_complete
     *  - @ref on_send_prepare
     *  - @ref on_send_complete
     *
     * Use @ref comm_operation to manage firing events correctly.
     *
     * @note Subclasses should never directly call any of @ref on_receive_prepare, @ref on_receive_complete,
     *  @ref on_send_prepare, @ref on_send_complete. These are managed by @ref comm_operation. Moreover, subclasses
     *  should never call @ref raw_send or @ref raw_receive without a @ref comm_operation in place.
     */
    class channel {
    public:
        virtual ~channel() = default;

        /**
         * @brief Channel-level errors.
         */
        enum struct error {
            comm_timeout,  ///< The given timeout was exceeded before the transmission was complete
            comm_error,    ///< Hardware error during trasmission.
            comm_malformed,///< Malformed data cannot be parsed (or unexpected frame).
            failure        ///< The PN532 gave an application-level ERROR frame..
        };

        template <class... Tn>
        using result = mlab::result<error, Tn...>;

    protected:
        /**
         * One of the two possible half-duplex communication modes of the channel, send and receive.
         */
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


        virtual result<> raw_send(mlab::range<bin_data::const_iterator> const &buffer, ms timeout) = 0;

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
        virtual result<> raw_receive(mlab::range<bin_data::iterator> const &buffer, ms timeout) = 0;

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
        virtual void on_receive_complete(result<> const &outcome) {}
        virtual bool on_send_prepare(ms timeout) { return true; }
        virtual void on_send_complete(result<> const &outcome) {}
        /**
         * @}
         */

        result<> send(any_frame const &frame, ms timeout);

        result<any_frame> receive(ms timeout);

    public:
        virtual bool wake() = 0;

        /**
         * @brief send_ack ACK or NACK frame
         * @internal
         * @param ack_value true for sending ACK, otherwise sends NACK
         * @param timeout maximum time for getting a response
         * @return No data, but can return the following errors: @ref error::comm_timeout.
         */
        result<> send_ack(bool ack_value, ms timeout);

        /**
         * @brief Wait for an ACK or NACK
         * @internal
         * @param timeout maximum time for getting a response
         * @returns true if ACK otherwhise false if NACK or the following errors: @ref error::comm_error,
         *  @ref error::comm_malformed, @ref error::comm_timeout
         */
        result<> receive_ack(bool ack_value, ms timeout);

        /**
         * @brief Command without response
         * @internal
         * @param cmd Command code
         * @param data Max 263 bytes, will be truncated
         * @param timeout maximum time for getting a response
         * @return No data, but can return the following errors: @ref error::comm_timeout, @ref error::nack,
         *   @ref error::comm_malformed
         */
        result<> command(bits::command cmd, bin_data data, ms timeout);

        /**
         * @brief Wait for a response frame of a command
         * @internal
         * @param cmd Command code
         * @param timeout maximum time for getting a response
         * @return Either the received data, or one of the following errors: @ref error::comm_malformed,
         *  @ref error::comm_checksum_fail, or @ref error::comm_timeout. No other error codes are produced.
         */
        result<bin_data> response(bits::command cmd, ms timeout);

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
        result<bin_data> command_response(bits::command cmd, bin_data data, ms timeout);

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
        result<Data> command_parse_response(bits::command cmd, bin_data data, ms timeout);

    private:
        /**
         * Receives the frame one piece at a time.
         */
        result<any_frame> receive_stream(ms timeout);

        /**
         * Receives the frame but restarts every time it needs to read a new chunk.
         */
        result<any_frame> receive_restart(ms timeout);

        bool _has_operation = false;
    };

    [[nodiscard]] const char *to_string(frame_type type);

    [[nodiscard]] const char *to_string(channel::error e);

    /**
     * @brief Class managing the correct firing of the events in the PN532.
     * This class is a RAII wrapper that fires the correct events at construction and destruction. It holds the
     * transmission result @ref channel::result<> obtained so far (or the corresponding error), in such a way that it
     * can pass it to @ref on_receive_complete or @ref on_send_complete. Always call @ref raw_send and @ref raw_receive
     * with one such class in scope (otherwise the events will not be fired and the class may not be in the correct
     * state). Use the passthrough methods @ref comm_operation::update to record results or errors, as in the
     * following example. Use the @ref comm_operation::ok accessor to check whether the @ref on_receive_prepare
     * or @ref on_send_prepare events were successful before calling any lower level function. See the examples
     * further down.
     *
     * @note Subclasses should never directly call any of @ref on_receive_prepare, @ref on_receive_complete,
     *  @ref on_send_prepare, @ref on_send_complete. These are managed by this class. Moreover, subclasses
     *  should never call @ref raw_send or @ref raw_receive without a @ref comm_operation in place.
     *
     * @code
     *  using namespace std::chrono_literals;
     *
     *  // In a subclass of channel
     *  channel::result<any_frame> chn_subclass::custom_receive_frame() {
     *      // Create a comm_operation alive within the scope of the if.
     *      // This fires on_receive_prepare, and test with ::ok() whether it succeeded.
     *      if (comm_operation op{*this, comm_mode::receive, 10ms}; op.ok()) {
     *          // Able to receive, prepare buffer
     *          mlab::bin_data buffer{mlab::prealloc(100)};
     *          // Make sure to test whether the communication succeeded
     *          if (const auto result_comm = raw_receive(buffer.view(), 10ms); result_comm) {
     *              // Success, attempt parsing
     *              mlab::bin_stream s{buffer};
     *              frame_id fid{};
     *              s >> fid;
     *              if (s.bad()) {
     *                  // Could not parse the frame, update the comm_operation and return
     *                  return op.update(error::comm_malformed);
     *              }
     *              // Extract the frame
     *              any_frame f{};
     *              std::tie(s, fid) >> f;
     *              if (s.bad()) {
     *                  // Could not parse the frame, update the comm_operation and return
     *                  return op.update(error::comm_malformed);
     *              }
     *              // Nice! Parsed. Update the operation and return the frame
     *              return op.update(std::move(f));
     *          } else {
     *              // Failure, update the comm_opeation and return the error from raw_receive
     *              return op.update(result_comm.error());
     *          }
     *      } else {
     *          // Receive preparation failed, return the error collected into comm_operation
     *          return op.error();
     *      }
     *  }
     * @endcode
     *
     * @code
     *  using namespace std::chrono_literals;
     *
     *  // In some subclass of channel that requires sending data to wake
     *  bool chn_subclass::wake() {
     *      // Create a comm_operation alive within the scope of the if.
     *      // This fires on_send_prepare, and test with ::ok() whether it succeeded.
     *      if (comm_operation op{*this, comm_mode::send, 10ms}; op.ok()) {
     *          // Attempt sending data; use the result to update the comm operation
     *          //  and passthrough. An explicit cast to bool is required here.
     *          return bool(op.update(raw_send({0x55, 0x55, 0x55}, 10ms)));
     *      } else {
     *          return false;
     *      }
     *  }
     * @endcode
     */
    class channel::comm_operation {
        channel &_owner;
        comm_mode _event;
        result<> _result;

    public:
        /**
         * Calls @ref on_receive_prepare or @ref on_send_prepare and stores the outcome.
         * @param owner The target class for calling @ref on_receive_prepare or @ref on_send_prepare.
         * @param event Chooses between @ref on_receive_prepare, @ref on_receive_complete and  @ref on_send_prepare,
         *  @ref on_send_complete.
         * @param timeout Timeout to pass to @ref on_receive_prepare or @ref on_send_prepare.
         * @see ok
         */

        comm_operation(channel &owner, comm_mode event, ms timeout);

        /**
         * Calls @ref on_receive_complete or @ref on_send_complete with the internally stored result.
         */
        ~comm_operation();

        /**
         * @ref Tests whether the operation contains an error or not.
         * The main usage of this is to test whether the @ref on_receive_prepare and @ref on_send_prepare
         * events have succeeded.
         * @return True if an only if so far the operation succeeded.
         * @code
         *  // Fire the on_receive_prepare event.
         *  if (comm_operation op{*this, comm_operation::receive, 10ms}; op.ok()) {
         *      // Do stuff
         *  } else {
         *      // Preparation failed
         *  }
         * @endcode
         */
        [[nodiscard]] inline bool ok() const;

        /**
         * @brief Error currently stored in this operation.
         * @return The error code of the currently stored result.
         * @note This calls @ref mlab::result::error; if the result is @ref mlab::result_success, it is not
         *  valid to call this method, therefore test first with @ref ok that this @ref comm_operation actually
         *  is _not_ ok and contains an error.
         */
        [[nodiscard]] inline decltype(auto) error() const;

        /**
         * @addtogroup comm_operation::update
         * These methods collect a result, an error, or a boolean representing success and store it inside the
         * class. Moreover, they return whatever was passed to them (in the form of @ref channel::result<> or in form
         * of @ref channel::error), in such a way that the user can directly pass it through in a `return` statement.
         * The updated result is used in the call to @ref on_receive_complete and @ref on_send_complete.
         * @{
         */

        /**
         * Stores an error state from an explicit error code.
         * @param e Error code
         * @return The same error code @p e
         */
        [[nodiscard]] inline enum error update(enum error e);

        /**
         * Stores a success or timeout state from a boolean.
         * @param operation_result True if the operation succeded, false if it timed out.
         * @return @ref mlab::result_success or @ref error::comm_timeout, depending on @p operation_result.
         */
        [[nodiscard]] inline result<> update(bool operation_result);

        /**
         * Stores an existing result into the internal @ref channel::result<>
         * @tparam Tn Any result type for @ref mlab::result
         * @tparam Args Anything that can be assigned to @ref channel::result<>
         * @param args Anything that can be assigned to @ref channel::result<>
         * @return The same result as the one specified
         */
        template <class... Tn, class... Args>
        [[nodiscard]] inline result<Tn...> update(Args &&... args);
        /**
         * @}
         */
    };

}// namespace pn532

namespace pn532 {

    template <class Data, class>
    channel::result<Data> channel::command_parse_response(bits::command cmd, bin_data data, ms timeout) {
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

    channel::result<> channel::comm_operation::update(bool operation_result) {
        if (operation_result) {
            _result = mlab::result_success;
        } else {
            _result = error::comm_timeout;
        }
        return _result;
    }

    template <class... Tn, class... Args>
    channel::result<Tn...> channel::comm_operation::update(Args &&... args) {
        result<Tn...> retval{std::forward<Args>(args)...};
        if (retval) {
            _result = mlab::result_success;
        } else {
            _result = retval.error();
        }
        return std::move(retval);
    }
}// namespace pn532
#endif//PN532_CHANNEL_REPL_HPP
