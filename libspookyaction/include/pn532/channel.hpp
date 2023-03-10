//
// Created by spak on 3/3/21.
//

#ifndef PN532_CHANNEL_REPL_HPP
#define PN532_CHANNEL_REPL_HPP

#include <chrono>
#include <mlab/bin_data.hpp>
#include <mlab/result.hpp>
#include <mlab/time.hpp>
#include <pn532/bits.hpp>
#include <pn532/log.h>
#include <pn532/msg.hpp>

namespace pn532 {
    using mlab::bin_data;
    using mlab::bin_stream;
    using ms = std::chrono::milliseconds;

    /**
     * @brief Types of frames transmitted from/to the PN532 (UM0701-02 §6.2.1).
     * @note We do not distinguish between a normal and an extended information frame.
     */
    enum struct frame_type {
        ack, ///< Previous communication was acknowledged.
        nack,///< Previous communication has to be repeated, or trasmission completed.
        info,///< Frame containing data.
        error///< Application-level error
    };


    /**
     * @brief Data structure holding data for the PN532 frame.
     *
     * For @ref frame_type::ack, @ref frame_type::nack, @ref frame_type::error, the type carries all the information
     * (there is no extra data). The only relevant template specialization is @ref frame<frame_type::info>
     *
     * @see frame<frame_type::info>
     */
    template <frame_type>
    struct frame {};

    /**
     * @brief An info frame (UM0701-02 §6.2.1.1), possibly extended (UM0701-02 §6.2.1.2).
     */
    template <>
    struct frame<frame_type::info> {
        bits::transport transport = bits::transport::host_to_pn532;//!< Direction in which the frame travels.
        command_code command = command_code::diagnose;             //!< Command code associated to the frame.
        bin_data data;                                             //!< Packet data.
    };

    /**
     * @brief Any frame transmitted by the PN532, i.e. one of @ref frame
     * @note In order to know which frame has to be extracted, parse first a @ref frame_id, and then
     * tie the stream and the @ref frame_id together as follows:
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
     *
     * Frame length is dynamically determined by the presence of preamble/postamble and by the frame type.
     * However, only some channels support reading one byte at a time in order to determine the full frame length; for those channels
     * which do not support stream reading, we request instead the frame over and over again by sending @ref frame_type::nack.
     * This data structure helps in tracking what is known about a frame while it is being received.
     * @see comm_rx_mode
     */
    struct frame_id {
        /**
         * Absolute minimum frame length, that is, just the start of packet code and the frame code.
         */
        static constexpr std::size_t min_frame_length =
                bits::start_of_packet_code.size() + std::max(std::max(bits::ack_packet_code.size(), bits::nack_packet_code.size()), bits::fixed_extended_packet_length.size());
        /**
         * Minimum transmission length that is guaranteed to contain the frame length.
         */
        static constexpr std::size_t max_min_info_frame_header_length = min_frame_length + 1 /* preamble */ + 3 /* extended info frame length */;

        /**
         * The frame type, if known. If unknown, the frame type is @ref frame_type::error;
         */
        frame_type type = frame_type::error;

        /**
         * True if and only if a preamble has been detected (and thus a postamble is expected at the end).
         */
        bool has_preamble = false;

        /**
         * Determined total frame length (so far).
         */
        std::size_t frame_total_length = min_frame_length;

        /**
         * @brief Determined data length for an info frame.
         *
         * This includes also transport info and command, not only the internal data of @ref frame<frame_type::info>.
         */
        std::size_t info_frame_data_size = 0;
    };

    /**
     * @addtogroup IOOperators
     * @{
     */
    bin_data &operator<<(bin_data &bd, frame<frame_type::ack> const &);
    bin_data &operator<<(bin_data &bd, frame<frame_type::nack> const &);
    bin_data &operator<<(bin_data &bd, frame<frame_type::error> const &);
    bin_data &operator<<(bin_data &bd, frame<frame_type::info> const &f);
    bin_data &operator<<(bin_data &bd, any_frame const &f);
    bin_stream &operator>>(bin_stream &s, any_frame &f);

    /**
     * @brief Special extraction operator that operates on a `bin_stream`, once a @ref frame_id has been parsed.
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
     * @brief Extractor for @ref frame_id.
     * This supports also extracting partial information, and will just leave as they are the members
     * it cannot fill. You can then compare the total length of @p s to @ref frame_id::frame_total_length
     * and request further bytes until when they suffice to cover the whole frame.
     * @param s Stream from which the @ref frame_id is extracted. Needs at least 5 bytes (ack, nack,
     *  standard info frame), better 8 (to determine length in extended info frames without having
     *  to request further extractions).
     * @param id @ref frame_id to fill.
     * @return The stream @p s after the extraction of @p id.
     * @see
     *  - frame_id::max_min_info_frame_header_length
     *  - frame_id::min_frame_length
     */
    bin_stream &operator>>(bin_stream &s, frame_id &id);

    /**
     * @}
     */

    /**
     * @brief Channel-level errors.
     * @note The enum entry @ref channel_error::app_error is special in the sense that the PN532
     *  has actual insight into the content of the packet tramission, i.e. it knows what command is being sent.
     *  This is the case for example when the target that the PN532 connects to is @ref target_type::mifare_classic_ultralight.
     *  In that case an error from the card will raise an application error.
     */
    enum struct channel_error {
        timeout,  ///< The given timeout was exceeded before the transmission was complete.
        hw_error, ///< Hardware error during transmission.
        malformed,///< Malformed data cannot be parsed, or the type of frame received was unexpected.
        app_error ///< The PN532 gave an application-level ERROR frame.
    };

    /**
     * A variant type which either holds arbitrary data, or an error code in the form of a @ref channel_error.
     * @note The errors produced by the PN532 commands are of @ref channel_error type, not of @ref internal_error_code type; in fact,
     *  the @ref internal_error_code can only be retrieved from @ref general_status or @ref rf_status.
     * @see internal_error_code
     */
    template <class... Tn>
    using result = mlab::result<channel_error, Tn...>;


    /**
     * One of the two possible half-duplex communication modes of the channel, send and receive.
     */
    enum struct comm_dir {
        send,  ///< Data goes from the host to the PN532.
        receive///< Data goes from the PN532 to the host.
    };

    /**
     * Mode in which @ref channel::raw_receive should operate to handle variable-length frames.
     * @see channel::raw_receive
     */
    enum struct comm_rx_mode {
        /**
         * @brief Data in the RX stream is progressively consumed by each @ref channel::raw_receive call.
         *
         * Multiple @ref channel::raw_receive calls of short length are performed within @ref channel::on_receive_prepare
         * and @ref channel::on_receive_complete. These are used to progressively read the parts of the received frame.
         * Each byte is thus read only once, and no reading beyond the frame boundary is performed.
         * This is the typical scenario for e.g. High Speed UART on ESP32.
         */
        stream,
        /**
         * @brief Only one @ref channel::raw_receive call can be performed on a frame.
         * At most a single call to @ref channel::raw_receive can be performed in-between @ref channel::on_receive_prepare
         * and @ref channel::on_receive_complete. In order to determine the full length of a response info frame,
         * it must be requested multiple times. This is obtained by sending an application-level NACK.
         * Since this technique only works for INFO frames (the PN532 would not resend an ACK/NACK/ERROR frame),
         * every @ref channel::raw_receive call will request at least as many bytes as necessary to parse an
         * ACK/NACK/ERROR frame (i.e. @ref frame_id::max_min_info_frame_header_length).
         */
        buffered
    };

    /**
     * @brief Abstract class for the PN532 communication channel.
     *
     * Each channel class must support send and receive over a hardware channel. Only one operation
     * among @ref comm_dir::send and @ref comm_dir::receive can be performed at a given time. Before
     * another communication operation is performed, the previous one is guaranteed to be completed.
     * The PN532 always uses half-duplex communication mode.
     *
     * Subclasses must implement the following methods:
     *  - @ref raw_send
     *  - @ref raw_receive
     *  - @ref wake
     *  - @ref comm_rx_mode
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

    protected:
        friend class comm_operation;

        /**
         * Pure virtual: sends the data in @p buffer over the channel, synchronously.
         * @param buffer Data to be sent.
         * @param timeout Maximum timeout for the underlying implementation to complete sending the data.
         * @warning Always call this with a suitable @ref comm_operation in scope to guarantee the correct event firing.
         * @return Either `mlab::result_success`, or one of
         *  - @ref channel_error::timeout
         *  - @ref channel_error::hw_error
         */
        virtual result<> raw_send(mlab::range<bin_data::const_iterator> buffer, ms timeout) = 0;

        /**
         * Pure virtual: fills @p buffer with data from the underlying channel, synchronously.
         * @param buffer Buffer to fill (it is expected to be already appropriately sized).
         * @param timeout Maximum timeout for the underlying implementation to complete sending the data.
         * @warning Always call this with a suitable @ref comm_operation in scope to guarantee the correct event firing.
         * @note in @ref comm_rx_mode::buffered, the caller may request to fill a @p buffer that is larger than
         *  the actual frame data. Subclasses must be prepared for this and not crash. It is not relevant what
         *  the buffer contains past the frame boundary (i.e. it could be garbage data), however we suggest setting
         *  that to something deterministic. The buffer will come prefilled with zeroes.
         * @return Either `mlab::result_success`, or one of
         *  - @ref channel_error::timeout
         *  - @ref channel_error::hw_error
         * @see comm_rx_mode
         */
        virtual result<> raw_receive(mlab::range<bin_data::iterator> buffer, ms timeout) = 0;

        /**
         * Determines whether multiple calls to @ref raw_receive can be performed as part of a single
         * receive operation (in-between @ref on_receive_prepare and @ref on_receive_complete).
         */
        [[nodiscard]] virtual comm_rx_mode raw_receive_mode() const = 0;

        /**
         * @name Channel events
         * These methods are paired `on_*_prepare`/`on_*_complete`. They are guaranteed to be called in pairs,
         * each `prepare` is followed by one `complete`.
         * If @ref raw_receive_mode is true, then multiple @ref raw_receive calls may be performed subsequently
         * in-between a @ref on_receive_prepare and a @ref on_receive_complete; otherwise, at most one call is
         * performed.
         * For sending data, there is always a single call to @ref raw_send in-between @ref on_send_prepare and its
         * counterpart @ref on_send_complete.
         * @{
         */
        /**
         * @brief Prepares the underlying channel for data reception.
         * The default implementation does nothing.
         * @param timeout Maximum time that can be used to set the channel up.
         * @return A boolean representing whether setup has been completed within the given @p timeout.
         */
        virtual bool on_receive_prepare(ms timeout) { return true; }
        /**
         * @brief Signals that the reception has been completed.
         * The default implementation does nothing.
         * @param outcome Result of the @ref raw_receive operation.
         */
        virtual void on_receive_complete(result<> const &outcome) {}
        /**
         * @brief Prepares the underlying channel for data trasmission.
         * The default implementation does nothing.
         * @param timeout Maximum time that can be used to set the channel up.
         * @return A boolean representing whether setup has been completed within the given @p timeout.
         */
        virtual bool on_send_prepare(ms timeout) { return true; }
        /**
         * @brief Signals that the transmission has been completed.
         * The default implementation does nothing.
         * @param outcome Result of the @ref raw_send operation.
         */
        virtual void on_send_complete(result<> const &outcome) {}
        /**
         * @}
         */

        /**
         * @brief Transmits the given @p frame to the PN532 in at most @p timeout milliseconds.
         * @param frame Frame to transmit.
         * @param timeout Maximum time allowed for the send operation.
         * @return Either `mlab::result_success`, or one of
         *  - @ref channel_error::timeout
         *  - @ref channel_error::hw_error
         */
        result<> send(any_frame const &frame, ms timeout);

        /**
         * @brief Reads one frame sent by the PN532 to the host in at most @p timeout milliseconds.
         * This method will appropriately call @ref raw_receive the suitable number of times in order to receive a @ref frame,
         * according to @ref raw_receive_mode.
         * @param timeout Maximum time allowed for the entire receive operation (this time might cover multiple calls to @ref raw_receive).
         * @return Either the received frame, or one of
         *  - @ref channel_error::timeout
         *  - @ref channel_error::hw_error
         *  - @ref channel_error::malformed
         */
        [[nodiscard]] result<any_frame> receive(ms timeout);

    public:
        /**
         * @brief Pure virtual: wakes up the PN532 from slumber.
         * This usually corresponds to sending some trigger garbage bytes over the channel, or raising/lowering some interrupt line.
         * @return A boolean representing whether the wake up operation has succeeded.
         */
        virtual bool wake() = 0;

        /**
         * @brief Sends a @ref frame_type::ack or a @ref frame_type::nack frame.
         * @param ack_value True for an @ref frame_type::ack frame, false for @ref frame_type::nack.
         * @param timeout Maximum time for sending the frame.
         * @return Either `mlab::result_success`, or one of
         *  - @ref channel_error::timeout
         *  - @ref channel_error::hw_error
         */
        result<> send_ack(bool ack_value, ms timeout);

        /**
         * @brief Waits until a @ref frame_type::ack or a @ref frame_type::nack frame is received..
         * @param ack_value True for an @ref frame_type::ack frame, false for @ref frame_type::nack.
         * @param timeout Maximum time for getting a response.
         * @returns `mlab::result_success` if the specified frame has been received, otherwise one of
         *  - @ref channel_error::malformed (this return code will be issued also if a NACK was expected but an ACK was sent, or vice versa)
         *  - @ref channel_error::hw_error
         *  - @ref channel_error::timeout
         *  - @ref channel_error::app_error
         */
        result<> receive_ack(bool ack_value, ms timeout);

        /**
         * @brief Sends a command without waiting for a response.
         * @param cmd Command code.
         * @param data Max 263 bytes, will be truncated.
         * @param timeout Maximum time for sending the frame.
         * @return `mlab::result_success` or any @ref channel_error.
         */
        result<> command(command_code cmd, bin_data data, ms timeout);

        /**
         * @brief Waits for a response frame of a specific command.
         * @param cmd Command code.
         * @param timeout Maximum time for getting a response.
         * @return Either the received data, or one of
         *  - @ref channel_error::malformed (this covers also the case of a @ref frame_type not begin an @ref frame_type::info frame).
         *  - @ref channel_error::timeout
         *  - @ref channel_error::malformed
         */
        [[nodiscard]] result<bin_data> response(command_code cmd, ms timeout);

        /**
         * @brief Command with response.
         * This calls subsequently @ref command and @ref response.
         * @param cmd Command code.
         * @param data Max 263 bytes, will be truncated.
         * @param timeout Maximum time for sending the frame and getting a response.
         * @return Either the received data, or any @ref channel_error (including @ref channel_error::malformed if the frame received is not an
         *  @ref frame_type::info frame).
         */
        [[nodiscard]] result<bin_data> command_response(command_code cmd, bin_data data, ms timeout);

        /**
         * @brief Command with a typed response which can be extracted from a `bin_stream`.
         * @tparam Data A type that supports `mlab::bin_stream &operator>>(mlab::bin_stream &, Data &)`.
         * @param cmd Command code.
         * @param data Max 263 bytes, will be truncated.
         * @param timeout Maximum time for sending the frame and getting a response.
         * @return Either the received data, or any @ref channel_error (including @ref channel_error::malformed if the frame received is not an
         *  @ref frame_type::info frame or if the data cannot be parsed.).
         */
        template <class Data, class = typename std::enable_if<bin_stream::is_extractable<Data>::value>::type>
        [[nodiscard]] result<Data> command_parse_response(command_code cmd, bin_data data, ms timeout);

    private:
        /**
         * Receives the frame one piece at a time.
         */
        [[nodiscard]] result<any_frame> receive_stream(ms timeout);

        /**
         * Receives the frame but restarts every time it needs to read a new chunk.
         */
        [[nodiscard]] result<any_frame> receive_restart(ms timeout);

        bool _has_operation = false;
    };


    /**
     * @addtogroup StringConversion
     * @{
     */
    [[nodiscard]] const char *to_string(frame_type type);

    [[nodiscard]] const char *to_string(channel_error e);
    /**
     * @}
     */

    /**
     * @brief Class managing the correct firing of the events in @ref channel.
     *
     * This class is a RAII wrapper that fires the correct events at construction and destruction. It holds the
     * transmission @ref result obtained so far (or the corresponding error), in such a way that it
     * can pass it to @ref channel::on_receive_complete or @ref channel::on_send_complete.
     * Use the passthrough methods @ref comm_operation::update to record results or errors, as in the example below.
     * Use the @ref comm_operation::ok accessor to check whether the @ref channel::on_receive_prepare
     * or @ref channel::on_send_prepare events were successful before calling any lower level function.
     *
     * @warning Always call @ref channel::raw_send and @ref channel::raw_receive with one such class in scope
     *  (otherwise the events will not be fired and the class may not be in the correct state).
     *
     * @note Subclasses should never directly call any of @ref channel::on_receive_prepare,
     * @ref channel::on_receive_complete, @ref channel::on_send_prepare, @ref channel::on_send_complete.
     * These are managed by this class.
     *
     * @code
     *  using namespace std::chrono_literals;
     *
     *  // In a subclass of channel
     *  result<any_frame> chn_subclass::custom_receive_frame() {
     *      // Create a comm_operation alive within the scope of the if.
     *      // This fires on_receive_prepare, and test with ::ok() whether it succeeded.
     *      if (comm_operation op{*this, comm_dir::receive, 10ms}; op.ok()) {
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
     *                  return op.update(error::malformed);
     *              }
     *              // Extract the frame
     *              any_frame f{};
     *              std::tie(s, fid) >> f;
     *              if (s.bad()) {
     *                  // Could not parse the frame, update the comm_operation and return
     *                  return op.update(error::malformed);
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
     *      if (comm_operation op{*this, comm_dir::send, 10ms}; op.ok()) {
     *          // Attempt sending data; use the result to update the comm operation
     *          //  and passthrough. An explicit cast to bool is required here.
     *          return bool(op.update(raw_send({0x55, 0x55, 0x55}, 10ms)));
     *      } else {
     *          return false;
     *      }
     *  }
     * @endcode
     */
    class comm_operation {
        channel &_owner;
        comm_dir _event;
        result<> _result;

    public:
        /**
         * Calls @ref channel::on_receive_prepare or @ref channel::on_send_prepare and stores the outcome.
         * @param owner The target class for calling @ref channel::on_receive_prepare or @ref channel::on_send_prepare.
         * @param event Chooses between @ref channel::on_receive_prepare, @ref channel::on_receive_complete and @ref channel::on_send_prepare,
         *  @ref channel::on_send_complete.
         * @param timeout Timeout to pass to @ref channel::on_receive_prepare or @ref channel::on_send_prepare.
         * @see ok
         */

        comm_operation(channel &owner, comm_dir event, ms timeout);

        /**
         * Calls @ref channel::on_receive_complete or @ref channel::on_send_complete with the internally stored result.
         */
        ~comm_operation();

        /**
         * @brief Tests whether the operation contains an error or not.
         * The main usage of this is to test whether the @ref channel::on_receive_prepare and @ref channel::on_send_prepare
         * events have succeeded; however it will also return false if e.g. @ref update has been called with a failed result.
         * @return True if an only if so far all the operations succeeded.
         *
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
         * @note This calls `mlab::result::error`; if the result is not an error, it is not
         *  possible to call this method, therefore test first with @ref ok that this @ref comm_operation contains
         *  in fact an error code.
         */
        [[nodiscard]] inline channel_error error() const;

        /**
         * @name Collect and update methods
         * These methods collect a result, an error, or a boolean representing success and store it inside the
         * class. Moreover, they return whatever was passed to them (in the form of @ref result or in form
         * of @ref channel_error), in such a way that the user can directly pass it through in a `return` statement.
         * The updated result is used in the call to @ref channel::on_receive_complete and @ref channel::on_send_complete.
         * @code
         * comm_operation op{...};
         * // ...
         * return op.update(raw_send(...));
         * @endcode
         * @{
         */

        /**
         * Stores an error state from an explicit error code.
         * @param e Error code.
         * @return The same error code @p e.
         */
        [[nodiscard]] inline channel_error update(channel_error e);

        /**
         * Stores a success or timeout state from a boolean.
         * @param operation_result True if the operation succeded, false if it timed out.
         * @return `mlab::result_success` or @ref channel_error::timeout, depending on @p operation_result.
         */
        [[nodiscard]] inline result<> update(bool operation_result);

        /**
         * Stores an existing result into the internal @ref result
         * @tparam Tn Any result type for @ref result.
         * @tparam Args Anything that can be assigned to @ref result.
         * @param args Anything that can be assigned to @ref result.
         * @return The same result as the one constructed.
         */
        template <class... Tn, class... Args>
        [[nodiscard]] inline result<Tn...> update(Args &&...args);
        /**
         * @}
         */
    };

}// namespace pn532

namespace pn532 {

    template <class Data, class>
    result<Data> channel::command_parse_response(command_code cmd, bin_data data, ms timeout) {
        if (const auto res_cmd = command_response(cmd, std::move(data), timeout); res_cmd) {
            bin_stream s{*res_cmd};
            auto retval = Data();
            s >> retval;
            if (s.bad()) {
                PN532_LOGE("%s: could not parse result from response data.", to_string(cmd));
                return channel_error::malformed;
            }
            if (not s.eof()) {
                PN532_LOGW("%s: stray data in response (%d bytes).", to_string(cmd), s.remaining());
            }
            return retval;
        } else {
            return res_cmd.error();
        }
    }

    bool comm_operation::ok() const {
        return bool(_result);
    }

    channel_error comm_operation::error() const {
        return _result.error();
    }

    channel_error comm_operation::update(channel_error e) {
        _result = e;
        return e;
    }

    result<> comm_operation::update(bool operation_result) {
        if (operation_result) {
            _result = mlab::result_success;
        } else {
            _result = channel_error::timeout;
        }
        return _result;
    }

    template <class... Tn, class... Args>
    result<Tn...> comm_operation::update(Args &&...args) {
        result<Tn...> retval{std::forward<Args>(args)...};
        if (retval) {
            _result = mlab::result_success;
        } else {
            _result = retval.error();
        }
        return retval;
    }
}// namespace pn532
#endif//PN532_CHANNEL_REPL_HPP
