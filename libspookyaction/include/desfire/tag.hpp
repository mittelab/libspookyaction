//
// Created by Pietro Saccardi on 02/01/2021.
//

/**
 * @defgroup card Mifare Card
 *
 * @defgroup application Application management
 *
 * @defgroup data Data storage
 *
 * @defgroup standardFile Standard file
 *
 * @defgroup backupFile Backup file
 *
 * @defgroup recordFile Cyclic or linear record file
 *
 * @defgroup valueFile Value file
 *
 * @defgroup cardAndApplication Application/card authentication
 *
 * @defgroup standardAndBackupFile Data files
 *
 * @defgroup committableFiles Committable files
 */

#ifndef DESFIRE_TAG_HPP
#define DESFIRE_TAG_HPP

#include <desfire/cipher_provider.hpp>
#include <desfire/data.hpp>
#include <desfire/keys.hpp>
#include <desfire/msg.hpp>
#include <desfire/pcd.hpp>
#include <desfire/protocol.hpp>
#include <list>
#include <memory>
#include <mlab/result.hpp>
#include <pn532/bits.hpp>
#include <type_traits>

namespace pn532 {
    class controller;
}

namespace ut::desfire_exchanges {
    struct session;
}

namespace desfire {
    using mlab::bin_stream;
    using mlab::lsb_t;


    /**
     * @brief Monostate structure that marks that implicitly accepts the @ref file_security provided on a @ref tag.
     * The unique instance of this structure, @ref trust_card, is used to select certain overloads in @ref desfire::tag.
     * @see desfire::trust_card
     */
    struct trust_card_t {};

    /**
     * @brief Flag marking the card as trusted, which enables determining automatically the communication mode from file settings..
     *
     * When using this instead of an explicitly set @ref comm_mode (in the methods of @ref tag that allow to do so),
     * @ref tag will be instructed to query and accept whatever security mode the file is written in. This might impact
     * security because a cloned card with different file security modes could prompt for a different communication mode
     * than the one intended. Therefore, they have to be called explicitly with `trust_card`.
     * @see
     *  - tag::change_file_settings(file_id fid, common_file_settings const &settings, trust_card_t)
     *  - tag::read_data(file_id fid, trust_card_t, std::uint32_t offset = 0, std::uint32_t length)
     *  - tag::write_data(file_id fid, bin_data const &data, trust_card_t, std::uint32_t offset)
     *  - tag::get_value(file_id fid, trust_card_t)
     *  - tag::credit(file_id fid, std::int32_t amount, trust_card_t)
     *  - tag::limited_credit(file_id fid, std::int32_t amount, trust_card_t)
     *  - tag::debit(file_id fid, std::int32_t amount, trust_card_t)
     *  - tag::write_record(file_id fid, bin_data const &data, trust_card_t, std::uint32_t offset)
     *  - tag::write_record(file_id fid, T &&record, trust_card_t)
     *  - tag::read_parse_records(file_id fid, trust_card_t, std::uint32_t index, std::uint32_t count)
     *  - tag::read_records(file_id fid, trust_card_t, std::uint32_t record_index, std::uint32_t record_count)
     */
    static constexpr trust_card_t trust_card{};

    /**
     * Constant marking that all records have to be read.
     * @see
     *  - tag::read_parse_records(file_id fid, trust_card_t, std::uint32_t index, std::uint32_t count)
     *  - tag::read_parse_records(file_id fid, comm_mode operation_mode, std::uint32_t index, std::uint32_t count)
     *  - tag::read_records(file_id fid, trust_card_t, std::uint32_t record_index, std::uint32_t record_count)
     */
    static constexpr std::uint32_t all_records = 0;

    /**
     * Constant marking that a file has to be read until the end.
     * @see
     *  - tag::read_data(file_id fid, trust_card_t, std::uint32_t offset, std::uint32_t length)
     *  - tag::read_data(file_id fid, comm_mode operation_mode, std::uint32_t offset, std::uint32_t length)
     */
    static constexpr std::uint32_t all_data = 0;

    /**
     * A variant type which either holds arbitrary data, or an error code in the form of a @ref error.
     * @note The errors produced by the PN532 commands are of @ref pn532::channel_error type, not of @ref error type.
     */
    template <class... Tn>
    using result = mlab::result<error, Tn...>;

    /**
     * @brief Lightweight data structure expressing the communication settings to use for a desfire command.
     * @note This is not relevant for the end user, unless you are calling @ref tag::command_status_response,
     *  @ref tag::command_response or @ref tag::command_parse_response manually.
     */
    struct comm_cfg {
        comm_mode tx = comm_mode::plain;      //!< Communication mode to use to send data
        comm_mode rx = comm_mode::plain;      //!< Communication mode to use to receive data
        std::size_t tx_secure_data_offset = 0;//!< Offset of the sensitive data that needs to be secure in the outgoing transmission.
        /**
         * @brief Flag marking whether this communication configuration has been tested to be correct.
         * If the user was specifying the communication mode, then this should be set to false. It will produce an extra
         * log message in case of error.
         * @note In some cases, e.g. all methods that receive @ref trust_card, the user can specify the communication mode (e.g. in the
         *  form of a @ref file_security value). This means that the communication has a chance of failing, if the communication mode
         *  does not match the one of the file on the card. For these methods, @ref is_validated should be set to false. For regular
         *  communication, it should be set to true. This is used to distinguish between an implementation error (i.e. a command has been
         *  issued with the wrong mode, which is an implementation error) or a parameter error (i.e. the user expects a different file
         *  security than the one present on the card).
         */
        bool is_validated = false;

        /**
         * Constructs (implicitly) a @ref comm_cfg with identical @ref tx and @ref rx modes, set to @p txrx.
         * @param txrx This will be the value for @ref tx and @ref rx.
         * @param sec_data_ofs This will be the value for @ref tx_secure_data_offset. Defaults to 1 because the command code is never secured.
         * @param validated This will be the value for @ref is_validated.
         */
        inline constexpr comm_cfg(comm_mode txrx, std::size_t sec_data_ofs = 1, bool validated = false);

        /**
         * Constructs a @ref comm_cfg with distinct @ref tx and @ref rx modes.
         * @param tx This will be the value for @ref tx.
         * @param rx This will be the value for @ref rx.
         * @param sec_data_ofs This will be the value for @ref tx_secure_data_offset.
         * @param validated This will be the value for @ref is_validated.
         */
        inline constexpr comm_cfg(comm_mode tx, comm_mode rx, std::size_t sec_data_ofs = 1, bool validated = false);
    };


    template <class T>
    concept is_parsable_reponse_t = mlab::is_extractable<T> or std::is_integral_v<T>;

    /**
     * @brief Main class representing a Desfire tag.
     * @note This class is stateful, and despite being very lightweight (does not store anything about the card),
     *  still has to store the protocol and cipher status, authentication status, active app and so on. It does *not* store
     *  the keys, that are only used for authentication and to derive a session key (which might be stored into the @ref crypto
     *  implementation).
     */
    class tag {
    public:
        /**
         * @brief Construct a new tag object.
         * @note If you want to handle a custom PCD, you should extend @ref desfire::pcd and implement @ref desfire::pcd::communicate.
         *
         * @param pcd A @ref desfire::pcd class that handles the tag communication.
         * @param provider Any @ref cipher_provider implementation to build @ref crypto and @ref protocol from a key.
         * @see
         *  - make(PCD &&pcd)
         *  - make(pn532::controller &ctrl, std::uint8_t logical_index)
         */
        tag(std::shared_ptr<desfire::pcd> pcd, std::unique_ptr<cipher_provider> provider);

        /**
         * @brief Construct a new tag object through a @ref pn532::desfire_pcd PCD subclass.
         * @param ctrl PN532 controller.
         * @param logical_index Logical index of the target.
         * @param provider Any @ref cipher_provider implementation to build @ref crypto and @ref protocol from a key.
         * @see
         *  - pn532::desfire_pcd
         *  - pn532::controller::initiator_data_exchange
         *  - make(PCD &&pcd)
         *  - make(pn532::controller &ctrl, std::uint8_t logical_index)
         */
        tag(pn532::controller &ctrl, std::uint8_t logical_index, std::unique_ptr<cipher_provider> provider);

        /**
         * @name Factory methods
         * @{
         */
        /**
         * @brief Constructs a new tag object instantiating the given cipher provider.
         * @tparam CipherProvider A subclass of @ref desfire::cipher_provider, which must be default-constructible.
         * @tparam PCD A subclass of @ref desfire::pcd or a `std::shared_ptr` to such a subclass.
         * @param pcd A (shared pointer of) a subclass of @ref desfire::pcd used as pcd for the tag.
         * @return An instance of @ref tag.
         *
         * @code
         * // Assume we have a `pn532::controller ctrl{}`;
         * // Assume we have scanned for a target with logical index 1.
         * // Assume we want to retain access to the desfire_pcd instance in order to analyze errors:
         * auto p_pcd = std::make_shared<pn532::desfire_pcd>(ctrl, 1);
         * auto tag = desfire::tag::make<desfire::esp32::default_cipher_provider>(p_pcd);
         * // If we do not care about dealing with the pcd we might as well do:
         * auto tag_ = desfire::tag::make<desfire::esp32::default_cipher_provider>(pn532::desfire_pcd{ctrl, 1});
         * @endcode
         * @note If you just want to use @ref pn532::desfire_pcd, consider using @ref make(pn532::controller &ctrl, std::uint8_t logical_index).
         */
        template <class CipherProvider, class PCD>
        [[nodiscard]] static inline tag make(PCD &&pcd);

        /**
         * @brief Constructs a new tag object instantiating the given cipher provider, and using @ref pn532::desfire_pcd as PCD.
         * @tparam CipherProvider A subclass of @ref desfire::cipher_provider, which must be default-constructible.
         * @param ctrl PN532 controller.
         * @param logical_index Logical index of the target.
         * @return An instance of @ref tag.
         *
         * @code
         * // Assume we have a `pn532::controller ctrl{}`;
         * // Assume we have scanned for a target with logical index 1.
         * auto tag = desfire::tag::make<desfire::esp32::default_cipher_provider>(ctrl, 1);
         * @endcode
         */
        template <class CipherProvider>
        [[nodiscard]] static inline tag make(pn532::controller &ctrl, std::uint8_t logical_index);
        /**
         * @}
         */

        /**
         * @name Move-only semantics.
         * @{
         */
        tag(tag const &) = delete;
        tag(tag &&) = default;
        tag &operator=(tag const &) = delete;
        tag &operator=(tag &&) = default;
        /**
         * @}
         */

        /**
         * @brief Exchanges a raw command with the tag.
         * @param tx_data Already preprocessed data, containing command code and payload.
         * @param rx_fetch_additional_frames If true and the response is marked as being incomplete ("additional frames"),
         *  it will automatically continue fetching data until when the response is complete. Otherwise, it will return the
         *  response with the additional frame marker as-is.
         * @return bin_data, or the following errors:
         * - @ref error::malformed
         * - @ref error::controller_error
         * @note This method is *not* private because we do not have access to a Desfire/Mifare specification, therefore we cannot
         *  guarantee that the list of commands implemented here is at all complete. Users who have access to the manual may therefore
         *  directly send packets encoding further commands without having to explicitly extend or modify this class.
         */
        result<bin_data> raw_command_response(bin_stream &tx_data, bool rx_fetch_additional_frames);

        /**
         * @brief Assembles and preprocesses a commands, sends it over and postprocesses the answer.
         * This method automatically divides @p data into appropriate chunks and sends them to the PICC, pre-processing
         * the data to send according to @p cfg by means of @ref protocol::prepare_tx (which is called on every chunk).
         * It will then collect the response data, and if @p cfg allows, it will also automatically concatenate all
         * response chunks, should the PICC request to send additional frames. The response data is the post-processed
         * by means of @ref protocol::confirm_rx, as set by @p cfg. The status byte is passed through and returned.
         *
         * @note Only returns an error in case of malformed packet sequence, communication error, malformed data in the
         * sense of not passing @ref protocol::confirm_rx. All other status codes are passed through as the first result
         * arguments. To automatically convert the status into an error, see @ref command_response or
         * @ref command_parse_response. This is a lower level command.
         * @see
         *  - command_response
         *  - command_parse_response
         * @ingroup data
         * @param cmd Command code of the command to issue.
         * @param payload Payload of the command (might be empty).
         * @param cfg Communication configuration.
         * @param rx_fetch_additional_frames If true and the response is marked as being incomplete ("additional frames"),
         *  it will automatically continue fetching data until when the response is complete. Otherwise the returned status byte
         *  will be "additional frames".
         * @param override_protocol Specify a valid pointer to a protocol to use a different protocol other than the currently set up one
         *  for preparing the transmission and decoding the response. This is useful in a very specific scenario: when authenticating to
         *  a different key.
         * @return The status and the response payload, or one the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        result<bits::status, bin_data> command_status_response(bits::command_code cmd, bin_data const &payload, comm_cfg const &cfg, bool rx_fetch_additional_frames = true, protocol *override_protocol = nullptr);

        /**
         * @brief Like @ref command_status_response, but will also convert the status byte into a @ref error.
         * Will automatically fetch all additional frames if requested to do so by @p cfg, and at the end will parse the
         * status byte to decide whether the command was successful (`status::ok` or `status::no_changes`).
         * @ingroup data
         * @param cmd Command code of the command to issue.
         * @param payload Payload of the command (might be empty).
         * @param cfg Communication configuration.
         * @param rx_fetch_additional_frames If true and the response is marked as being incomplete ("additional frames"),
         *  it will automatically continue fetching data until when the response is complete. Otherwise the returned status byte
         *  will be "additional frames".
         * @param override_protocol Specify a valid pointer to a protocol to use a different protocol other than the currently set up one
         *  for preparing the transmission and decoding the response. This is useful in a very specific scenario: when authenticating to
         *  a different key.
         * @return The response payload, or any of @ref error.
         * @see command_status_response
         */
        result<bin_data> command_response(bits::command_code cmd, bin_data const &payload, comm_cfg const &cfg, bool rx_fetch_additional_frames = true, protocol *override_protocol = nullptr);

        /**
         * @brief Like @ref command_response, but will also parse the returned `bin_data` into a specific type `Data`.
         * This command will always fetch additional frames until the end.
         * @ingroup data
         * @tparam Data Type into which to convert the obtained response data. Must be extractable from `mlab::bin_stream`.
         * @param cmd Command code of the command to issue.
         * @param payload Payload of the command (might be empty).
         * @param cfg Communication configuration.
         * @return The response payload, or any of @ref error.
         * @see command_response
         */
        template <is_parsable_reponse_t Data>
        result<Data> command_parse_response(bits::command_code cmd, bin_data const &payload, comm_cfg const &cfg);

        /**
         * The currently active app id (by default, @ref root_app).
         * @ingroup card
         * @see select_application
         */
        [[nodiscard]] inline app_id const &active_app() const;

        /**
         * The @ref cipher_type of the currently active key (by default, @ref cipher_type::none).
         * @see authenticate
         * @ingroup cardAndApplication
         */
        [[nodiscard]] inline cipher_type active_cipher_type() const;

        /**
         * The number of the currently authenticated key (0..13, included), or `0xff` if no authentication has taken place.
         * @ingroup cardAndApplication
         * @see authenticate
         */
        [[nodiscard]] inline std::uint8_t active_key_no() const;

        /**
         * @brief Authenticates to the active application @ref active_app with key @p k.
         * As a consequence, @ref active_cipher_type and @ref active_key_no will be updated.
         * @ingroup cardAndApplication
         * @param k Key to use to authenticate.
         * @return Either `mlab::result_success` or any of @ref error (usually @ref error::authentication_error or @ref error::permission_denied).
         */
        result<> authenticate(any_key const &k);

        /**
         * @brief Authenticates to the active application @ref active_app with key @p k.
         * As a consequence, @ref active_cipher_type and @ref active_key_no will be updated.
         * Strongly-typed version of @ref authenticate(any_key const &).
         * @ingroup cardAndApplication
         * @tparam Type Type of the key and cipher.
         * @param k Key to use to authenticate.
         * @return Either `mlab::result_success` or any of @ref error (usually @ref error::authentication_error or @ref error::permission_denied).
         */
        template <cipher_type Type>
        result<> authenticate(key<Type> const &k);

        /**
         * @dot
         * digraph AlignmentMap {
         *  node [shape=record fontname="sans-serif"];
         *  rankdir=LR;
         *  sent1 [label="{0x5A\n[1 byte]|AID\n[3 byte LSB first]}"];
         *  received1 [label="{0x00\n[1 byte]}"];
         *  error [style=dashed label="{Error code\n[1 byte]}"];
         *  sent1 -> {received1 error}[ sametail="b"];
         * }
         * @enddot
         *
         * @brief Selects the application to use for successive operations.
         * After selecting a new application, the PICC is logged out and you need to @ref authenticate again.
         * @ingroup cardAndApplication
         * @param aid The id of the app to be selected.
         * @return Either `mlab::result_success` or any of @ref error. If the app is not present, @ref error::app_not_found is returned.
         */
        result<> select_application(app_id const &aid = root_app);

        /**
         * @dot
         * digraph AlignmentMap {
         *  node [shape=record fontname="sans-serif"];
         *  rankdir=LR;
         *  sent1 [label="{0xCA\n[1 byte]|AID\n[3 byte LSB first]|key settings\n[1 byte]|# of Keys\n[1 byte]}"];
         *  received1 [label="{0x00\n[1 byte]}"];
         *  error [style=dashed label="{Error code\n[1 byte]}"];
         *  sent1 -> {received1 error}[ sametail="b"];
         * }
         * @enddot
         *
         * @brief Add a new application to the card.
         * Must be on the @ref root_app for this to succeed (@ref select_application), and a previous @ref authenticate
         * must have taken place, unless the @ref root_app's @ref key_rights::create_delete_without_master_key is set
         * to true. In that case, no authentication is necessary.
         * @ingroup application
         * @param aid The id of the new app to be created.
         * @param settings Configuration of tha app (mainly: number of keys and witch cipher to use)
         * @return Either `mlab::result_success` or any of @ref error, in particular @ref error::permission_denied if the operation is now allowed,
         *  or @ref error::duplicate_error if the app exists already.
         */
        result<> create_application(app_id const &aid, app_settings settings);

        /**
         * @dot
         * digraph AlignmentMap {
         *  node [shape=record fontname="sans-serif"];
         *  rankdir=LR;
         *  sent1 [label="{0x54\n[1 byte]|key settings\n[8 byte enchipered]}"];
         *  received1 [label="{0x00\n[1 byte]}"];
         *  error [style=dashed label="{Error code\n[1 byte]}"];
         *  sent1 -> {received1 error}[ sametail="b"];
         * }
         * @enddot
         *
         * @brief Change the setting of @ref active_app.
         * This requires a previous @ref authenticate command with the app master key (i.e. key number zero);
         * moreover the app's @ref key_rights::config_changeable must be set to true.
         * @ingroup application
         * @param new_rights the new app settings
         * @return Either `mlab::result_success` or any of @ref error, in particular @ref error::permission_denied.
         */
        result<> change_app_settings(key_rights new_rights);

        /**
         * @dot
         * digraph AlignmentMap {
         *  node [shape=record fontname="sans-serif"];
         *  rankdir=LR;
         *  sent1 [label="{0x45\n[1 byte]}"];
         *  received1 [label="{0x00\n[1 byte]|key settings\n[1 byte]|# of Keys\n[1 byte]}"];
         *  error [style=dashed label="{Error code\n[1 byte]}"];
         *  sent1 -> {received1 error}[ sametail="b"];
         * }
         * @enddot
         *
         * @brief Get the configuration of @ref active_app.
         * The app need to be selected first (with @ref select_application) for this to succeed.
         * Moreover, you need to @ref authenticate with the master key, unless the app's @ref key_rights::dir_access_without_auth
         * is set to true.
         * @ingroup application
         * @return The @ref app_settings, any of @ref error, in particular @ref error::permission_denied.
         */
        [[nodiscard]] result<app_settings> get_app_settings();

        /**
         * @dot
         * digraph AlignmentMap {
         *  node [shape=record fontname="sans-serif"];
         *  rankdir=LR;
         *  sent1 [label="{0x64\n[1 byte]|Key #\n[1 byte]}"];
         *  received1 [label="{0x00\n[1 byte]|key version\n[1 byte]}"];
         *  error [style=dashed label="{Error code\n[1 byte]}"];
         *  sent1 -> {received1 error}[ sametail="b"];
         * }
         * @enddot
         *
         * @brief Get the version of the key (in the @ref active_app).
         * @ingroup application
         * @param key_no Number of the key, an integer in the range 0..13 (included).
         *  If an out-of-range number is specified, this method returns @ref error::parameter_error.
         * @return Integer representing the key version, any of @ref error, in particular
         *  @ref error::parameter_error.
         */
        [[nodiscard]] result<std::uint8_t> get_key_version(std::uint8_t key_no);

        /**
         * @dot
         * digraph AlignmentMap {
         *  node [shape=record fontname="sans-serif"];
         *  rankdir=LR;
         *  sent1 [label="{0x6A\n[1 byte]}"];
         *  received1 [label="{0x00\n[1 byte]|AID\n[3xN byte 0-7 AIDs]}"];
         *  received2 [label="{0xAF\n[1 byte]|AID\n[3xN byte 0-19 AIDs]}"];
         *  received3 [label="{0x00\n[1 byte]|AID\n[3xN byte 0-7 AIDs]}"];
         *  error [style=dashed label="{Error code\n[1 byte]}"];
         *  sent2 [label="{0xAF\n[1 byte]}"];
         *  sent1 -> {received1 received2 error}[sametail="b"];
         *  received2 -> sent2 -> received3;
         * }
         * @enddot
         *
         * @brief Get a list of all application in the card.
         * Must be on the @ref root_app (@ref select_application) for this to succeed.
         * Moreover, a previous @ref authenticate command might be required, unless the @ref root_app's @ref key_rights::dir_access_without_auth
         * is set to true.
         * @ingroup application
         * @return Vector of @ref app_id, any of @ref error, in particular @ref error::permission_denied.
         */
        [[nodiscard]] result<std::vector<app_id>> get_application_ids();

        /**
         * @dot
         * digraph AlignmentMap {
         *  node [shape=record fontname="sans-serif"];
         *  rankdir=LR;
         *  sent1 [label="{0xDA\n[1 byte]|AID\n[3 byte LSB first]}"];
         *  received1 [label="{0x00\n[1 byte]}"];
         *  error [style=dashed label="{Error code\n[1 byte]}"];
         *  sent1 -> {received1 error}[ sametail="b"];
         * }
         * @enddot
         *
         * @brief Delete the application, and all data stored in it.
         * Must authenticated on the @ref root_app or in @p aid, with the master key (key number zero) for this
         * to succeed. Alternatively, if the @ref root_app's @ref key_rights::create_delete_without_master_key
         * is set to true, the deletion can be performed without authentication on the @ref root_app.
         * @ingroup application
         * @param aid The app ID of the application to be deleted
         * @return Either `mlab::result_success` or any of @ref error, in particular @ref error::permission_denied.
         */
        result<> delete_application(app_id const &aid);

        /**
         * @dot
         * digraph AlignmentMap {
         *  node [shape=record fontname="sans-serif"];
         *  rankdir=LR;
         *     graph [ranksep=2]
         *
         *  subgraph cluster_ss{
         *  sent1 [label="{0x60\n[1 byte]}"];
         *  sent2 [label="{0xAF\n[1 byte]}"];
         *  sent3 [label="{0xAF\n[1 byte]}"];
         *  }
         *
         *  subgraph cluster_rr{
         *  received1 [label="{0xAF\n[1 byte]|Vendor ID\n[1 byte]|Type\n[1 byte]|Sub-type\n[1 byte]|Mayor version\n[1 byte]|Minor version\n[1 byte]|Tag size\n[1 byte]|protocol\n[1 byte]}"];
         *  received2 [label="{0xAF\n[1 byte]|Vendor ID\n[1 byte]|Type\n[1 byte]|Sub-type\n[1 byte]|Mayor version\n[1 byte]|Minor version\n[1 byte]|Tag size\n[1 byte]|protocol\n[1 byte]}"];
         *  received3 [label="{0x00\n[1 byte]|UID\n[7 byte]|Batch #\n[5 byte]|Production week\n[1 byte]|Production year\n[1 byte]}"];
         *  }
         *  sent1 -> received1 [samehead="s1" ];
         *  sent2 -> received1 [samehead="s1" sametail="r1" dir=back ];
         *  sent2 -> received2[sametail="r1" samehead="s2"];
         *  sent3 -> received2[samehead="s2" sametail="r2" dir=back];
         *  sent3 -> received3[sametail="r2"];
         * }
         * @enddot
         *
         * @brief Read tag information.
         * Serial number, production year and so on.
         * We conjecture this can be called on any app and without authentication.
         * @ingroup card
         * @return A @ref manufacturing_info instance containing tag information, or any of @ref error.
         */
        [[nodiscard]] result<manufacturing_info> get_info();


        /**
         *
         * @dot
         * digraph AlignmentMap {
         *  node [shape=record fontname="sans-serif"];
         *  rankdir=LR;
         *  sent1 [label="{0xFC\n[1 byte]}"];
         *  received1 [label="{0x00\n[1 byte]}"];
         *  error [style=dashed label="{Error code\n[1 byte]}"];
         *  sent1 -> {received1 error}[ sametail="b"];
         * }
         * @enddot
         *
         * @brief Delete all the applications and files.
         * This requires a previous @ref authenticate of @ref root_app with the master (root) key.
         * Afterwards, the PICC will be on @ref root_app with no authentication.
         * @note This does not change the root key and the @ref root_app's settings!
         * @ingroup cardAndApplication
         * @return Either `mlab::result_success` or any of @ref error.
         */
        result<> format_picc();

        /**
         * @dot
         * digraph AlignmentMap {
         *  node [shape=record fontname="sans-serif"];
         *  rankdir=LR;
         *  sent1 [label="{0x54\n[1 byte]|Key #\n[1 byte]|key body\n[24 byte echipered]}"];
         *  received1 [label="{0x00\n[1 byte]}"];
         *  error [style=dashed label="{Error code\n[1 byte]}"];
         *  sent1 -> {received1 error}[ sametail="b"];
         * }
         * @enddot
         * @brief Changes the current key.
         * You must have a valid @ref authenticate with the key of the same number as @p new_key.
         * Moreover, the @ref active_app's @ref key_rights::allowed_to_change_keys must be either @ref same_key,
         * or exactly @ref active_key_no.
         * After this command, the app is unchanged but a new @ref authenticate command must be performed.
         * @ingroup cardAndApplication
         * @return Either `mlab::result_success`, or any of @ref error, in particular @ref error::permission_denied.
         */
        result<> change_key(any_key const &new_key);

        /**
         * @dot
         * digraph AlignmentMap {
         *  node [shape=record fontname="sans-serif"];
         *  rankdir=LR;
         *  sent1 [label="{0x54\n[1 byte]|Key #\n[1 byte]|key body\n[24 byte echipered]}"];
         *  received1 [label="{0x00\n[1 byte]}"];
         *  error [style=dashed label="{Error code\n[1 byte]}"];
         *  sent1 -> {received1 error}[ sametail="b"];
         * }
         * @enddot
         * @brief Changes the current key.
         * Strongly-typed version of @ref change_key(any_key const &).
         * You must have a valid @ref authenticate with the key of the same number as @p new_key.
         * Moreover, the @ref active_app's @ref key_rights::allowed_to_change_keys must be either @ref same_key,
         * or exactly @ref active_key_no.
         * After this command, the app is unchanged but a new @ref authenticate command must be performed.
         * @ingroup cardAndApplication
         * @return Either `mlab::result_success`, or any of @ref error, in particular @ref error::permission_denied.
         */
        template <cipher_type Type>
        result<> change_key(key<Type> const &new_key);

        /**
         * @brief Changes a key other than the @ref active_key_no.
         * You must have a valid @ref authenticate with the key specified by @ref active_app's @ref key_rights::allowed_to_change_keys
         * in order for this to succeed. Moreover, you still need to pass the key to be changed together with the new key.
         * In case of success, the app and the authentication status are unchanged.
         * @note You are not supposed to use this to change @ref active_key_no; if you do, this method will automatically attempt
         *  an @ref authenticate command with @p previous_key, and then call @ref change_key(any_key const &) with @p new_key instead.
         *  A new authentication will thus be required.
         * @param previous_key Key to change. The @ref any_key::key_number must match @p new_key's.
         * @param new_key New key. The @ref any_key::key_number must match @p previous_key's.
         * @ingroup cardAndApplication
         * @return Either `mlab::result_success`, or any of @ref error, in particular @ref error::permission_denied.
         */
        result<> change_key(any_key const &previous_key, any_key const &new_key);

        /**
         * @brief Changes a key other than the @ref active_key_no.
         * Strongly-typed version of @ref change_key(any_key const &, any_key const &).
         * You must have a valid @ref authenticate with the key specified by @ref active_app's @ref key_rights::allowed_to_change_keys
         * in order for this to succeed. Moreover, you still need to pass the key to be changed together with the new key.
         * In case of success, the app and the authentication status are unchanged.
         * @note You are not supposed to use this to change @ref active_key_no; if you do, this method will automatically attempt
         *  an @ref authenticate command with @p previous_key, and then call @ref change_key(any_key const &) with @p new_key instead.
         *  A new authentication will thus be required.
         * @param previous_key Key to change. The @ref any_key::key_number must match @p new_key's.
         * @param new_key New key. The @ref any_key::key_number must match @p previous_key's.
         * @ingroup application
         * @return Either `mlab::result_success`, or any of @ref error, in particular @ref error::permission_denied.
         */
        template <cipher_type Type>
        result<> change_key(key<Type> const &previous_key, key<Type> const &new_key);

        /**
         * @dot
         * digraph AlignmentMap {
         *  node [shape=record fontname="sans-serif"];
         *  rankdir=LR;
         *  sent1 [label="{0x6F\n[1 byte]}"];
         *  received1 [label="{0x00\n[1 byte]|FID\n[1xN byte (0-16 FIDs)]}"];
         *  error [style=dashed label="{Error code\n[1 byte]}"];
         *  sent1 -> {received1 error}[ sametail="b"];
         * }
         * @enddot
         *
         * @brief Get a list of files in @ref active_app.
         * You must have a preceding @ref authenticate command on the app, or @ref active_app's @ref key_rights::dir_access_without_auth
         * must be set to true.
         * @ingroup data
         * @return Vector of @ref file_id, or any of @ref error, in particular @ref error::permission_denied.
         */
        [[nodiscard]] result<std::vector<file_id>> get_file_ids();

        /**
         * @brief Read the file settings.
         * You must have a preceding @ref authenticate command on the app, or @ref active_app's @ref key_rights::dir_access_without_auth
         * must be set to true.
         * @ingroup data
         * @param fid The file id, in the range 0..15 (included).
         * @return A @ref any_file_settings containing the file settings, or any of @ref error. In particular, if
         *  the file does not exist, @ref error::file_not_found, or if the operation is not allowed,
         *  @ref error::permission_denied.
         */
        [[nodiscard]] result<any_file_settings> get_file_settings(file_id fid);

        /**
         * @brief Read the settings of a specific @ref file_type.
         * You must have a preceding @ref authenticate command on the app, or @ref active_app's @ref key_rights::dir_access_without_auth
         * must be set to true. Moreover, if the file exists, it must have exactly `Type` @ref file_type.
         * @ingroup data
         * @tparam Type Expected @ref file_type. In case of mismatch, @ref error::malformed is returned.
         * @param fid The file id, in the range 0..15 (included).
         * @return A @ref file_settings containing the file settings, or any of @ref error. In particular, if
         *  the file does not exist, @ref error::file_not_found, or if the operation is not allowed,
         *  @ref error::permission_denied. If the file exists but has the wrong @ref file_type, @ref error::malformed.
         */
        template <file_type Type>
        [[nodiscard]] result<file_settings<Type>> get_specific_file_settings(file_id fid);

        /**
         * @dot
         * digraph AlignmentMap {
         *  node [shape=record fontname="sans-serif"];
         *  rankdir=LR;
         *  sent1 [label="{0x5F\n[1 byte]|FID\n[1 byte]|Comm. settings\n[1 byte]|Access rights\n[2 byte LDB first]}"];
         *  received1 [label="{0x00\n[1 byte]}"];
         *  error [style=dashed label="{Error code\n[1 byte]}"];
         *  sent1 -> {received1 error}[ sametail="b"];
         *
         *  sent1e [label="{0x5F\n[1 byte]|FID\n[1 byte]|new settings\n[8 byte enchipered]}"];
         *  received1e [label="{0x00\n[1 byte]}"];
         *  errore [style=dashed label="{Error code\n[1 byte]}"];
         *  sent1e -> {received1e errore}[ sametail="b"];
         * }
         * @enddot
         *
         * @brief Modify the file settings.
         * This requires a previous @ref authenticate command on @ref active_app, and the key must match the key number specified
         * in @ref any_file_settings::common_settings @ref file_access_rights::change. If instead @ref file_access_rights::change
         * is set to @ref free_access, no authentication is required, just @ref select_application.
         * @ingroup data
         * @param fid The file id, in the range 0..15 (included).
         * @param settings The new file settings.
         * @return Either `mlab::result_success` or any of @ref error, in particular @ref error::permission_denied or
         *  @ref error::file_not_found.
         *
         * @warning Consider using the overload of this method which requires explicitly a @ref comm_mode operation mode parameter.
         *  This method will auto-detect the security settings used: if a card is cloned and a file is created with the same id
         *  but different security, this method will accept the different security transmission mode. It may thus leak data.
         */
        result<> change_file_settings(file_id fid, common_file_settings const &settings, trust_card_t);

        /**
         * @dot
         * digraph AlignmentMap {
         *  node [shape=record fontname="sans-serif"];
         *  rankdir=LR;
         *  sent1 [label="{0x5F\n[1 byte]|FID\n[1 byte]|Comm. settings\n[1 byte]|Access rights\n[2 byte LDB first]}"];
         *  received1 [label="{0x00\n[1 byte]}"];
         *  error [style=dashed label="{Error code\n[1 byte]}"];
         *  sent1 -> {received1 error}[ sametail="b"];
         *
         *  sent1e [label="{0x5F\n[1 byte]|FID\n[1 byte]|new settings\n[8 byte enchipered]}"];
         *  received1e [label="{0x00\n[1 byte]}"];
         *  errore [style=dashed label="{Error code\n[1 byte]}"];
         *  sent1e -> {received1e errore}[ sametail="b"];
         * }
         * @enddot
         *
         * @brief Modify the file settings.
         * This requires a previous @ref authenticate command on @ref active_app, and the key must match the key number specified
         * in @ref any_file_settings::common_settings @ref file_access_rights::change. If instead @ref file_access_rights::change
         * is set to @ref free_access, no authentication is required, just @ref select_application.
         * @ingroup data
         * @param fid The file id, in the range 0..15 (included).
         * @param settings The new file settings.
         * @param operation_mode The communication mode to use for this operation. This is derived from the base file security and
         *  the value of @ref file_access_rights::change member: a free access implies no security is specified, otherwise it falls back
         *  to the file's own security mode.
         * @see determine_operation_mode
         * @return Either `mlab::result_success` or any of @ref error, in particular @ref error::permission_denied or
         *  @ref error::file_not_found. If @p operation_mode is incorrect, @ref error::crypto_error is returned.
         */
        result<> change_file_settings(file_id fid, common_file_settings const &settings, comm_mode operation_mode);

        /**
         * @dot
         * digraph AlignmentMap {
         *  node [shape=record fontname="sans-serif"];
         *  rankdir=LR;
         *  sent1 [label="{0xCD\n[1 byte]|FID\n[1 byte]|Comm. settings\n[1 byte]|Access rights\n[2 byte LSB first]|File size\n[3 byte LSB first]}"];
         *  received1 [label="{0x00\n[1 byte]}"];
         *  error [style=dashed label="{Error code\n[1 byte]}"];
         *  sent1 -> {received1 error}[ sametail="b"];
         * }
         * @enddot
         *
         * @brief Create a new standard data file in @ref active_app.
         * This requires a valid @ref authenticate command with the master key (key number zero), unless
         * @ref key_rights::create_delete_without_master_key is set to true.
         * @ingroup standardFile
         * @param fid The file id, in the range 0..15 (included).
         * @param settings The new file settings.
         * @return Either `mlab::result_success` or any of @ref error, in particular @ref error::permission_denied or
         *  @ref error::duplicate_error if the file exists already.
         */
        result<> create_file(file_id fid, file_settings<file_type::standard> const &settings);

        /**
         * @brief Create a new file in @ref active_app.
         * This requires a valid @ref authenticate command with the master key (key number zero), unless
         * @ref key_rights::create_delete_without_master_key is set to true.
         * @ingroup data
         * @param fid The file id, in the range 0..15 (included). For any file other than @ref file_type::standard, this can be at most 7.
         * @param settings The new file settings.
         * @return Either `mlab::result_success` or any of @ref error, in particular @ref error::permission_denied or
         *  @ref error::duplicate_error if the file exists already.
         */
        result<> create_file(file_id fid, any_file_settings const &settings);


        /**
         * @dot
         * digraph AlignmentMap {
         *  node [shape=record fontname="sans-serif"];
         *  rankdir=LR;
         *  sent1 [label="{0xCB\n[1 byte]|FID\n[1 byte]|Comm. settings\n[1 byte]|Access rights\n[2 byte LSB first]|File size\n[3 byte LSB first]}"];
         *  received1 [label="{0x00\n[1 byte]}"];
         *  error [style=dashed label="{Error code\n[1 byte]}"];
         *  sent1 -> {received1 error}[ sametail="b"];
         * }
         * @enddot
         *
         * @brief Create a new backup data file in @ref active_app.
         * This requires a valid @ref authenticate command with the master key (key number zero), unless
         * @ref key_rights::create_delete_without_master_key is set to true.
         * @ingroup backupFile
         * @param fid The file id, in the range 0..7 (included).
         * @param settings The new file settings.
         * @return Either `mlab::result_success` or any of @ref error, in particular @ref error::permission_denied or
         *  @ref error::duplicate_error if the file exists already.
         */
        result<> create_file(file_id fid, file_settings<file_type::backup> const &settings);

        /**
         * @dot
         * digraph AlignmentMap {
         *  node [shape=record fontname="sans-serif"];
         *  rankdir=LR;
         *  sent1 [label="{0xCC\n[1 byte]|FID\n[1 byte]|Comm. settings\n[1 byte]|Access rights\n[2 byte LSB first]|Lower Limit\n[4 byte LSB first]|Upper Limit\n[4 byte LSB first]|Value\n[4 byte LSB first]|Lim. credit\n[1 byte]}"];
         *  received1 [label="{0x00\n[1 byte]}"];
         *  error [style=dashed label="{Error code\n[1 byte]}"];
         *  sent1 -> {received1 error}[ sametail="b"];
         * }
         * @enddot
         *
         * @brief Create a new value file in @ref active_app.
         * This requires a valid @ref authenticate command with the master key (key number zero), unless
         * @ref key_rights::create_delete_without_master_key is set to true.
         * @ingroup data
         * @param fid The file id, in the range 0..7 (included).
         * @param settings Must have @ref value_file_settings::upper_limit greater than or equal to
         *  @ref value_file_settings::lower_limit.
         * @return Either `mlab::result_success` or any of @ref error, in particular @ref error::permission_denied or
         *  @ref error::duplicate_error if the file exists already.
         */
        result<> create_file(file_id fid, file_settings<file_type::value> const &settings);

        /**
         * @dot
         * digraph AlignmentMap {
         *  node [shape=record fontname="sans-serif"];
         *  rankdir=LR;
         *  sent1 [label="{0xC1\n[1 byte]|FID\n[1 byte]|Comm. settings\n[1 byte]|Access rights\n[2 byte LSB first]|Record Size\n[3 byte LSB first]|Max # of records\n[3 byte LSB first]}"];
         *  received1 [label="{0x00\n[1 byte]}"];
         *  error [style=dashed label="{Error code\n[1 byte]}"];
         *  sent1 -> {received1 error}[ sametail="b"];
         * }
         * @enddot
         *
         * @brief Create a new linear record file in @ref active_app.
         * This requires a valid @ref authenticate command with the master key (key number zero), unless
         * @ref key_rights::create_delete_without_master_key is set to true.
         * @ingroup recordFile
         * @param fid The file id, in the range 0..7 (included).
         * @param settings Must have @ref record_file_settings::record_size > 0 and
         *  @ref record_file_settings::max_record_count > 0.
         * @return Either `mlab::result_success` or any of @ref error, in particular @ref error::permission_denied or
         *  @ref error::duplicate_error if the file exists already.
         */
        result<> create_file(file_id fid, file_settings<file_type::linear_record> const &settings);

        /**
         * @dot
         * digraph AlignmentMap {
         *  node [shape=record fontname="sans-serif"];
         *  rankdir=LR;
         *  sent1 [label="{0xC0\n[1 byte]|FID\n[1 byte]|Comm. settings\n[1 byte]|Access rights\n[2 byte LSB first]|Record Size\n[3 byte LSB first]|Max # of records\n[3 byte LSB first]}"];
         *  received1 [label="{0x00\n[1 byte]}"];
         *  error [style=dashed label="{Error code\n[1 byte]}"];
         *  sent1 -> {received1 error}[ sametail="b"];
         * }
         * @enddot
         *
         * @brief Create a new cyclic record file in @ref active_app.
         * This requires a valid @ref authenticate command with the master key (key number zero), unless
         * @ref key_rights::create_delete_without_master_key is set to true.
         * @ingroup recordFile
         * @param fid The file id, in the range 0..7 (included).
         * @param settings Must have @ref record_file_settings::record_size > 0 and
         *  @ref record_file_settings::max_record_count > 1 (at least 2).
         * @return Either `mlab::result_success` or any of @ref error, in particular @ref error::permission_denied or
         *  @ref error::duplicate_error if the file exists already.
         */
        result<> create_file(file_id fid, file_settings<file_type::cyclic_record> const &settings);

        /**
         *
         * @dot
         * digraph AlignmentMap {
         *  node [shape=record fontname="sans-serif"];
         *  rankdir=LR;
         *  sent1 [label="{0xDF\n[1 byte]|FID\n[1 byte]}"];
         *  received1 [label="{0x00\n[1 byte]}"];
         *  error [style=dashed label="{Error code\n[1 byte]}"];
         *  sent1 -> {received1 error}[ sametail="b"];
         * }
         * @enddot
         *
         * @brief Deletes a file from @ref active_app.
         * This requires a valid @ref authenticate command with the master key (key number zero), unless
         * @ref key_rights::create_delete_without_master_key is set to true.
         * @ingroup data
         * @param fid The file id, in the range 0..15 (included).
         * @return Either `mlab::result_success` or any of @ref error, in particular @ref error::permission_denied
         *  or @ref error::file_not_found if the file does not exist.
         */
        result<> delete_file(file_id fid);

        /**
         * @dot
         * digraph AlignmentMap {
         *  node [shape=record fontname="sans-serif"];
         *  rankdir=LR;
         *  sent1 [label="{0xEB\n[1 byte]|FID\n[1 byte]}"];
         *  received1 [label="{0x00\n[1 byte]}"];
         *  error [style=dashed label="{Error code\n[1 byte]}"];
         *  sent1 -> {received1 error}[ sametail="b"];
         * }
         * @enddot
         *
         * @brief Clear the records from a linear or cyclic record file.
         * This requires a valid @ref authenticate command with a key that satisfies @ref file_access_rights::read_write
         * (possibly none if set to @ref free_access).
         * @ingroup recordFile
         * @param fid The file id of the record file, in the range 0..7 (included).
         * @return Either `mlab::result_success` or any of @ref error, in particular @ref error::permission_denied
         *  or @ref error::file_not_found if the file does not exist.
         */
        result<> clear_record_file(file_id fid);

        /**
         * @dot
         * digraph AlignmentMap {
         *  node [shape=record fontname="sans-serif"];
         *  rankdir=LR;
         *  sent1 [label="{0xC7\n[1 byte]}"];
         *  received1 [label="{0x00\n[1 byte]}"];
         *  error [style=dashed label="{Error code\n[1 byte]}"];
         *  sent1 -> {received1 error}[ sametail="b"];
         * }
         * @enddot
         *
         * @brief Commits all data to a value, record or backup file.
         * The changes to any file type other than @ref file_type::standard require a call to this method to be saved.
         * @see abort_transaction
         * @ingroup committableFiles
         * @return Either `mlab::result_success` or any of @ref error, in particular @ref error::permission_denied.
         */
        result<> commit_transaction();

        /**
         *
         * @dot
         * digraph AlignmentMap {
         *  node [shape=record fontname="sans-serif"];
         *  rankdir=LR;
         *  sent1 [label="{0xA7\n[1 byte]}"];
         *  received1 [label="{0x00\n[1 byte]}"];
         *  error [style=dashed label="{Error code\n[1 byte]}"];
         *  sent1 -> {received1 error}[ sametail="b"];
         * }
         * @enddot
         *
         * @brief Aborts any change to a value, record or backup file.
         * Any change that has not been committed will be discarded.
         * @see commit_transaction.
         * @ingroup committableFiles
         * @return Either `mlab::result_success` or any of @ref error.
         */
        result<> abort_transaction();

        /**
         * @dot
         * digraph AlignmentMap {
         *  node [shape=record fontname="sans-serif"];
         *  rankdir=LR;
         *  sent1 [label="{0xBD\n[1 byte]|FID\n[1 byte]|Offset\n[3 byte LSB first]|Lenght\n[3 byte LSB first]}"];
         *  received1 [label="{0xAF\n[1 byte]|DATA\n[1-59 bytes]}"];
         *  received2 [label="{0x00\n[1 byte]|DATA\n[1-59 bytes]}"];
         *  received3 [label="{0x00\n[1 byte]|DATA\n[1-59 bytes]}"];
         *  sent2 [label="{0xAF\n[1 byte]}"];
         *  error [style=dashed label="{Error code\n[1 byte]}"];
         *  sent1 -> {received1 received2 error}[ sametail="b"];
         *  received1 -> sent2 -> received3;
         * }
         * @enddot
         *
         * @brief Read data from a standard or backup file.
         * This method requires a previous @ref authenticate command with a key that is compatible with the
         * @ref file_access_rights::read (or @ref file_access_rights::read_write) in order to complete successfully.
         * If the file is a @ref file_type::backup, this will read the content of the file after the last
         * @ref commit_transaction call, i.e. uncommitted changes are not reflected here.
         * @ingroup standardAndBackupFile
         * @param fid The file id, in the range 0..15 (included). For @ref file_type::backup, this can be at most 7.
         * @param offset Limited to 24 bits, i.e. must be below 0xFFFFFF. Must also be less than the file size.
         * @param length Limited to 24 bits, i.e. must be below 0xFFFFFF. Specify @ref all_data (zero) to read until the end.
         * @return The data (or part thereof) in the file, or any of @ref error. In particular, @ref error::permission_denied, or
         *  @ref error::file_not_found if the file does not exist.
         *  If @p offset or @p length are not valid, @ref error::parameter_error and @ref error::length_error are also possible.
         *
         * @warning Consider using the overload of this method which requires explicitly a @ref comm_mode operation mode parameter.
         *  This method will auto-detect the security settings used: if a card is cloned and a file is created with the same id
         *  but different security, this method will accept the different security transmission mode. It may thus leak data.
         */
        [[nodiscard]] result<bin_data> read_data(file_id fid, trust_card_t, std::uint32_t offset = 0, std::uint32_t length = all_data);

        /**
         * @dot
         * digraph AlignmentMap {
         *  node [shape=record fontname="sans-serif"];
         *  rankdir=LR;
         *  sent1 [label="{0xBD\n[1 byte]|FID\n[1 byte]|Offset\n[3 byte LSB first]|Lenght\n[3 byte LSB first]}"];
         *  received1 [label="{0xAF\n[1 byte]|DATA\n[1-59 bytes]}"];
         *  received2 [label="{0x00\n[1 byte]|DATA\n[1-59 bytes]}"];
         *  received3 [label="{0x00\n[1 byte]|DATA\n[1-59 bytes]}"];
         *  sent2 [label="{0xAF\n[1 byte]}"];
         *  error [style=dashed label="{Error code\n[1 byte]}"];
         *  sent1 -> {received1 received2 error}[ sametail="b"];
         *  received1 -> sent2 -> received3;
         * }
         * @enddot
         *
         * @brief Read data from a standard or backup file.
         * This method requires a previous @ref authenticate command with a key that is compatible with the
         * @ref file_access_rights::read (or @ref file_access_rights::read_write) in order to complete successfully.
         * If the file is a @ref file_type::backup, this will read the content of the file after the last
         * @ref commit_transaction call, i.e. uncommitted changes are not reflected here.
         * @ingroup standardAndBackupFile
         * @param fid The file id, in the range 0..15 (included). For @ref file_type::backup, this can be at most 7.
         * @param operation_mode The communication mode to use for this operation. This is derived from the base file security and
         *  the value of @ref file_access_rights::read and @ref file_access_rights::read_write members: a free access implies no security
         *  is specified, otherwise it falls back to the file's own security mode.
         * @param offset Limited to 24 bits, i.e. must be below 0xFFFFFF. Must also be less than the file size.
         * @param length Limited to 24 bits, i.e. must be below 0xFFFFFF. Specify @ref all_data (zero) to read until the end.
         * @see determine_operation_mode
         * @return The data (or part thereof) in the file, or any of @ref error. In particular, @ref error::permission_denied, or
         *  @ref error::file_not_found if the file does not exist. If @p operation_mode is incorrect, @ref error::crypto_error is returned.
         *  If @p offset or @p length are not valid, @ref error::parameter_error and @ref error::length_error are also possible.
         */
        [[nodiscard]] result<bin_data> read_data(file_id fid, comm_mode operation_mode, std::uint32_t offset = 0, std::uint32_t length = all_data);

        /**
         * @brief Writes data to a standard or backup file.
         * This method requires a previous @ref authenticate command with a key that is compatible with the
         * @ref file_access_rights::write (or @ref file_access_rights::read_write) in order to complete successfully.
         * If the file is a @ref file_type::backup, a subsequent call to @ref commit_transaction is required.
         * @ingroup standardAndBackupFile
         * @param fid The file id, in the range 0..15 (included). For @ref file_type::backup, this can be at most 7.
         * @param data Limited to 24 bits, i.e. must be shorter than 0xFFFFFF.
         * @param offset Limited to 24 bits, i.e. must be below 0xFFFFFF.
         *
         * @return Either `mlab::result_success` or any of @ref error. In particular, @ref error::permission_denied, or
         *  @ref error::file_not_found if the file does not exist.
         *  If @p offset is not valid or @p data's length is invalid, @ref error::parameter_error and @ref error::length_error are also possible.
         *
         * @warning Consider using the overload of this method which requires explicitly a @ref comm_mode operation mode parameter.
         *  This method will auto-detect the security settings used: if a card is cloned and a file is created with the same id
         *  but different security, this method will accept the different security transmission mode. It may thus leak data.
         */
        result<> write_data(file_id fid, bin_data const &data, trust_card_t, std::uint32_t offset = 0);

        /**
         * @brief Writes data to a standard or backup file.
         * This method requires a previous @ref authenticate command with a key that is compatible with the
         * @ref file_access_rights::write (or @ref file_access_rights::read_write) in order to complete successfully.
         * If the file is a @ref file_type::backup, a subsequent call to @ref commit_transaction is required.
         * @ingroup standardAndBackupFile
         * @param fid The file id, in the range 0..15 (included). For @ref file_type::backup, this can be at most 7.
         * @param data Limited to 24 bits, i.e. must be shorten than 0xFFFFFF.
         * @param operation_mode The communication mode to use for this operation. This is derived from the base file security and
         *  the value of @ref file_access_rights::write and @ref file_access_rights::read_write members: a free access implies no security
         *  is specified, otherwise it falls back to the file's own security mode.
         * @param offset Limited to 24 bits, i.e. must be below 0xFFFFFF.
         * @see determine_operation_mode
         * @return Either `mlab::result_success` or any of @ref error. In particular, @ref error::permission_denied, or
         *  @ref error::file_not_found if the file does not exist. If @p operation_mode is incorrect, @ref error::crypto_error is returned.
         *  If @p offset is not valid or @p data's length is invalid, @ref error::parameter_error and @ref error::length_error are also possible.
         */
        result<> write_data(file_id fid, bin_data const &data, comm_mode operation_mode, std::uint32_t offset = 0);

        /**
         * @dot
         * digraph AlignmentMap {
         *  node [shape=record fontname="sans-serif"];
         *  rankdir=LR;
         *  sent1 [label="{0x6C\n[1 byte]|FID\n[1 byte]}"];
         *  received1 [label="{0x00\n[1 byte]|Value\n[4 byte]}"];
         *  error [style=dashed label="{Error code\n[1 byte]}"];
         *  sent1 -> {received1 error}[ sametail="b"];
         * }
         * @enddot
         *
         * @brief Gets the content of a value file.
         * This method requires a previous @ref authenticate command with a key that is compatible with the
         * @ref file_access_rights::read, or @ref file_access_rights::write, or @ref file_access_rights::read_write in order to complete successfully.
         * Any change that has not been committed via @ref commit_transaction is **not** reflected in the returned value.
         * @ingroup valueFile
         * @param fid The file id, in the range 0..7 (included).
         * @return The value of the file or any of @ref error. In particular, @ref error::permission_denied, or
         *  @ref error::file_not_found if the file does not exist.
         *
         * @warning Consider using the overload of this method which requires explicitly a @ref comm_mode operation mode parameter.
         *  This method will auto-detect the security settings used: if a card is cloned and a file is created with the same id
         *  but different security, this method will accept the different security transmission mode. It may thus leak data.
         */
        [[nodiscard]] result<std::int32_t> get_value(file_id fid, trust_card_t);

        /**
         * @dot
         * digraph AlignmentMap {
         *  node [shape=record fontname="sans-serif"];
         *  rankdir=LR;
         *  sent1 [label="{0x6C\n[1 byte]|FID\n[1 byte]}"];
         *  received1 [label="{0x00\n[1 byte]|Value\n[4 byte]}"];
         *  error [style=dashed label="{Error code\n[1 byte]}"];
         *  sent1 -> {received1 error}[ sametail="b"];
         * }
         * @enddot
         *
         * @brief Gets the content of a value file.
         * This method requires a previous @ref authenticate command with a key that is compatible with the
         * @ref file_access_rights::read, or @ref file_access_rights::write, or @ref file_access_rights::read_write in order to complete successfully.
         * Any change that has not been committed via @ref commit_transaction is **not** reflected in the returned value.
         * @ingroup valueFile
         * @param fid The file id, in the range 0..7 (included).
         * @param operation_mode The communication mode to use for this operation. This is derived from the base file security and
         *  the value of @ref file_access_rights::read and @ref file_access_rights::read_write members: a free access implies no security
         *  is specified, otherwise it falls back to the file's own security mode.
         * @see determine_operation_mode
         * @return The value of the file or any of @ref error. In particular, @ref error::permission_denied, or
         *  @ref error::file_not_found if the file does not exist. If @p operation_mode is incorrect, @ref error::crypto_error is returned.
         */
        [[nodiscard]] result<std::int32_t> get_value(file_id fid, comm_mode operation_mode);

        /**
         * @dot
         * digraph AlignmentMap {
         *  node [shape=record fontname="sans-serif"];
         *  rankdir=LR;
         *  sent1 [label="{0x0C\n[1 byte]|FID\n[1 byte]| Credit anmount\n[4 byte]}"];
         *  received1 [label="{0x00\n[1 byte]}"];
         *  error [style=dashed label="{Error code\n[1 byte]}"];
         *  sent1 -> {received1 error}[ sametail="b"];
         * }
         * @enddot
         *
         * @brief Increments a value file.
         * This method requires a previous @ref authenticate command with a key that is compatible with the
         * @ref file_access_rights::read_write in order to complete successfully.
         * A call to @ref commit_transaction is necessary to permanently update the value.
         * @ingroup valueFile
         * @param fid The file id, in the range 0..7 (included).
         * @param amount Must be non-negative.
         * @return Either `mlab::result_success` or any of @ref error. In particular, @ref error::permission_denied, or
         *  @ref error::file_not_found if the file does not exist.
         *  If @p amount is invalid, @ref error::parameter_error is also possible.
         *
         * @warning Consider using the overload of this method which requires explicitly a @ref comm_mode operation mode parameter.
         *  This method will auto-detect the security settings used: if a card is cloned and a file is created with the same id
         *  but different security, this method will accept the different security transmission mode. It may thus leak data.
         */
        result<> credit(file_id fid, std::int32_t amount, trust_card_t);

        /**
         * @dot
         * digraph AlignmentMap {
         *  node [shape=record fontname="sans-serif"];
         *  rankdir=LR;
         *  sent1 [label="{0x0C\n[1 byte]|FID\n[1 byte]| Credit anmount\n[4 byte]}"];
         *  received1 [label="{0x00\n[1 byte]}"];
         *  error [style=dashed label="{Error code\n[1 byte]}"];
         *  sent1 -> {received1 error}[ sametail="b"];
         * }
         * @enddot
         *
         * @brief Increments a value file.
         * This method requires a previous @ref authenticate command with a key that is compatible with the
         * @ref file_access_rights::read_write in order to complete successfully.
         * A call to @ref commit_transaction is necessary to permanently update the value.
         * @ingroup valueFile
         * @param fid The file id, in the range 0..7 (included).
         * @param amount Must be non-negative.
         * @param operation_mode The communication mode to use for this operation. This is derived from the base file security and
         *  the value of @ref file_access_rights::write and @ref file_access_rights::read_write members: a free access implies no security
         *  is specified, otherwise it falls back to the file's own security mode.
         * @see determine_operation_mode
         * @return Either `mlab::result_success` or any of @ref error. In particular, @ref error::permission_denied, or
         *  @ref error::file_not_found if the file does not exist. If @p operation_mode is incorrect, @ref error::crypto_error is returned.
         *  If @p amount is invalid, @ref error::parameter_error is also possible.
         */
        result<> credit(file_id fid, std::int32_t amount, comm_mode operation_mode);

        /**
         * @dot
         * digraph AlignmentMap {
         *  node [shape=record fontname="sans-serif"];
         *  rankdir=LR;
         *  sent1 [label="{0xDC\n[1 byte]|FID\n[1 byte]| Credit anmount\n[4 byte]}"];
         *  received1 [label="{0x00\n[1 byte]}"];
         *  error [style=dashed label="{Error code\n[1 byte]}"];
         *  sent1 -> {received1 error}[ sametail="b"];
         * }
         * @enddot
         *
         * @brief Increments the value file, to the maximum amount of the past @ref debit transactions.
         * This method requires a previous @ref authenticate command with a key that is compatible with the
         * @ref file_access_rights::write (or @ref file_access_rights::read_write) in order to complete successfully.
         * Moreover, the setting @ref value_file_settings::limited_credit_enabled must be set to true.
         * A call to @ref commit_transaction is necessary to permanently update the value.
         * @ingroup valueFile
         * @param fid The file id, in the range 0..7 (included).
         * @param amount Must be non-negative.
         * @note This can be used without full write/read permission. It can be use to refound a transaction in a safe way.
         * @return Either `mlab::result_success` or any of @ref error. In particular, @ref error::permission_denied, or
         *  @ref error::file_not_found if the file does not exist.
         *  If @p amount is invalid, @ref error::parameter_error is also possible.
         *
         * @warning Consider using the overload of this method which requires explicitly a @ref comm_mode operation mode parameter.
         *  This method will auto-detect the security settings used: if a card is cloned and a file is created with the same id
         *  but different security, this method will accept the different security transmission mode. It may thus leak data.
         */
        result<> limited_credit(file_id fid, std::int32_t amount, trust_card_t);

        /**
         * @dot
         * digraph AlignmentMap {
         *  node [shape=record fontname="sans-serif"];
         *  rankdir=LR;
         *  sent1 [label="{0xDC\n[1 byte]|FID\n[1 byte]| Credit anmount\n[4 byte]}"];
         *  received1 [label="{0x00\n[1 byte]}"];
         *  error [style=dashed label="{Error code\n[1 byte]}"];
         *  sent1 -> {received1 error}[ sametail="b"];
         * }
         * @enddot
         *
         * @brief Increments the value file, to the maximum amount of the past @ref debit transactions.
         * This method requires a previous @ref authenticate command with a key that is compatible with the
         * @ref file_access_rights::write (or @ref file_access_rights::read_write) in order to complete successfully.
         * Moreover, the setting @ref value_file_settings::limited_credit_enabled must be set to true.
         * A call to @ref commit_transaction is necessary to permanently update the value.
         * @ingroup valueFile
         * @param fid The file id, in the range 0..7 (included).
         * @param amount Must be non-negative.
         * @param operation_mode The communication mode to use for this operation. This is derived from the base file security and
         *  the value of @ref file_access_rights::write and @ref file_access_rights::read_write members: a free access implies no security
         *  is specified, otherwise it falls back to the file's own security mode.
         * @see determine_operation_mode
         * @note This can be used without full write/read permission. It can be use to refound a transaction in a safe way.
         * @return Either `mlab::result_success` or any of @ref error. In particular, @ref error::permission_denied, or
         *  @ref error::file_not_found if the file does not exist. If @p operation_mode is incorrect, @ref error::crypto_error is returned.
         *  If @p amount is invalid, @ref error::parameter_error is also possible.
         */
        result<> limited_credit(file_id fid, std::int32_t amount, comm_mode operation_mode);

        /**
         * @dot
         * digraph AlignmentMap {
         *  node [shape=record fontname="sans-serif"];
         *  rankdir=LR;
         *  sent1 [label="{0xDC\n[1 byte]|FID\n[1 byte]| Debit anmount\n[4 byte]}"];
         *  received1 [label="{0x00\n[1 byte]}"];
         *  error [style=dashed label="{Error code\n[1 byte]}"];
         *  sent1 -> {received1 error}[ sametail="b"];
         * }
         * @enddot
         *
         * @brief Decrements a value file.
         * This method requires a previous @ref authenticate command with a key that is compatible with the
         * @ref file_access_rights::read, or @ref file_access_rights::write, or @ref file_access_rights::read_write in order to complete successfully.
         * A call to @ref commit_transaction is necessary to permanently update the value.
         * @ingroup valueFile
         * @param fid The file id, in the range 0..7 (included).
         * @param amount Must be non-negative.
         * @return Either `mlab::result_success` or any of @ref error. In particular, @ref error::permission_denied, or
         *  @ref error::file_not_found if the file does not exist.
         *  If @p amount is invalid, @ref error::parameter_error is also possible.
         *
         * @warning Consider using the overload of this method which requires explicitly a @ref comm_mode operation mode parameter.
         *  This method will auto-detect the security settings used: if a card is cloned and a file is created with the same id
         *  but different security, this method will accept the different security transmission mode. It may thus leak data.
         */
        result<> debit(file_id fid, std::int32_t amount, trust_card_t);

        /**
         * @dot
         * digraph AlignmentMap {
         *  node [shape=record fontname="sans-serif"];
         *  rankdir=LR;
         *  sent1 [label="{0xDC\n[1 byte]|FID\n[1 byte]| Debit anmount\n[4 byte]}"];
         *  received1 [label="{0x00\n[1 byte]}"];
         *  error [style=dashed label="{Error code\n[1 byte]}"];
         *  sent1 -> {received1 error}[ sametail="b"];
         * }
         * @enddot
         *
         * @brief Decrements a value file.
         * This method requires a previous @ref authenticate command with a key that is compatible with the
         * @ref file_access_rights::read, or @ref file_access_rights::write, or @ref file_access_rights::read_write in order to complete successfully.
         * A call to @ref commit_transaction is necessary to permanently update the value.
         * @ingroup valueFile
         * @param fid The file id, in the range 0..7 (included).
         * @param amount Must be non-negative.
         * @param operation_mode The communication mode to use for this operation. This is derived from the base file security and
         *  the value of @ref file_access_rights::write and @ref file_access_rights::read_write members: a free access implies no security
         *  is specified, otherwise it falls back to the file's own security mode.
         * @see determine_operation_mode
         * @return Either `mlab::result_success` or any of @ref error. In particular, @ref error::permission_denied, or
         *  @ref error::file_not_found if the file does not exist. If @p operation_mode is incorrect, @ref error::crypto_error is returned.
         *  If @p amount is invalid, @ref error::parameter_error is also possible.
         */
        result<> debit(file_id fid, std::int32_t amount, comm_mode operation_mode);

        /**
         * @brief Appends a record to a linear or cyclic file.
         * This method requires a previous @ref authenticate command with a key that is compatible with the
         * @ref file_access_rights::write (or @ref file_access_rights::read_write) in order to complete successfully.
         * A call to @ref commit_transaction is necessary to permanently update the value.
         * @ingroup recordFile
         * @param fid The file id, in the range 0..7 (included).
         * @param data Limited to 24 bits, must match in length @ref record_file_settings::record_size.
         * @param offset Limited to 24 bits, i.e. must be below 0xFFFFFF. Must also be less than the record size.
         *  This is the offset within the record at which to write.
         * @return Either `mlab::result_success` or any of @ref error. In particular, @ref error::permission_denied, or
         *  @ref error::file_not_found if the file does not exist.
         *  If @p offset is invalid or @p data's length incorrect, @ref error::parameter_error and @ref error::length_error are also possible.
         *
         * @warning Consider using the overload of this method which requires explicitly a @ref comm_mode operation mode parameter.
         *  This method will auto-detect the security settings used: if a card is cloned and a file is created with the same id
         *  but different security, this method will accept the different security transmission mode. It may thus leak data.
         */
        result<> write_record(file_id fid, bin_data const &data, trust_card_t, std::uint32_t offset = 0);

        /**
         * @brief Appends a record to a linear or cyclic file.
         * This method requires a previous @ref authenticate command with a key that is compatible with the
         * @ref file_access_rights::write (or @ref file_access_rights::read_write) in order to complete successfully.
         * A call to @ref commit_transaction is necessary to permanently update the value.
         * @ingroup recordFile
         * @param fid The file id, in the range 0..7 (included).
         * @param data Limited to 24 bits, must match in length @ref record_file_settings::record_size.
         * @param operation_mode The communication mode to use for this operation. This is derived from the base file security and
         *  the value of @ref file_access_rights::write and @ref file_access_rights::read_write members: a free access implies no security
         *  is specified, otherwise it falls back to the file's own security mode.
         * @param offset Limited to 24 bits, i.e. must be below 0xFFFFFF. Must also be less than the record size.
         *  This is the offset within the record at which to write.
         * @see determine_operation_mode
         * @return Either `mlab::result_success` or any of @ref error. In particular, @ref error::permission_denied, or
         *  @ref error::file_not_found if the file does not exist. If @p operation_mode is incorrect, @ref error::crypto_error is returned.
         *  If @p offset is invalid or @p data's length incorrect, @ref error::parameter_error and @ref error::length_error are also possible.
         */
        result<> write_record(file_id fid, bin_data const &data, comm_mode operation_mode, std::uint32_t offset = 0);

        /**
         * @brief Appends a record of a given type `T` to a cyclic or linear record file.
         * This method requires a previous @ref authenticate command with a key that is compatible with the
         * @ref file_access_rights::write (or @ref file_access_rights::read_write) in order to complete successfully.
         * A call to @ref commit_transaction is necessary to permanently update the value.
         * @ingroup recordFile
         * @tparam T A record type which can be injected into `mlab::bin_data`.
         * @param fid The file id, in the range 0..7 (included).
         * @param record Record to write. Must be injectable to `mlab::bin_data` with as many bytes as @ref record_file_settings::record_size.
         * @return Either `mlab::result_success` or any of @ref error. In particular, @ref error::permission_denied, or
         *  @ref error::file_not_found if the file does not exist.
         *  If the encoded length of @p record is incorrect, @ref error::parameter_error and @ref error::length_error are also possible.
         *
         * @warning Consider using the overload of this method which requires explicitly a @ref comm_mode operation mode parameter.
         *  This method will auto-detect the security settings used: if a card is cloned and a file is created with the same id
         *  but different security, this method will accept the different security transmission mode. It may thus leak data.
         */
        template <class T>
        result<> write_record(file_id fid, T &&record, trust_card_t);

        /**
         * @brief Appends a record of a given type `T` to a cyclic or linear record file.
         * This method requires a previous @ref authenticate command with a key that is compatible with the
         * @ref file_access_rights::write (or @ref file_access_rights::read_write) in order to complete successfully.
         * A call to @ref commit_transaction is necessary to permanently update the value.
         * @ingroup recordFile
         * @tparam T A record type which can be injected into `mlab::bin_data`.
         * @param fid The file id, in the range 0..7 (included).
         * @param record Record to write. Must be injectable to `mlab::bin_data` with as many bytes as @ref record_file_settings::record_size.
         * @param operation_mode The communication mode to use for this operation. This is derived from the base file security and
         *  the value of @ref file_access_rights::write and @ref file_access_rights::read_write members: a free access implies no security
         *  is specified, otherwise it falls back to the file's own security mode.
         * @see determine_operation_mode
         * @return Either `mlab::result_success` or any of @ref error. In particular, @ref error::permission_denied, or
         *  @ref error::file_not_found if the file does not exist. If @p operation_mode is incorrect, @ref error::crypto_error is returned.
         *  If the encoded length of @p record is incorrect, @ref error::parameter_error and @ref error::length_error are also possible.
         */
        template <class T>
        result<> write_record(file_id fid, T &&record, comm_mode operation_mode);

        /**
         * @brief Read records from a linear or cyclic file, oldest to most recent, and converts the records to `T`.
         * This method requires a previous @ref authenticate command with a key that is compatible with the
         * @ref file_access_rights::read (or @ref file_access_rights::read_write) in order to complete successfully.
         * The changes made by @ref write_record that have not been committed via @ref commit_transaction are not visible through this method.
         * @ingroup recordFile
         * @tparam T A type that can be extracted from a `mlab::bin_stream`. They must be fixed-size when encoded into binary form, because each
         *  record has a fixed size, and they will be extracted one by one, in a flat-array form, from the binary data returned by the PICC.
         * @param fid The file id, in the range 0..7 (included).
         * @param record_index Limited to 24 bits, i.e. must be below 0xFFFFFF. Must be less than the number of existing records.
         * @param record_count Limited to 24 bits, i.e. must be below 0xFFFFFF. Must be less or equal than the number of existing
         *  records. Specify zero to read all records.
         * @return The binary data of the selected records or any of @ref error. In particular, @ref error::permission_denied, or
         *  @ref error::file_not_found if the file does not exist.
         *  If @p record_index is invalid or @p record_count incorrect, @ref error::parameter_error and @ref error::length_error are also possible.
         *
         * @warning Consider using the overload of this method which requires explicitly a @ref comm_mode operation mode parameter.
         *  This method will auto-detect the security settings used: if a card is cloned and a file is created with the same id
         *  but different security, this method will accept the different security transmission mode. It may thus leak data.
         */
        template <class T>
        [[nodiscard]] result<std::vector<T>> read_parse_records(file_id fid, trust_card_t, std::uint32_t record_index = 0, std::uint32_t record_count = all_records);

        /**
         * @brief Read records from a linear or cyclic file, oldest to most recent, and converts the records to `T`.
         * This method requires a previous @ref authenticate command with a key that is compatible with the
         * @ref file_access_rights::read (or @ref file_access_rights::read_write) in order to complete successfully.
         * The changes made by @ref write_record that have not been committed via @ref commit_transaction are not visible through this method.
         * @ingroup recordFile
         * @tparam T A type that can be extracted from a `mlab::bin_stream`. They must be fixed-size when encoded into binary form, because each
         *  record has a fixed size, and they will be extracted one by one, in a flat-array form, from the binary data returned by the PICC.
         * @param fid The file id, in the range 0..7 (included).
         * @param record_index Limited to 24 bits, i.e. must be below 0xFFFFFF. Must be less than the number of existing records.
         * @param record_count Limited to 24 bits, i.e. must be below 0xFFFFFF. Must be less or equal than the number of existing
         *  records. Specify zero to read all records.
         * @param operation_mode The communication mode to use for this operation. This is derived from the base file security and
         *  the value of @ref file_access_rights::read and @ref file_access_rights::read_write members: a free access implies no security
         *  is specified, otherwise it falls back to the file's own security mode.
         * @see determine_operation_mode
         * @return The binary data of the selected records or any of @ref error. In particular, @ref error::permission_denied, or
         *  @ref error::file_not_found if the file does not exist. If @p operation_mode is incorrect, @ref error::crypto_error is returned.
         *  If @p record_index is invalid or @p record_count incorrect, @ref error::parameter_error and @ref error::length_error are also possible.
         */
        template <class T>
        [[nodiscard]] result<std::vector<T>> read_parse_records(file_id fid, comm_mode operation_mode, std::uint32_t record_index = 0, std::uint32_t record_count = all_records);

        /**
         * @brief Read records from a linear or cyclic file, oldest to most recent.
         * This method requires a previous @ref authenticate command with a key that is compatible with the
         * @ref file_access_rights::read (or @ref file_access_rights::read_write) in order to complete successfully.
         * The changes made by @ref write_record that have not been committed via @ref commit_transaction are not visible through this method.
         * @ingroup recordFile
         * @param fid The file id, in the range 0..7 (included).
         * @param record_index Limited to 24 bits, i.e. must be below 0xFFFFFF. Must be less than the number of existing records.
         * @param record_count Limited to 24 bits, i.e. must be below 0xFFFFFF. Must be less or equal than the number of existing
         *  records. Specify zero to read all records.
         * @return The binary data of the selected records or any of @ref error. In particular, @ref error::permission_denied, or
         *  @ref error::file_not_found if the file does not exist.
         *  If @p record_index is invalid or @p record_count incorrect, @ref error::parameter_error and @ref error::length_error are also possible.
         *
         * @warning Consider using the overload of this method which requires explicitly a @ref comm_mode operation mode parameter.
         *  This method will auto-detect the security settings used: if a card is cloned and a file is created with the same id
         *  but different security, this method will accept the different security transmission mode. It may thus leak data.
         */
        [[nodiscard]] result<bin_data> read_records(file_id fid, trust_card_t, std::uint32_t record_index = 0, std::uint32_t record_count = all_records);

        /**
         * @brief Read records from a linear or cyclic file, oldest to most recent.
         * This method requires a previous @ref authenticate command with a key that is compatible with the
         * @ref file_access_rights::read (or @ref file_access_rights::read_write) in order to complete successfully.
         * The changes made by @ref write_record that have not been committed via @ref commit_transaction are not visible through this method.
         * @ingroup recordFile
         * @param fid The file id, in the range 0..7 (included).
         * @param record_index Limited to 24 bits, i.e. must be below 0xFFFFFF. Must be less than the number of existing records.
         * @param record_count Limited to 24 bits, i.e. must be below 0xFFFFFF. Must be less or equal than the number of existing
         *  records. Specify zero to read all records.
         * @param operation_mode The communication mode to use for this operation. This is derived from the base file security and
         *  the value of @ref file_access_rights::read and @ref file_access_rights::read_write members: a free access implies no security
         *  is specified, otherwise it falls back to the file's own security mode.
         * @see determine_operation_mode
         * @return The binary data of the selected records or any of @ref error. In particular, @ref error::permission_denied, or
         *  @ref error::file_not_found if the file does not exist. If @p operation_mode is incorrect, @ref error::crypto_error is returned.
         *  If @p record_index is invalid or @p record_count incorrect, @ref error::parameter_error and @ref error::length_error are also possible.
         */
        [[nodiscard]] result<bin_data> read_records(file_id fid, std::uint32_t record_index, std::uint32_t record_count, comm_mode operation_mode);

        /**
         * @brief Get the card UID.
         * This does not require authentication (and is not transmitted in a secure way); however, in case UID randomization
         * is enabled via @ref set_configuration, this method will return the random UID generated when the PICC was activated,
         * **unless** an authentication with a valid key had been performed.
         * @warning We sacrificed some cards to the random UID features, and for the cards we tested, this method actually
         *  still returned the random UID even though it was authenticated, despite other publicly available libraries claiming
         *  otherwise (MF2DL(H)x0 §11.5.3).
         * @ingroup card
         * @return The card UID or any of @ref error.
         */
        [[nodiscard]] result<pn532::nfcid_2t> get_card_uid();

        /**
         * @brief Read the amount of free flash memory.
         * We conjecture no authentication is required for this.
         * @ingroup card
         * @return The amount of free memory in bytes, or one of @ref error.
         */
        [[nodiscard]] result<std::uint32_t> get_free_mem();

        /**
         * @brief Configure whether the card can be formatted, or whether will show the real UID.
         * @ingroup card
         * @param allow_format Allow clearing all the apps and files in the card.
         * @param enable_random_id Enable if UID should be randomized (the real UID supposedly should be read with @ref get_card_uid).
         * @warning Enabling random id is an **irreversible** operation! And @ref get_card_uid does not seem to work.
         * @return Either `mlab::result_success` or any of @ref error.
         */
        result<> set_configuration(bool allow_format = true, bool enable_random_id = false);

        /**
         * @brief Determines which security level to apply for a certain file operation.
         * This method will test @p file_rights and @p security against the specified @p requested_access.
         * @param requested_access Type of access requested.
         * @param file_rights Access rights to the given file.
         * @param security Security with which the file was created.
         * @return The security mode to apply to an operation that requires the specified @p requested_access mode.
         */
        [[nodiscard]] static comm_mode determine_operation_mode(file_access requested_access, file_access_rights const &file_rights, file_security security);

        /**
         * @brief Determines which security level to apply for a certain file operation.
         * This method will test @ref common_file_settings::rights and @ref common_file_settings::security against the specified @p requested_access.
         * @param requested_access Type of access requested.
         * @param settings File settings.
         * @return The security mode to apply to an operation that requires the specified @p requested_access mode.
         */
        [[nodiscard]] static comm_mode determine_operation_mode(file_access requested_access, common_file_settings const &settings);

        /**
         * @brief Determines which security level to apply for a certain file operation.
         * This method will test @ref common_file_settings::rights and @ref common_file_settings::security against the specified @p requested_access
         * from the @ref any_file_settings::common_settings property.
         * @param requested_access Type of access requested.
         * @param settings File settings.
         * @return The security mode to apply to an operation that requires the specified @p requested_access mode.
         */
        [[nodiscard]] static comm_mode determine_operation_mode(file_access requested_access, any_file_settings const &settings);

        /**
         * @brief Determines which security level to apply for a certain file operation.
         * This method will query the file settings via @ref get_file_settings and test @p file_rights and @p security
         * against the specified @p requested_access.
         * @param requested_access Type of access requested.
         * @param fid The file id, in the range 0..15 (included). For any file other than @ref file_type::standard, this can be at most 7.
         * @return The security mode to apply to an operation that requires the specified @p requested_access mode, or
         *  any of the errors that might be returned by @ref get_file_settings.
         */
        [[nodiscard]] result<comm_mode> determine_operation_mode(file_access requested_access, file_id fid);

    private:
        /**
         * The power of friendship, cit. Wifasoi, 2020
         * @internal
         */
        friend struct ut::desfire_exchanges::session;

        /**
         * Simulate a new session without the @ref authenticate random component
         * @internal
         */
        template <cipher_type Cipher>
        void ut_init_session(desfire::key<Cipher> const &session_key, desfire::app_id app, std::uint8_t key_no);


        template <class T>
        [[nodiscard]] static std::vector<T> parse_records(bin_data const &data, std::uint32_t exp_count);

        [[nodiscard]] static result<> safe_drop_payload(bits::command_code cmd, result<bin_data> const &result);
        static void log_not_empty(bits::command_code cmd, range<bin_data::const_iterator> data);

        [[nodiscard]] inline desfire::pcd &pcd();

        result<> change_key_internal(any_key const *previous_key, any_key const &new_key);

        /**
         * @name Assert communication mode
         * All these methods take a @p validated parameter. This means that the communication mode has been validated,
         * i.e. tested and decided by libSpookyAction. For the overloads that instead take the comm mode from the user,
         * we assume that there could be a user error and the comm mode is incorrect. In the first case, we have a hard error
         * message on a different message tag. In the second, we just issue a regular warning.
         * @{
         */
        result<> change_file_settings_internal(file_id fid, common_file_settings const &settings, comm_mode operation_mode, bool validated);
        result<bin_data> read_data_internal(file_id fid, comm_mode operation_mode, std::uint32_t offset, std::uint32_t length, bool validated);
        result<> write_data_internal(file_id fid, bin_data const &data, comm_mode operation_mode, std::uint32_t offset, bool validated);
        result<std::int32_t> get_value_internal(file_id fid, comm_mode operation_mode, bool validated);
        /**
         * @internal
         * @param cmd Must be one of `command_code::credit`, `command_code::debit`, `command_code::limited_credit`.
         * @param fid The file id, in the range 0..7 (included).
         * @param amount Must be non-negative.
         * @param operation_mode The communication mode to use for this operation. This is derived from the base file security and
         *  the value of @ref file_access_rights::change member: a free access implies no security is specified, otherwise it falls back
         *  to the file's own security mode.
         * @param validated This will be the value for @ref comm_cfg::is_validated.
         */
        result<> write_value_internal(bits::command_code cmd, file_id fid, std::int32_t amount, comm_mode operation_mode, bool validated);
        result<> write_record_internal(file_id fid, bin_data const &data, comm_mode operation_mode, std::uint32_t offset, bool validated);
        result<bin_data> read_records_internal(file_id fid, std::uint32_t record_index, std::uint32_t record_count, comm_mode operation_mode, bool validated);
        /**
         * @}
         */


        /**
         * Clears data __locally__ (i.e. it may be out of sync with the card if not called at the right time).
         */
        void logout();

        [[nodiscard]] comm_cfg const &default_comm_cfg() const;
        [[nodiscard]] bool active_protocol_is_legacy() const;

        std::shared_ptr<desfire::pcd> _pcd;

        std::unique_ptr<cipher_provider> _provider;
        std::unique_ptr<protocol> _active_protocol;
        cipher_type _active_cipher_type;
        std::uint8_t _active_key_number;
        app_id _active_app;
    };
}// namespace desfire

namespace desfire {

    desfire::pcd &tag::pcd() {
        return *_pcd;
    }

    template <class CipherProvider, class PCD>
    tag tag::make(PCD &&pcd) {
        static_assert(std::is_base_of_v<desfire::cipher_provider, CipherProvider>);
        static_assert(std::is_default_constructible_v<CipherProvider>);

        if constexpr (std::is_base_of_v<desfire::pcd, PCD>) {
            static_assert(std::is_move_constructible_v<PCD>);
            return tag{std::make_shared<PCD>(std::forward<PCD>(pcd)), std::make_unique<CipherProvider>()};
        } else {
            static_assert(std::is_convertible_v<PCD, std::shared_ptr<desfire::pcd>>);
            return tag{std::forward<PCD>(pcd), std::make_unique<CipherProvider>()};
        }
    }

    template <class CipherProvider>
    tag tag::make(pn532::controller &ctrl, std::uint8_t logical_index) {
        static_assert(std::is_base_of_v<desfire::cipher_provider, CipherProvider>);
        static_assert(std::is_default_constructible_v<CipherProvider>);
        return tag{ctrl, logical_index, std::make_unique<CipherProvider>()};
    }

    template <cipher_type Type>
    result<> tag::authenticate(key<Type> const &k) {
        return authenticate(any_key{k});
    }
    template <cipher_type Type>
    result<> tag::change_key(key<Type> const &new_key) {
        return change_key(any_key{new_key});
    }

    template <cipher_type Type>
    result<> tag::change_key(key<Type> const &previous_key, key<Type> const &new_key) {
        return change_key(any_key{previous_key}, any_key{new_key});
    }


    app_id const &tag::active_app() const {
        return _active_app;
    }
    cipher_type tag::active_cipher_type() const {
        return _active_cipher_type;
    }
    std::uint8_t tag::active_key_no() const {
        return _active_key_number;
    }

    constexpr comm_cfg::comm_cfg(comm_mode txrx, std::size_t sec_data_ofs, bool validated)
        : tx{txrx},
          rx{txrx},
          tx_secure_data_offset{sec_data_ofs},
          is_validated{validated} {}

    constexpr comm_cfg::comm_cfg(comm_mode tx, comm_mode rx, std::size_t sec_data_ofs, bool validated)
        : tx{tx},
          rx{rx},
          tx_secure_data_offset{sec_data_ofs},
          is_validated{validated} {}

    template <is_parsable_reponse_t Data>
    result<Data> tag::command_parse_response(bits::command_code cmd, bin_data const &payload, comm_cfg const &cfg) {
        const auto res_cmd = command_response(cmd, payload, cfg);
        if (not res_cmd) {
            return res_cmd.error();
        }
        bin_stream s{*res_cmd};
        auto data = Data();
        // Automatically add the ability to parse integral types with at least 16 bits as LSB.
        if constexpr (std::is_integral_v<Data> and sizeof(Data) > 1) {
            s >> lsb_t<sizeof(Data) * 8>{} >> data;
        } else {
            s >> data;
        }
        if (s.bad()) {
            DESFIRE_LOGE("%s: could not parse result from response data.", to_string(cmd));
            return error::malformed;
        } else if (not s.eof()) {
            log_not_empty(cmd, s.peek());
        }
        return data;
    }


    template <cipher_type Cipher>
    void tag::ut_init_session(desfire::key<Cipher> const &session_key, desfire::app_id app, std::uint8_t key_no) {
        _active_protocol = _provider->protocol_from_key(session_key);
        _active_app = app;
        _active_cipher_type = Cipher;
        _active_key_number = key_no;
    }

    template <file_type Type>
    result<file_settings<Type>> tag::get_specific_file_settings(file_id fid) {
        if (auto res_cmd = get_file_settings(fid); res_cmd) {
            // Assert the file type is correct
            if (res_cmd->type() != Type) {
                return error::malformed;
            }
            return std::move(res_cmd->template get<Type>());
        } else {
            return res_cmd.error();
        }
    }


    template <class T>
    result<> tag::write_record(file_id fid, T &&record, comm_mode operation_mode) {
        static bin_data buffer{};
        buffer.clear();
        buffer << std::forward<T>(record);
        return write_record(fid, buffer, operation_mode, 0);
    }

    template <class T>
    result<> tag::write_record(file_id fid, T &&record, trust_card_t) {
        static bin_data buffer{};
        buffer.clear();
        buffer << std::forward<T>(record);
        return write_record(fid, buffer, trust_card, 0);
    }

    template <class T>
    std::vector<T> tag::parse_records(bin_data const &data, std::uint32_t exp_count) {
        std::vector<T> records{};
        records.reserve(exp_count);
        bin_stream s{data};
        while (s.good() and (records.size() < exp_count or exp_count == all_records)) {
            records.template emplace_back();
            s >> records.back();
        }
        if (not s.eof()) {
            DESFIRE_LOGW("%s: could not parse all records, there are %u stray bytes.",
                         to_string(bits::command_code::read_records), s.remaining());
        }
        if (exp_count != all_records and records.size() != exp_count) {
            DESFIRE_LOGW("%s: expected to parse %lu records, got only %u.",
                         to_string(bits::command_code::read_records), exp_count, records.size());
        }
        return records;
    }

    template <class T>
    result<std::vector<T>> tag::read_parse_records(file_id fid, comm_mode operation_mode, std::uint32_t record_index, std::uint32_t record_count) {
        const auto res_read_records = read_records(fid, record_index, record_count, operation_mode);
        if (not res_read_records) {
            return res_read_records.error();
        }
        return parse_records<T>(*res_read_records, record_count);
    }

    template <class T>
    result<std::vector<T>> tag::read_parse_records(file_id fid, trust_card_t, std::uint32_t record_index, std::uint32_t record_count) {
        const auto res_read_records = read_records(fid, trust_card, record_index, record_count);
        if (not res_read_records) {
            return res_read_records.error();
        }
        return parse_records<T>(*res_read_records, record_count);
    }


}// namespace desfire

#endif//DESFIRE_TAG_HPP
