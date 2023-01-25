//
// Created by Pietro Saccardi on 02/01/2021.
//

/**
 * @defgroup card Mifare Card
 * @{
 */

/**
 * @defgroup application Application management
 * Command to create and modify application on the mifare card
 */

/**
 * @defgroup data Data storage
 * Commands to create and read/write files on the card
 * @{
 */

/**
 * @defgroup standardFile Standard file
 */

/**
 * @defgroup recordFile Cyclic or linear record file
 */

/**
 * @defgroup valueFile Value file
 */

/**
 * @}
 */

/**
 * @}
 */

#ifndef DESFIRE_TAG_HPP
#define DESFIRE_TAG_HPP

#include <desfire/cipher.hpp>
#include <desfire/cipher_provider.hpp>
#include <desfire/data.hpp>
#include <desfire/keys.hpp>
#include <desfire/msg.hpp>
#include <desfire/pcd.hpp>
#include <list>
#include <memory>
#include <mlab/result.hpp>
#include <type_traits>

namespace pn532 {
    class controller;
}

namespace ut::desfire_exchanges {
    struct session;
}

namespace desfire {

    namespace {
        template <unsigned N>
        using lsb_t = mlab::lsb_t<N>;
    }

    struct trust_card_t {};
    /**
     * @brief Flag marking the card as trusted, which enables determining automatically the communication mode from file settings..
     *
     * When using this instead of an explicitly set @ref cipher_mode (in the methods of @ref tag that allow to do so),
     * @ref tag will be instructed to query and accept whatever security mode the file is written in. This might impact
     * security because a cloned card with different file security modes could prompt for a different communication mode
     * than the one intended. Therefore, they have to be called explicitly with `trust_card`.
     */
    static constexpr trust_card_t trust_card{};

    class tag {
    public:
        struct comm_cfg;

        template <class... Tn>
        using result = mlab::result<error, Tn...>;

        /**
         * @brief Construct a new tag object
         * @note if you want to create a custom pcd, you should extend  @ref desfire::pcd and implement @ref desfire::pcd::communicate
         *
         * @param pcd_ a @ref desfire::pcd class that handles the tag communication. This must be alive at least as long as the @ref tag object.
         * @param provider Any @ref cipher_provider implementation to convert keys into the respective cipher.
         */
        tag(std::shared_ptr<desfire::pcd> pcd, std::unique_ptr<cipher_provider> provider);

        /**
         * @brief Construct a new tag object through a @ref pn532::desfire_pcd PCD subclass.
         * @param ctrl PN532 controller
         * @param logical_index Index of the target
         * @param provider Cipher provider
         * @see pn532::desfire_pcd
         * @see pn532::controller::initiator_data_exchange
         */
        tag(pn532::controller &ctrl, std::uint8_t logical_index, std::unique_ptr<cipher_provider> provider);

        /**
         * @brief Constructs a new tag object instantiating the given cipher provider.
         * @tparam CipherProvider A subclass of @ref desfire::cipher_provider, which must be default-constructible.
         * @tparam PCD A subclass of @ref desfire::pcd or a @ref std::shared_ptr to such a subclass
         * @param pcd A (shared pointer of) a subclass of @ref desfire::pcd used as pcd for the tag.
         * @return An instance of @ref tag.
         */
        template <class CipherProvider, class PCD>
        [[nodiscard]] static inline tag make(PCD &&pcd);

        /**
         * @brief Constructs a new tag object instantiating the given cipher provider, and using @ref pn532::desfire_pcd as PCD.
         * @tparam CipherProvider A subclass of @ref desfire::cipher_provider, which must be default-constructible.
         * @param ctrl PN532 controller
         * @param logical_index Index of the target
         * @return An instance of @ref tag.
         */
        template <class CipherProvider>
        [[nodiscard]] static inline tag make(pn532::controller &ctrl, std::uint8_t logical_index);

        tag(tag const &) = delete;

        tag(tag &&) = default;

        tag &operator=(tag const &) = delete;

        tag &operator=(tag &&) = default;

        /**
         * @return bin_data, or the following errors:
         * - @ref error::malformed
         * - @ref error::controller_error
         * @note This method is *not* private because we do not have access to a Desfire/Mifare specification, therefore we cannot
         *  guarantee that the list of commands implemented here is at all complete. Users who have access to the manual may therefore
         *  directly send packets encoding further commands without having to explicitly extend or modify this class.
         */
        result<bin_data> raw_command_response(bin_stream &tx_data, bool rx_fetch_additional_frames);

        /**
         * This method automatically divides @p data into appropriate chunks and sends them to the PICC, pre-processing
         * the data to send according to @p cfg by means of @ref cipher::prepare_tx (which is called on every chunk).
         * It will then collect the response data, and if @p cfg allows, it will also automatically concatenate all
         * response chunks, should the PICC request to send additional frames. The response data is the post-processed
         * by means of @ref cipher::confirm_rx, as set by @p cfg. The status byte is passed through and returned.
         *
         * @note Only returns an error in case of malformed packet sequence, communication error, malformed data in the
         * sense of not passing @ref cipher::confirm_rx. All other status codes are passed through as the first result
         * arguments. To automatically convert the status into an error, see @ref command_response or
         * @ref command_parse_response. This is a lower level command.
         * @see command_response
         * @see command_parse_response
         * @ingroup data
         * @internal
         * @return @ref bits::status and @ref mlab::bin_data, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        result<status, bin_data> command_status_response(command_code cmd, bin_data const &data, comm_cfg const &cfg, bool rx_fetch_additional_frames = true, cipher *override_cipher = nullptr);

        /**
         * Will automatically fetch all additional frames if requested to do so by @p cfg, and at the end will parse the
         * status byte to decide whether the command was successful (@ref status::ok or @ref status::no_changes).
         * @ingroup data
         * @return @ref mlab::bin_data, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        result<bin_data> command_response(command_code cmd, bin_data const &payload, comm_cfg const &cfg, bool rx_fetch_additional_frames = true, cipher *override_cipher = nullptr);

        /**
         * @ingroup data
         * @return @ref mlab::bin_data, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        template <class Data, class = typename std::enable_if<bin_stream::is_extractable<Data>::value or std::is_integral_v<Data>>::type>
        result<Data> command_parse_response(command_code cmd, bin_data const &payload, comm_cfg const &cfg);

        /**
         * @return @ref root_app if no app was selected, otherwise the app id.
         */
        [[nodiscard]] inline app_id const &active_app() const;

        [[nodiscard]] inline cipher_type active_key_type() const;

        /**
         * @return ''std::numeric_limits<std::uint8_t>::max'' when no authentication has took place, the the key number.
         */
        [[nodiscard]] inline std::uint8_t active_key_no() const;

        template <cipher_type Type>
        result<> authenticate(key<Type> const &k);
        result<> authenticate(any_key const &k);

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
         * @brief Selects the application to use for sucessive operations
         * @ingroup application
         * @param app The id of the app to be selected
         * @note After selecting a new application, the pcd is logged out and a new authentication is necessary.
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        result<> select_application(app_id const &app = root_app);

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
         * @brief Add a new application to the card
         * @ingroup application
         * @param new_app_id the id of the new app to be created
         * @param settings configuration of tha app (mainly: number of keys and witch cipher to use)
         * @note Must be on the @ref root_app for this to succeed.
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        result<> create_application(app_id const &new_app_id, app_settings settings);

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
         * @brief Change the setting of the selected app
         * @ingroup application
         * @param new_rights the new app settings
         * @note Need to be autenticated to the app (with @ref authenticate) for this to succeed.
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
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
         * @brief Get the configuration of the selected app
         * @ingroup application
         * @note The app need to be selected first (with @ref select_application) for this to succeed.
         * @return @ref app_settings, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        result<app_settings> get_app_settings();

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
         * @brief Get the version of the key (in the selected application)
         * @ingroup application
         * @return integer rappresenting the key version, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::parameter_error
         * - @ref error::controller_error
         */
        result<std::uint8_t> get_key_version(std::uint8_t key_num);

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
         * @brief Get a list of all application in the card
         * @ingroup application
         * @note Must be on the @ref root_app, possibly authenticated.
         * @return vector of @ref app_id, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        result<std::vector<app_id>> get_application_ids();

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
         * @brief Delete the application, and all data stored in it
         * @ingroup application
         * @param app_id The app ID of the application to be deleted
         * @note Must authenticated on the @ref root_app or in @p app, with the appropriate master key.
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        result<> delete_application(app_id const &app);

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
         * @brief Read tag information
         * @ingroup application
         * @return @ref manufacturing_info containing tag information, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        result<manufacturing_info> get_info();


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
         * @brief Delete all the application, and keys on the card
         * @ingroup application
         * @note Must be on the @ref root_app for this to succeed, and authenticated with the master key. After
         * formatting the pcd will be logged out and on the @ref root_app.
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        result<> format_picc();

        /**
         * @dot
         * digraph AlignmentMap {
         *  node [shape=record fontname="sans-serif"];
         *  rankdir=LR;
         *  sent1 [label="{0x54\n[1 byte]|Key #\n[1 byte]|key data\n[24 byte echipered]}"];
         *  received1 [label="{0x00\n[1 byte]}"];
         *  error [style=dashed label="{Error code\n[1 byte]}"];
         *  sent1 -> {received1 error}[ sametail="b"];
         * }
         * @enddot
         * @note Assumes authentication has happened and the key settings allow the change.
         * @ingroup application
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::parameter_error
         * - @ref error::controller_error
         * - @ref error::authentication_error
         */
        template <cipher_type Type>
        result<> change_key(key<Type> const &new_key);
        result<> change_key(any_key const &new_key);


        /**
         * @note Used to change a different key than the current (when key settings allow to do so). It is necessary to
         * pass the current key in order to change another, even if already authenticated.
         */
        template <cipher_type Type1, cipher_type Type2>
        result<> change_key(key<Type1> const &current_key, std::uint8_t key_no_to_change, key<Type2> const &new_key);
        result<> change_key(any_key const &current_key, std::uint8_t key_no_to_change, any_key const &new_key);

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
         * @brief get a list of files in the selected application
         * @ingroup data
         * @return vector of @ref file_id, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        result<std::vector<file_id>> get_file_ids();

        /**
         * @brief Read the file settings
         * @ingroup data
         * @param fid The file ID, Max @ref bits::max_standard_data_file_id.
         * @return @ref any_file_settings containing the file settings, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        result<any_file_settings> get_file_settings(file_id fid);

        /**
         * @brief Read the file settings
         * @ingroup data
         * @param fid The file ID, Max @ref bits::max_standard_data_file_id.
         */
        template <file_type Type>
        result<file_settings<Type>> get_specific_file_settings(file_id fid);

        /**
         * ~~~~
         * 0      1       2                3               5     0        1    0       1
         * +------+-------+----------------+---------------+     +--------+    +-------+
         * | 0x5F |  FID  | Comm. settings | Access rights | --> |  0x00  | OR | CODE  |
         * +------+-------+----------------+---------------+     +--------+    +-------+
         * | cmd  |       |                |LSB         MSB|     | Status |    | Error |
         *
         * OR (based on the communication setings of the file)
         *
         * 0      1       2                                10    0        1    0       1
         * +------+-------+--------------------------------+     +--------+    +-------+
         * | 0x5F |  FID  |       ###new settings###       | --> |  0x00  | OR | CODE  |
         * +------+-------+--------------------------------+     +--------+    +-------+
         * | cmd  |       |           enchipered           |     | Status |    | Error |
         * ~~~~
         *
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
         * @brief Modify the file settings
         * @ingroup data
         * @param fid The file ID, Max @ref bits::max_standard_data_file_id.
         * @param settings The new file settings
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         *
         * @warning Consider using the overload of this method which requires explicitly a @ref cipher_mode operation mode parameter.
         *  This method will auto-detect the security settings used: if a card is cloned and a file is created with the same id
         *  but different security, this method will accept the different security transmission mode. It may thus leak data.
         */
        result<> change_file_settings(file_id fid, generic_file_settings const &settings, trust_card_t);

        /**
         * ~~~~
         * 0      1       2                3               5     0        1    0       1
         * +------+-------+----------------+---------------+     +--------+    +-------+
         * | 0x5F |  FID  | Comm. settings | Access rights | --> |  0x00  | OR | CODE  |
         * +------+-------+----------------+---------------+     +--------+    +-------+
         * | cmd  |       |                |LSB         MSB|     | Status |    | Error |
         *
         * OR (based on the communication setings of the file)
         *
         * 0      1       2                                10    0        1    0       1
         * +------+-------+--------------------------------+     +--------+    +-------+
         * | 0x5F |  FID  |       ###new settings###       | --> |  0x00  | OR | CODE  |
         * +------+-------+--------------------------------+     +--------+    +-------+
         * | cmd  |       |           enchipered           |     | Status |    | Error |
         * ~~~~

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
         * @brief Modify the file settings
         * @ingroup data
         * @param fid The file ID, Max @ref bits::max_standard_data_file_id.
         * @param settings The new file settings
         * @param operation_mode The communication mode to use for this operation. This is derived from the base file security and
         *  the value of @ref access_rights::change member: a free access implies no security is specified, otherwise it falls back
         *  to the file's own security mode.
         * @see determine_operation_mode
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        result<> change_file_settings(file_id fid, generic_file_settings const &settings, cipher_mode operation_mode);

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
         * @brief Create a new file in the selected application
         * @ingroup data
         * @param fid file ID, Max @ref bits::max_standard_data_file_id.
         * @param settings The new file settings
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        result<> create_file(file_id fid, file_settings<file_type::standard> const &settings);

        /**
         * @brief Create a new file in the selected application
         * @ingroup data
         * @param fid file ID, Max @ref bits::max_standard_data_file_id.
         * @param settings The file settings of the created file
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
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
         * @brief Create a new file in the selected application
         * @ingroup data
         * @param fid Max @ref bits::max_backup_data_file_id.
         * @param settings The file settings of the created file
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
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
         * @brief Create a new file in the selected application
         * @ingroup valueFile
         * @param fid Max @ref bits::max_value_file_id.
         * @param settings Must have @ref value_file_settings::upper_limit greater than or equal to
         *  @ref value_file_settings::lower_limit.
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
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
         * @brief Create a new file in the selected application
         * @ingroup recordFile
         * @param fid Max @ref bits::max_record_file_id.
         * @param settings Must have @ref record_file_settings::record_size > 0 and
         *  @ref record_file_settings::max_record_count > 0.
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
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
         * @brief Create a new file in the selected application
         * @ingroup recordFile
         * @param fid Max @ref bits::max_record_file_id.
         * @param settings Must have @ref record_file_settings::record_size > 0 and
         *  @ref record_file_settings::max_record_count > 1 (at least 2).
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
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
         * @brief Delete file
         * @ingroup data
         * @param fid The file id to be removed, Max @ref bits::max_record_file_id.
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
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
         * @brief clear the linear records from the file
         * @ingroup recordFile
         * @param fid The file id of the record, Max @ref bits::max_record_file_id.
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
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
         * @brief commit data to file, abort on error
         * @ingroup data
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
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
         * @brief abort data write to file
         * @ingroup data
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
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
         * @brief read data from file
         * @ingroup data
         * @param fid Max @ref bits::max_standard_data_file_id or @ref bits::max_backup_data_file_id
         * @param offset Limited to 24 bits, i.e. must be below 0xFFFFFF. Must also be less than the file size.
         * @param length Limited to 24 bits, i.e. must be below 0xFFFFFF. Specify zero to read until the end.
         * @return @ref bin_data containing requested data, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         *
         * @warning Consider using the overload of this method which requires explicitly a @ref cipher_mode operation mode parameter.
         *  This method will auto-detect the security settings used: if a card is cloned and a file is created with the same id
         *  but different security, this method will accept the different security transmission mode. It may thus leak data.
         */
        result<bin_data> read_data(file_id fid, trust_card_t, std::uint32_t offset = 0, std::uint32_t length = all_data);

        /**
         * @brief read data from file
         * @ingroup data
         * @param fid Max @ref bits::max_standard_data_file_id or @ref bits::max_backup_data_file_id
         * @param operation_mode The communication mode to use for this operation. This is derived from the base file security and
         *  the value of @ref access_rights::read and @ref access_rights::read_write members: a free access implies no security
         *  is specified, otherwise it falls back to the file's own security mode.
         * @param offset Limited to 24 bits, i.e. must be below 0xFFFFFF. Must also be less than the file size.
         * @param length Limited to 24 bits, i.e. must be below 0xFFFFFF. Specify zero to read until the end.
         * @see determine_operation_mode
         * @return @ref bin_data containing requested data, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        result<bin_data> read_data(file_id fid, cipher_mode operation_mode, std::uint32_t offset = 0, std::uint32_t length = all_data);

        /**
         * @brief write data to file
         * @param fid Max @ref bits::max_standard_data_file_id or @ref bits::max_backup_data_file_id
         * @param data Limited to 24 bits, i.e. must be shorter than 0xFFFFFF.
         * @param offset Limited to 24 bits, i.e. must be below 0xFFFFFF.
         *
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::parameter_error
         * - @ref error::controller_error
         *
         * @warning Consider using the overload of this method which requires explicitly a @ref cipher_mode operation mode parameter.
         *  This method will auto-detect the security settings used: if a card is cloned and a file is created with the same id
         *  but different security, this method will accept the different security transmission mode. It may thus leak data.
         */
        result<> write_data(file_id fid, bin_data const &data, trust_card_t, std::uint32_t offset = 0);

        /**
         * @brief write data to file
         * @param fid Max @ref bits::max_standard_data_file_id or @ref bits::max_backup_data_file_id
         * @param data Limited to 24 bits, i.e. must be shorten than 0xFFFFFF.
         * @param operation_mode The communication mode to use for this operation. This is derived from the base file security and
         *  the value of @ref access_rights::write and @ref access_rights::read_write members: a free access implies no security
         *  is specified, otherwise it falls back to the file's own security mode.
         * @param offset Limited to 24 bits, i.e. must be below 0xFFFFFF.
         * @see determine_operation_mode
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::parameter_error
         * - @ref error::controller_error
         */
        result<> write_data(file_id fid, bin_data const &data, cipher_mode operation_mode, std::uint32_t offset = 0);

        /**
         *
         *
         * @brief read value of a credit/debit file
         * @ingroup valueFile
         * @param fid Max @ref bits::max_value_file_id.
         * @return the value in the file, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         *
         * @warning Consider using the overload of this method which requires explicitly a @ref cipher_mode operation mode parameter.
         *  This method will auto-detect the security settings used: if a card is cloned and a file is created with the same id
         *  but different security, this method will accept the different security transmission mode. It may thus leak data.
         */
        result<std::int32_t> get_value(file_id fid, trust_card_t);

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
         * @brief read value of a credit/debit file
         * @ingroup valueFile
         * @param fid Max @ref bits::max_value_file_id.
         * @param operation_mode The communication mode to use for this operation. This is derived from the base file security and
         *  the value of @ref access_rights::read and @ref access_rights::read_write members: a free access implies no security
         *  is specified, otherwise it falls back to the file's own security mode.
         * @see determine_operation_mode
         * @return the value in the file, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        result<std::int32_t> get_value(file_id fid, cipher_mode operation_mode);

        /**
         *
         *
         * @brief Increment a value file
         * @ingroup valueFile
         * @param fid Max @ref bits::max_value_file_id.
         * @param amount Must be nonnegative.
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         *
         * @warning Consider using the overload of this method which requires explicitly a @ref cipher_mode operation mode parameter.
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
         * @brief Increment a value file
         * @ingroup valueFile
         * @param fid Max @ref bits::max_value_file_id.
         * @param amount Must be nonnegative.
         * @param security The communication mode to use for this operation. This is derived from the base file security and
         *  the value of @ref access_rights::write and @ref access_rights::read_write members: a free access implies no security
         *  is specified, otherwise it falls back to the file's own security mode.
         * @see determine_operation_mode
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        result<> credit(file_id fid, std::int32_t amount, cipher_mode operation_mode);

        /**
         *
         * @brief Increment, limited by past debits transaction, the value file
         * @ingroup valueFile
         * @param fid Max @ref bits::max_value_file_id.
         * @param amount Must be nonnegative.
         * @note This can be used without full write/read permission. It can be use to refound a transaction in a safe way.
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         *
         * @warning Consider using the overload of this method which requires explicitly a @ref cipher_mode operation mode parameter.
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
         * @brief Increment, limited by past debits transaction, the value file
         * @ingroup valueFile
         * @param fid Max @ref bits::max_value_file_id.
         * @param amount Must be nonnegative.
         * @param security The communication mode to use for this operation. This is derived from the base file security and
         *  the value of @ref access_rights::write and @ref access_rights::read_write members: a free access implies no security
         *  is specified, otherwise it falls back to the file's own security mode.
         * @see determine_operation_mode
         * @note This can be used without full write/read permission. It can be use to refound a transaction in a safe way.
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        result<> limited_credit(file_id fid, std::int32_t amount, cipher_mode operation_mode);

        /**
         *
         * @brief Decrement a value file
         * @ingroup valueFile
         * @param fid Max @ref bits::max_value_file_id.
         * @param amount Must be nonnegative.
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         *
         * @warning Consider using the overload of this method which requires explicitly a @ref cipher_mode operation mode parameter.
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
         * @brief Decrement a value file
         * @ingroup valueFile
         * @param fid Max @ref bits::max_value_file_id.
         * @param amount Must be nonnegative.
         * @param security The communication mode to use for this operation. This is derived from the base file security and
         *  the value of @ref access_rights::write and @ref access_rights::read_write members: a free access implies no security
         *  is specified, otherwise it falls back to the file's own security mode.
         * @see determine_operation_mode
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        result<> debit(file_id fid, std::int32_t amount, cipher_mode operation_mode);

        /**
         * @brief Write to a linear or cyclic file
         * @ingroup recordFile
         * @param fid Max @ref bits::max_record_file_id.
         * @param data Limited to 24 bits, i.e. must be below 0xFFFFFF.
         * @param offset Limited to 24 bits, i.e. must be below 0xFFFFFF. Must also be less than the record size.
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::parameter_error
         * - @ref error::controller_error
         *
         * @warning Consider using the overload of this method which requires explicitly a @ref cipher_mode operation mode parameter.
         *  This method will auto-detect the security settings used: if a card is cloned and a file is created with the same id
         *  but different security, this method will accept the different security transmission mode. It may thus leak data.
         */
        result<> write_record(file_id fid, bin_data const &data, trust_card_t, std::uint32_t offset = 0);

        /**
         * @brief Write to a linear or cyclic file
         * @ingroup recordFile
         * @param fid Max @ref bits::max_record_file_id.
         * @param data Limited to 24 bits, i.e. must be below 0xFFFFFF.
         * @param operation_mode The communication mode to use for this operation. This is derived from the base file security and
         *  the value of @ref access_rights::write and @ref access_rights::read_write members: a free access implies no security
         *  is specified, otherwise it falls back to the file's own security mode.
         * @param offset Limited to 24 bits, i.e. must be below 0xFFFFFF. Must also be less than the record size.
         * @see determine_operation_mode
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::parameter_error
         * - @ref error::controller_error
         */
        result<> write_record(file_id fid, bin_data const &data, cipher_mode operation_mode, std::uint32_t offset = 0);

        template <class T>
        result<> write_record(file_id fid, T &&record, trust_card_t);
        template <class T>
        result<> write_record(file_id fid, T &&record, cipher_mode operation_mode);

        template <class T>
        result<std::vector<T>> read_parse_records(file_id fid, trust_card_t, std::uint32_t index = 0, std::uint32_t count = all_records);

        template <class T>
        result<std::vector<T>> read_parse_records(file_id fid, cipher_mode operation_mode, std::uint32_t index = 0, std::uint32_t count = all_records);

        /**
         * @brief Read records from a linear or cyclic file, oldest to most recent.
         * @param fid Max @ref bits::max_record_file_id.
         * @param record_index Limited to 24 bits, i.e. must be below 0xFFFFFF. Must be less than the number of existing records.
         * @param record_count Limited to 24 bits, i.e. must be below 0xFFFFFF. Must be less or equal than the number of existing
         *  records. Specify zero to read all records.
         * @return @ref bin_data containing the record/s, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::parameter_error
         * - @ref error::controller_error
         *
         * @warning Consider using the overload of this method which requires explicitly a @ref cipher_mode operation mode parameter.
         *  This method will auto-detect the security settings used: if a card is cloned and a file is created with the same id
         *  but different security, this method will accept the different security transmission mode. It may thus leak data.
         */
        result<bin_data> read_records(file_id fid, trust_card_t, std::uint32_t record_index = 0, std::uint32_t record_count = all_records);

        /**
         * @brief Read records from a linear or cyclic file
         * @param fid Max @ref bits::max_record_file_id.
         * @param record_index Limited to 24 bits, i.e. must be below 0xFFFFFF. Must be less than the number of existing records.
         * @param record_count Limited to 24 bits, i.e. must be below 0xFFFFFF. Must be less or equal than the number of existing
         *  records. Specify zero to read all records.
         * @param operation_mode The communication mode to use for this operation. This is derived from the base file security and
         *  the value of @ref access_rights::read and @ref access_rights::read_write members: a free access implies no security
         *  is specified, otherwise it falls back to the file's own security mode.
         * @see determine_operation_mode
         * @return @ref bin_data containing the record/s, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::parameter_error
         * - @ref error::controller_error
         */
        result<bin_data> read_records(file_id fid, std::uint32_t record_index, std::uint32_t record_count, cipher_mode operation_mode);

        /**
         * @brief Get the card UID
         * @ingroup card
         * @note need to be authenticated, this will fetch the "real" uid in case "uid randomization" is enabled
         * @return @ref bin_data containing the record/s, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        result<std::array<std::uint8_t, 7>> get_card_uid();

        /**
         * @brief Read the amount of free flash memory
         * @ingroup card
         * @return the amount of free memory, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        result<std::uint32_t> get_free_mem();

        /**
         * @brief Configure if the card can be formatted, or if will show the real UID
         * @ingroup card
         * @param allow_format Allow clearing all the card
         * @param enable_random_id Enable if UID should be randomized (the real UID can be read with @ref get_card_uid)
         * @warning Enabling random id is an **irreversible** operation! And @ref get_card_uid does not seem to work.
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        result<> set_configuration(bool allow_format = true, bool enable_random_id = false);

        /**
         * @brief Determines which security level to apply for a certain file operation.
         * This method will test @p file_rights and @p security against the specified @p requested_access.
         * @param requested_access Type of access requested
         * @param file_rights Access rights to the given file
         * @param security Security with which the file was created
         * @return The security mode to apply to an operation that requires the specified @p requested_access mode.
         */
        [[nodiscard]] static cipher_mode determine_operation_mode(file_access requested_access, access_rights const &file_rights, file_security security);

        /**
         * @brief Determines which security level to apply for a certain file operation.
         * This method will test @ref generic_file_settings::rights and @ref generic_file_settings::security against the specified @p requested_access.
         * @param requested_access Type of access requested
         * @param settings File settings
         * @return The security mode to apply to an operation that requires the specified @p requested_access mode.
         */
        [[nodiscard]] static cipher_mode determine_operation_mode(file_access requested_access, generic_file_settings const &settings);

        /**
         * @brief Determines which security level to apply for a certain file operation.
         * This method will test @ref generic_file_settings::rights and @ref generic_file_settings::security against the specified @p requested_access
         * from the @ref any_file_settings::generic_settings property.
         * @param requested_access Type of access requested
         * @param settings File settings
         * @return The security mode to apply to an operation that requires the specified @p requested_access mode.
         */
        [[nodiscard]] static cipher_mode determine_operation_mode(file_access requested_access, any_file_settings const &settings);

        /**
         * @brief Determines which security level to apply for a certain file operation.
         * This method will query the file settings via @ref get_file_settings and test @p file_rights and @p security
         * against the specified @p requested_access.
         * @param requested_access Type of access requested
         * @param fid File ID
         * @return The security mode to apply to an operation that requires the specified @p requested_access mode, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        [[nodiscard]] result<cipher_mode> determine_operation_mode(file_access requested_access, file_id fid);

    private:
        /**
         * The power of friendship, cit. Wifasoi, 2020
         */
        friend struct ut::desfire_exchanges::session;

        /**
         * Simulate a new session without the @ref authenticate random component
         */
        template <cipher_type Cipher>
        void ut_init_session(desfire::key<Cipher> const &session_key, desfire::app_id app, std::uint8_t key_no);


        template <class T>
        [[nodiscard]] static std::vector<T> parse_records(bin_data const &data, std::uint32_t exp_count);

        [[nodiscard]] static result<> safe_drop_payload(command_code cmd, tag::result<bin_data> const &result);
        static void log_not_empty(command_code cmd, range<bin_data::const_iterator> data);

        [[nodiscard]] inline desfire::pcd &pcd();

        result<> change_key_internal(any_key const *current_key, std::uint8_t key_no_to_change, any_key const &new_key);

        /**
         * @param cmd Must be one of @ref command_code::credit, @ref command_code::debit, @ref command_code::limited_credit.
         * @param fid Max @ref bits::max_value_file_id.
         * @param amount Must be nonnegative.
         */
        result<> write_value(command_code cmd, file_id fid, std::int32_t amount, cipher_mode operation_mode);


        /**
         * Clears data __locally__ (i.e. it may be out of sync with the card if not called at the right time).
         */
        void logout(bool due_to_error);

        [[nodiscard]] comm_cfg const &default_comm_cfg() const;
        [[nodiscard]] bool active_cipher_is_legacy() const;

        struct auto_logout;

        std::shared_ptr<desfire::pcd> _pcd;

        std::unique_ptr<cipher_provider> _provider;
        std::unique_ptr<cipher> _active_cipher;
        cipher_type _active_key_type;
        std::uint8_t _active_key_number;
        app_id _active_app;
    };


    struct tag::comm_cfg {
        cipher_mode tx = cipher_mode::plain;
        cipher_mode rx = cipher_mode::plain;
        std::size_t tx_secure_data_offset = 0;

        inline constexpr comm_cfg(cipher_mode txrx, std::size_t sec_data_ofs = 1);
        inline constexpr comm_cfg(cipher_mode tx, cipher_mode rx, std::size_t sec_data_ofs = 1);
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
    tag::result<> tag::authenticate(key<Type> const &k) {
        return authenticate(any_key{k});
    }
    template <cipher_type Type>
    tag::result<> tag::change_key(key<Type> const &new_key) {
        return change_key(any_key{new_key});
    }

    template <cipher_type Type1, cipher_type Type2>
    tag::result<> tag::change_key(key<Type1> const &current_key, std::uint8_t key_no_to_change, key<Type2> const &new_key) {
        return change_key(any_key{current_key}, key_no_to_change, any_key{new_key});
    }


    app_id const &tag::active_app() const {
        return _active_app;
    }
    cipher_type tag::active_key_type() const {
        return _active_key_type;
    }
    std::uint8_t tag::active_key_no() const {
        return _active_key_number;
    }

    constexpr tag::comm_cfg::comm_cfg(cipher_mode txrx, std::size_t sec_data_ofs) : tx{txrx},
                                                                                    rx{txrx},
                                                                                    tx_secure_data_offset{sec_data_ofs} {}

    constexpr tag::comm_cfg::comm_cfg(cipher_mode tx, cipher_mode rx, std::size_t sec_data_ofs) : tx{tx},
                                                                                                  rx{rx},
                                                                                                  tx_secure_data_offset{sec_data_ofs} {}

    template <class Data, class>
    tag::result<Data> tag::command_parse_response(command_code cmd, bin_data const &payload, comm_cfg const &cfg) {
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
        _active_cipher = _provider->cipher_from_key(session_key);
        _active_app = app;
        _active_key_type = Cipher;
        _active_key_number = key_no;
    }

    template <file_type Type>
    tag::result<file_settings<Type>> tag::get_specific_file_settings(file_id fid) {
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
    tag::result<> tag::write_record(file_id fid, T &&record, cipher_mode operation_mode) {
        static bin_data buffer{};
        buffer.clear();
        buffer << std::forward<T>(record);
        return write_record(fid, buffer, operation_mode, 0);
    }

    template <class T>
    tag::result<> tag::write_record(file_id fid, T &&record, trust_card_t) {
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
            DESFIRE_LOGW("%s: could not parse all records, there are %d stray bytes.",
                         to_string(command_code::read_records), s.remaining());
        }
        if (exp_count != all_records and records.size() != exp_count) {
            DESFIRE_LOGW("%s: expected to parse %d records, got only %d.",
                         to_string(command_code::read_records), exp_count, records.size());
        }
        return records;
    }

    template <class T>
    tag::result<std::vector<T>> tag::read_parse_records(file_id fid, cipher_mode operation_mode, std::uint32_t index, std::uint32_t count) {
        const auto res_read_records = read_records(fid, index, count, operation_mode);
        if (not res_read_records) {
            return res_read_records.error();
        }
        return parse_records<T>(*res_read_records, count);
    }

    template <class T>
    tag::result<std::vector<T>> tag::read_parse_records(file_id fid, trust_card_t, std::uint32_t index, std::uint32_t count) {
        const auto res_read_records = read_records(fid, trust_card, index, count);
        if (not res_read_records) {
            return res_read_records.error();
        }
        return parse_records<T>(*res_read_records, count);
    }


}// namespace desfire

#endif//DESFIRE_TAG_HPP
