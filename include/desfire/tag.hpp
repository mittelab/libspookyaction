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

#include "cipher.hpp"
#include "controller.hpp"
#include "data.hpp"
#include "mlab/result.hpp"
#include "msg.hpp"
#include <list>
#include <memory>


namespace ut::desfire_exchanges {
    struct session;
}

namespace desfire {

    namespace {
        template <unsigned N>
        using lsb_t = mlab::lsb_t<N>;
    }

    class tag {
    public:
        struct comm_cfg;

        template <class... Tn>
        using r = mlab::result<error, Tn...>;

        inline explicit tag(controller &controller);

        tag(tag const &) = delete;

        tag(tag &&) = default;

        tag &operator=(tag const &) = delete;

        tag &operator=(tag &&) = default;

        /**
         * @internal
         * @return bin_data, or the following errors:
         * - @ref error::malformed
         * - @ref error::controller_error
         */
        r<bin_data> raw_command_response(bin_stream &tx_data, bool rx_fetch_additional_frames);

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
        r<status, bin_data> command_status_response(command_code cmd, bin_data const &data, comm_cfg const &cfg, bool rx_fetch_additional_frames = true, cipher *override_cipher = nullptr);

        /**
         * Will automatically fetch all additional frames if requested to do so by @p cfg, and at the end will parse the
         * status byte to decide whether the command was successful (@ref status::ok or @ref status::no_changes).
         * @ingroup data
         * @return @ref mlab::bin_data, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        r<bin_data> command_response(command_code cmd, bin_data const &payload, comm_cfg const &cfg, bool rx_fetch_additional_frames = true, cipher *override_cipher = nullptr);

        /**
         * @ingroup data
         * @return @ref mlab::bin_data, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        template <class Data, class = typename std::enable_if<bin_stream::is_extractable<Data>::value or std::is_integral_v<Data>>::type>
        r<Data> command_parse_response(command_code cmd, bin_data const &payload, comm_cfg const &cfg);

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
        r<> authenticate(key<Type> const &k);
        r<> authenticate(any_key const &k);

        /**
         * @brief Selects the application to use for sucessive operations
         * @ingroup application
         * @param app The id of the app to be selected
         * @note After selecting a new application, the controller is logged out and a new authentication is necessary.
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        r<> select_application(app_id const &app = root_app);

        /**
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
        r<> create_application(app_id const &new_app_id, app_settings settings);

        /**
         * @brief Change the setting of the selected app
         * @ingroup application
         * @param new_rights the new app settings
         * @note Need to be autenticated to the app (with @ref authenticate) for this to succeed.
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        r<> change_app_settings(key_rights new_rights);

        /**
         * @brief Get the configuration of the selected app
         * @ingroup application
         * @note The app need to be selected first (with @ref select_application) for this to succeed.
         * @return @ref app_settings, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        r<app_settings> get_app_settings();

        /**
         * @brief Get the version of the key (in the selected application)
         * @ingroup application
         * @return integer rappresenting the key version, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::parameter_error
         * - @ref error::controller_error
         */
        r<std::uint8_t> get_key_version(std::uint8_t key_num);

        /**
         * @brief Get a list of all application in the card
         * @ingroup application
         * @note Must be on the @ref root_app, possibly authenticated.
         * @return vector of @ref app_id, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        r<std::vector<app_id>> get_application_ids();

        /**
         * @brief Delete the application, and all data stored in it
         * @ingroup application
         * @param app_id The app ID of the application to be deleted
         * @note Must authenticated on the @ref root_app or in @p app, with the appropriate master key.
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        r<> delete_application(app_id const &app);

        /**
         * @brief Read tag information
         * @ingroup application
         * @return @ref manufacturing_info containing tag information, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        r<manufacturing_info> get_info();


        /**
         * @brief Delete all the application, and keys on the card
         * @ingroup application
         * @note Must be on the @ref root_app for this to succeed, and authenticated with the master key. After
         * formatting the controller will be logged out and on the @ref root_app.
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        r<> format_picc();

        /**
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
        r<> change_key(key<Type> const &new_key);
        r<> change_key(any_key const &new_key);


        /**
         * @note Used to change a different key than the current (when key settings allow to do so). It is necessary to
         * pass the current key in order to change another, even if already authenticated.
         */
        template <cipher_type Type1, cipher_type Type2>
        r<> change_key(key<Type1> const &current_key, std::uint8_t key_no_to_change, key<Type2> const &new_key);
        r<> change_key(any_key const &current_key, std::uint8_t key_no_to_change, any_key const &new_key);

        /**
         * @brief get a list of files in the selected application
         * @ingroup data
         * @return vector of @ref file_id, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        r<std::vector<file_id>> get_file_ids();

        /**
         * @brief Read the file settings
         * @ingroup data
         * @param fid The file ID, Max @ref bits::max_standard_data_file_id.
         * @return @ref any_file_settings cointaining the file settings, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        r<any_file_settings> get_file_settings(file_id fid);

        /**
         * @brief Read the file settings
         * @ingroup data
         * @param fid The file ID, Max @ref bits::max_standard_data_file_id.
         */
        template <file_type Type>
        r<file_settings<Type>> get_specific_file_settings(file_id fid);

        /**
         * @brief Modify the file settings
         * @ingroup data
         * @param fid The file ID, Max @ref bits::max_standard_data_file_id.
         * @param settings The new file settings
         * @note will read the file configuration to check witch comunication mode (@ref file_security) should use
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        r<> change_file_settings(file_id fid, generic_file_settings const &settings);

        /**
         * @brief Modify the file settings
         * @ingroup data
         * @param fid The file ID, Max @ref bits::max_standard_data_file_id.
         * @param settings The new file settings
         * @param security The comunication mode to use
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        r<> change_file_settings(file_id fid, generic_file_settings const &settings, file_security security);

        /**
         * @brief Create a new file in the selected application
         * @ingroup data
         * @param fid file ID, Max @ref bits::max_standard_data_file_id.
         * @param settings The new file settings
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        r<> create_file(file_id fid, file_settings<file_type::standard> const &settings);

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
        r<> create_file(file_id fid, any_file_settings const &settings);


        /**
         * @brief Create a new file in the selected application
         * @ingroup data
         * @param fid Max @ref bits::max_backup_data_file_id.
         * @param settings The file settings of the created file
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        r<> create_file(file_id fid, file_settings<file_type::backup> const &settings);

        /**
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
        r<> create_file(file_id fid, file_settings<file_type::value> const &settings);

        /**
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
        r<> create_file(file_id fid, file_settings<file_type::linear_record> const &settings);

        /**
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
        r<> create_file(file_id fid, file_settings<file_type::cyclic_record> const &settings);

        /**
         * @brief Delete file
         * @ingroup data
         * @param fid The file id to be removed, Max @ref bits::max_record_file_id.
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        r<> delete_file(file_id fid);

        /**
         * @brief clear the linear records from the file
         * @ingroup recordFile
         * @param fid The file id of the record, Max @ref bits::max_record_file_id.
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        r<> clear_record_file(file_id fid);

        /**
         * @brief commit data to file, abort on error
         * @ingroup data
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        r<> commit_transaction();

        /**
         * @brief abort data write to file
         * @ingroup data
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        r<> abort_transaction();

        /**
         * @brief read data from file
         * @ingroup data
         * @param fid Max @ref bits::max_standard_data_file_id or @ref bits::max_backup_data_file_id
         * @param offset Limited to 24 bits, i.e. must be below 0xFFFFFF.
         * @param length Limited to 24 bits, i.e. must be below 0xFFFFFF.
         * @return @ref bin_data containing requested data, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        r<bin_data> read_data(file_id fid, std::uint32_t offset, std::uint32_t length);

        /**
         * @brief read data from file
         * @ingroup data
         * @param fid Max @ref bits::max_standard_data_file_id or @ref bits::max_backup_data_file_id
         * @param offset Limited to 24 bits, i.e. must be below 0xFFFFFF.
         * @param length Limited to 24 bits, i.e. must be below 0xFFFFFF.
         * @param security Force the comunication mode, and do not auto-detect
         * @return @ref bin_data containing requested data, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        r<bin_data> read_data(file_id fid, std::uint32_t offset, std::uint32_t length, file_security security);

        /**
         * @brief write data to file
         * @param fid Max @ref bits::max_standard_data_file_id or @ref bits::max_backup_data_file_id
         * @param offset Limited to 24 bits, i.e. must be below 0xFFFFFF.
         * @param data Limited to 24 bits, i.e. must be below 0xFFFFFF.
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::parameter_error
         * - @ref error::controller_error
         */
        r<> write_data(file_id fid, std::uint32_t offset, bin_data const &data);

        /**
         * @brief write data to file
         * @param fid Max @ref bits::max_standard_data_file_id or @ref bits::max_backup_data_file_id
         * @param offset Limited to 24 bits, i.e. must be below 0xFFFFFF.
         * @param data Limited to 24 bits, i.e. must be below 0xFFFFFF.
         * @param security Force the comunication mode, and do not auto-detect
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::parameter_error
         * - @ref error::controller_error
         */
        r<> write_data(file_id fid, std::uint32_t offset, bin_data const &data, file_security security);

        /**
         * @brief read value of a credit/debit file
         * @ingroup valueFile
         * @param fid Max @ref bits::max_value_file_id.
         * @return the value in the file, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        r<std::int32_t> get_value(file_id fid);

        /**
         * @brief read value of a credit/debit file
         * @ingroup valueFile
         * @param fid Max @ref bits::max_value_file_id.
         * @param security Force the comunication mode, and do not auto-detect
         * @return the value in the file, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        r<std::int32_t> get_value(file_id fid, file_security security);

        /**
         * @brief Increment a value file
         * @ingroup valueFile
         * @param fid Max @ref bits::max_value_file_id.
         * @param amount Must be nonnegative.
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        r<> credit(file_id fid, std::int32_t amount);

        /**
         * @brief Increment a value file
         * @ingroup valueFile
         * @param fid Max @ref bits::max_value_file_id.
         * @param amount Must be nonnegative.
         * @param security Force the comunication mode, and do not auto-detect
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        r<> credit(file_id fid, std::int32_t amount, file_security security);

        /**
         * @brief Increment, limited by past debits transaction, the value file
         * @ingroup valueFile
         * @param fid Max @ref bits::max_value_file_id.
         * @param amount Must be nonnegative.
         * @note This can be used without full write/read permission. It can be use to refound a transaction in a safe way.
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        r<> limited_credit(file_id fid, std::int32_t amount);

        /**
         * @brief Increment, limited by past debits transaction, the value file
         * @ingroup valueFile
         * @param fid Max @ref bits::max_value_file_id.
         * @param amount Must be nonnegative.
         * @param security Force the comunication mode, and do not auto-detect
         * @note This can be used without full write/read permission. It can be use to refound a transaction in a safe way.
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        r<> limited_credit(file_id fid, std::int32_t amount, file_security security);

        /**
         * @brief Drecement a value file
         * @ingroup valueFile
         * @param fid Max @ref bits::max_value_file_id.
         * @param amount Must be nonnegative.
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        r<> debit(file_id fid, std::int32_t amount);

        /**
         * @brief Drecement a value file
         * @ingroup valueFile
         * @param fid Max @ref bits::max_value_file_id.
         * @param amount Must be nonnegative.
         * @param security Force the comunication mode, and do not auto-detect
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        r<> debit(file_id fid, std::int32_t amount, file_security security);

        /**
         * @brief Write to a linear or cyclic file
         * @ingroup recordFile
         * @param fid Max @ref bits::max_record_file_id.
         * @param offset Limited to 24 bits, i.e. must be below 0xFFFFFF.
         * @param data Limited to 24 bits, i.e. must be below 0xFFFFFF.
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::parameter_error
         * - @ref error::controller_error
         */
        r<> write_record(file_id fid, std::uint32_t offset, bin_data const &data);

        /**
         * @brief Write to a linear or cyclic file
         * @ingroup recordFile
         * @param fid Max @ref bits::max_record_file_id.
         * @param offset Limited to 24 bits, i.e. must be below 0xFFFFFF.
         * @param data Limited to 24 bits, i.e. must be below 0xFFFFFF.
         * @param security Force the comunication mode, and do not auto-detect
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::parameter_error
         * - @ref error::controller_error
         */
        r<> write_record(file_id fid, std::uint32_t offset, bin_data const &data, file_security security);

        template <class T>
        r<> write_record(file_id fid, T &&record);
        template <class T>
        r<> write_record(file_id fid, T &&record, file_security security);

        template <class T>
        r<std::vector<T>> read_parse_records(file_id fid, std::uint32_t index = 0, std::uint32_t count = all_records);

        template <class T>
        r<std::vector<T>> read_parse_records(file_id fid, std::uint32_t index, std::uint32_t count, file_security security);

        /**
         * @brief Read records from a linear or cyclic file
         * @param fid Max @ref bits::max_record_file_id.
         * @param record_index Limited to 24 bits, i.e. must be below 0xFFFFFF.
         * @param record_count Limited to 24 bits, i.e. must be below 0xFFFFFF.
         * @return @ref bin_data cointaining the record/s, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::parameter_error
         * - @ref error::controller_error
         */
        r<bin_data> read_records(file_id fid, std::uint32_t record_index = 0, std::uint32_t record_count = all_records);

        /**
         * @brief Read records from a linear or cyclic file
         * @param fid Max @ref bits::max_record_file_id.
         * @param record_index Limited to 24 bits, i.e. must be below 0xFFFFFF.
         * @param record_count Limited to 24 bits, i.e. must be below 0xFFFFFF.
         * @param security Force the comunication mode, and do not auto-detect
         * @return @ref bin_data cointaining the record/s, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::parameter_error
         * - @ref error::controller_error
         */
        r<bin_data> read_records(file_id fid, std::uint32_t record_index, std::uint32_t record_count, file_security security);

        /**
         * @brief Get the card UID
         * @ingroup card
         * @note need to be authenticated, this will fetch the "real" uid in case "uid randomization" is enabled
         * @return @ref bin_data cointaining the record/s, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        r<std::array<std::uint8_t, 7>> get_card_uid();

        /**
         * @brief Read the amount of free flash memory
         * @ingroup card
         * @return the amount of free memory, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        r<std::uint32_t> get_free_mem();

        /**
         * @brief Configure if the card can be formatted, or if will show the real UID
         * @ingroup card
         * @param allow_format Allow clearing all the card
         * @param enable_random_id Enable if UID should be randomized (the real UID can be read with @ref get_card_uid)
         * @warning Watch out when using this function! It is not clear whether any of this is reversible.
         * @return None, or the following errors:
         * - @ref error::malformed
         * - @ref error::crypto_error
         * - @ref error::controller_error
         */
        r<> set_configuration(bool allow_format = true, bool enable_random_id = false);

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

        [[nodiscard]] r<file_security> determine_file_security(file_id fid, file_access access);
        [[nodiscard]] file_security determine_file_security(file_access access, any_file_settings const &settings) const;

        [[nodiscard]] static r<> safe_drop_payload(command_code cmd, tag::r<bin_data> const &result);
        static void log_not_empty(command_code cmd, range<bin_data::const_iterator> const &data);

        [[nodiscard]] inline controller &ctrl();

        r<> change_key_internal(any_key const *current_key, std::uint8_t key_no_to_change, any_key const &new_key);

        /**
         * @param cmd Must be one of @ref command_code::credit, @ref command_code::debit, @ref command_code::limited_credit.
         * @param fid Max @ref bits::max_value_file_id.
         * @param amount Must be nonnegative.
         */
        r<> write_value(command_code cmd, file_id fid, std::int32_t amount, file_security security);


        /**
         * Clears data __locally__ (i.e. it may be out of sync with the card if not called at the right time).
         */
        void logout(bool due_to_error);

        [[nodiscard]] comm_cfg const &default_comm_cfg() const;

        struct auto_logout;


        controller *_controller;

        std::unique_ptr<cipher> _active_cipher;
        cipher_type _active_cipher_type;
        std::uint8_t _active_key_number;
        app_id _active_app;
    };


    struct tag::comm_cfg {
        cipher_mode tx = cipher_mode::plain;
        cipher_mode rx = cipher_mode::plain;
        std::size_t tx_secure_data_offset = 0;

        inline comm_cfg(cipher_mode txrx, std::size_t sec_data_ofs = 1);
        inline comm_cfg(cipher_mode tx, cipher_mode rx, std::size_t sec_data_ofs = 1);
    };
}// namespace desfire

namespace desfire {

    controller &tag::ctrl() {
        return *_controller;
    }

    tag::tag(controller &controller) : _controller{&controller},
                                       _active_cipher{std::make_unique<cipher_dummy>()},
                                       _active_cipher_type{cipher_type::none},
                                       _active_key_number{std::numeric_limits<std::uint8_t>::max()},
                                       _active_app{root_app} {}

    template <cipher_type Type>
    tag::r<> tag::authenticate(key<Type> const &k) {
        return authenticate(any_key{k});
    }
    template <cipher_type Type>
    tag::r<> tag::change_key(key<Type> const &new_key) {
        return change_key(any_key{new_key});
    }

    template <cipher_type Type1, cipher_type Type2>
    tag::r<> tag::change_key(key<Type1> const &current_key, std::uint8_t key_no_to_change, key<Type2> const &new_key) {
        return change_key(any_key{current_key}, key_no_to_change, any_key{new_key});
    }


    app_id const &tag::active_app() const {
        return _active_app;
    }
    cipher_type tag::active_key_type() const {
        return _active_cipher_type;
    }
    std::uint8_t tag::active_key_no() const {
        return _active_key_number;
    }

    tag::comm_cfg::comm_cfg(cipher_mode txrx, std::size_t sec_data_ofs) : tx{txrx},
                                                                          rx{txrx},
                                                                          tx_secure_data_offset{sec_data_ofs} {}

    tag::comm_cfg::comm_cfg(cipher_mode tx, cipher_mode rx, std::size_t sec_data_ofs) : tx{tx},
                                                                                        rx{rx},
                                                                                        tx_secure_data_offset{sec_data_ofs} {}

    template <class Data, class>
    tag::r<Data> tag::command_parse_response(command_code cmd, bin_data const &payload, comm_cfg const &cfg) {
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
        _active_cipher = session_key.make_cipher();
        _active_app = app;
        _active_cipher_type = Cipher;
        _active_key_number = key_no;
    }

    template <file_type Type>
    tag::r<file_settings<Type>> tag::get_specific_file_settings(file_id fid) {
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
    tag::r<> tag::write_record(file_id fid, T &&record, file_security security) {
        static bin_data buffer{};
        buffer.clear();
        buffer << std::forward<T>(record);
        return write_record(fid, 0, buffer, security);
    }

    template <class T>
    tag::r<> tag::write_record(file_id fid, T &&record) {
        static bin_data buffer{};
        buffer.clear();
        buffer << std::forward<T>(record);
        return write_record(fid, 0, buffer);
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
    tag::r<std::vector<T>> tag::read_parse_records(file_id fid, std::uint32_t index, std::uint32_t count, file_security security) {
        const auto res_read_records = read_records(fid, index, count, security);
        if (not res_read_records) {
            return res_read_records.error();
        }
        return parse_records<T>(*res_read_records, count);
    }

    template <class T>
    tag::r<std::vector<T>> tag::read_parse_records(file_id fid, std::uint32_t index, std::uint32_t count) {
        const auto res_read_records = read_records(fid, index, count);
        if (not res_read_records) {
            return res_read_records.error();
        }
        return parse_records<T>(*res_read_records, count);
    }


}// namespace desfire

#endif//DESFIRE_TAG_HPP
