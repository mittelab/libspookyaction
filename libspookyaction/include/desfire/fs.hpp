//
// Created by spak on 11/24/22.
//

#ifndef DESFIRE_FS_HPP
#define DESFIRE_FS_HPP

#include <desfire/tag.hpp>

#ifndef DESFIRE_NO_FS_MACROS

#define DESFIRE_FS_DEFAULT_LOG_PREFIX "DESFIRE-FS"
#ifndef DESFIRE_FS_LOG_PREFIX
#define DESFIRE_FS_LOG_PREFIX DESFIRE_FS_DEFAULT_LOG_PREFIX
#endif

#define DESFIRE_FAIL_MSG(CMD_STR, RESULT)                      \
    ESP_LOGW(DESFIRE_FS_LOG_PREFIX, "%s:%d failed %s with %s", \
             __FILE__, __LINE__, CMD_STR, to_string(RESULT.error()));

#define DESFIRE_FAIL_CMD(CMD_STR, RESULT) \
    DESFIRE_FAIL_MSG(CMD_STR, RESULT)     \
    return RESULT.error();

#define DESFIRE_CMD_WITH_NAMED_RESULT(CMD, RESULT_NAME) \
    if (auto RESULT_NAME = (CMD); not RESULT_NAME) {    \
        DESFIRE_FAIL_CMD(#CMD, RESULT_NAME)             \
    }

#define DESFIRE_CMD_WITH_NAMED_RESULT_SILENT(CMD, RESULT_NAME) \
    if (auto RESULT_NAME = (CMD); not RESULT_NAME) {           \
        return RESULT_NAME.error();                            \
    }

#define TRY(CMD) DESFIRE_CMD_WITH_NAMED_RESULT(CMD, _r)

#define TRY_SILENT(CMD) DESFIRE_CMD_WITH_NAMED_RESULT_SILENT(CMD, _r)

#define TRY_RESULT(CMD)                   \
    DESFIRE_CMD_WITH_NAMED_RESULT(CMD, r) \
    else

#define TRY_RESULT_SILENT(CMD)                   \
    DESFIRE_CMD_WITH_NAMED_RESULT_SILENT(CMD, r) \
    else

#define TRY_RESULT_AS(CMD, RES_VAR)             \
    DESFIRE_CMD_WITH_NAMED_RESULT(CMD, RES_VAR) \
    else

#define TRY_RESULT_AS_SILENT(CMD, RES_VAR)             \
    DESFIRE_CMD_WITH_NAMED_RESULT_SILENT(CMD, RES_VAR) \
    else

#endif

/**
 * @defgroup roFiles Creating read-only files
 *
 * @defgroup roFreeFiles Creating read-only, free-to-read files
 *
 * @defgroup authShortcuts Authentication shortcuts
 *
 * @defgroup fsHelpers Generic filesystem helpers
 *
 * @defgroup roApps Creating read-only applications
 */

/**
 * Helper functions that automate common file and application tasks, which however require several calls
 * to the base methods of @ref desfire::tag.
 */
namespace desfire::fs {

    /**
     * @brief Creates a read-only data file the specified @p read_access in the current application.
     * The file can only be deleted afterwards, it is not possible to write on it. Reading requires authentication depending on the value
     * of @p read_access.
     * This assumes the app is already selected, the user is already authenticated, if the security settings require so,
     * and file @p fid does not exists.
     * The caller is responsible for selecting the app and authenticating. No change in app and authentication is performed by this method.
     * @ingroup roFiles
     * @param tag Tag on which to operate.
     * @param fid The file id, in the range 0..15 (included).
     * @param data Content of the file.
     * @param read_access The read access to apply to @ref file_access_rights::read.
     * @param security Security to use for this file. Note that if @p read_access is set to @ref free_access, this file might as well
     *  use @ref file_security::none.
     * @return Either `mlab::result_success`, or any of the error codes returned
     *  by @ref tag::create_file, @ref tag::write_data or @ref tag::change_file_settings.
     */
    result<> create_ro_data_file(tag &tag, file_id fid, mlab::bin_data const &data, key_actor<free_access_t> read_access, file_security security);

    /**
     * @brief Creates a read-only value file the specified @p read_access in the current application.
     * The file can only be deleted afterwards, it is not possible to change its value. Reading the value requires authentication depending on the value
     * of @p read_access. This assumes the app is already selected, the user is already authenticated, if the security settings require so,
     * and file @p fid does not exists.
     * The caller is responsible for selecting the app and authenticating. No change in app and authentication is performed by this method.
     * @ingroup roFiles
     * @param tag Tag on which to operate.
     * @param fid The file id, in the range 0..7 (included).
     * @param value Value of the file.
     * @param read_access The read access to apply to @ref file_access_rights::read.
     * @param security Security to use for this file. Note that if @p read_access is set to @ref free_access, this file might as well
     *  use @ref file_security::none.
     * @return Either `mlab::result_success`, or any of the error codes returned by @ref tag::create_file.
     */
    result<> create_ro_value_file(tag &tag, file_id fid, std::int32_t value, key_actor<free_access_t> read_access, file_security security);

    /**
     * @brief Creates a read-only data file with free read access in the current application.
     * The file can only be deleted afterwards, it is not possible to write on it. Reading does not require any authentication.
     * This assumes the app is already selected, the user is already authenticated, if the security settings require so,
     * and file @p fid does not exists.
     * The caller is responsible for selecting the app and authenticating. No change in app and authentication is performed by this method.
     * @ingroup roFreeFiles
     * @param tag Tag on which to operate.
     * @param fid The file id, in the range 0..15 (included).
     * @param data Content of the file.
     * @return Either `mlab::result_success`, or any of the error codes returned
     *  by @ref tag::create_file, @ref tag::write_data or @ref tag::change_file_settings.
     */
    result<> create_ro_free_data_file(tag &tag, file_id fid, mlab::bin_data const &data);

    /**
     * @brief Creates a read-only value file with free read access in the current application.
     * The file can only be deleted afterwards, it is not possible to change its value. Reading does not require any authentication.
     * This assumes the app is already selected, the user is already authenticated, if the security settings require so,
     * and file @p fid does not exists.
     * The caller is responsible for selecting the app and authenticating. No change in app and authentication is performed by this method.
     * @ingroup roFreeFiles
     * @param tag Tag on which to operate.
     * @param fid The file id, in the range 0..7 (included).
     * @param value Value of the file.
     * @return Either `mlab::result_success`, or any of the error codes returned by @ref tag::create_file.
     */
    result<> create_ro_free_value_file(tag &tag, file_id fid, std::int32_t value);

    /**
     * @brief Logs out the current key from @p tag, but maintains the current app selected.
     * This method cycles to the root app and back to @ref tag::active_app with @ref tag::select_application.
     * @ingroup authShortcuts
     * @param tag Tag on which to operate.
     * @return Either `mlab::result_success`, or any of the error codes returned by @ref tag::select_application.
     */
    result<> logout_app(tag &tag);

    /**
     * @brief Selects the app and authenticates to it with the given key.
     * This method is a shorthand for @ref tag::select_application and @ref tag::authenticate.
     * @ingroup authShortcuts
     * @param tag Tag on which to operate.
     * @param aid Application id to select.
     * @param key Key to use for authentication to @p aid.
     * @return Either `mlab::result_success`, or any of the error codes returned by @ref tag::select_application and @ref tag::authenticate.
     */
    result<> login_app(tag &tag, app_id aid, any_key const &key);

    /**
     * @brief Makes the current app "read only".
     * This is achieved by preventing any change in the master key and configuration, and allowing
     * no key to further change keys.
     * The caller is responsible for selecting the app and authenticating. No change in app and authentication is performed by this method.
     * If any other key is set up, then those keys will still be able to modify the application. Make sure the current key is the only
     * allowed key in the app.
     * @see create_app_for_ro
     * @ingroup roApps
     * @param tag Tag on which to operate.
     * @param list_requires_auth True to require authentication with a key for listing files and their settings,
     *  as in @ref key_rights::dir_access_without_auth.
     * @return Either `mlab::result_success`, or any of the error codes returned by @ref tag::change_app_settings.
     */
    result<> make_app_ro(tag &tag, bool list_requires_auth);

    /**
     * @brief Creates an app with a unique, randomized key, suitable for being turned into a "read only" app later.
     * @note The caller is responsible for selecting the root app and authenticating, and ensuring that @p aid does not exist.
     *  On successful exit, the tag will have @p aid selected and be authenticated on the returned key.
     * @ingroup roApps
     * @param tag Tag on which to operate.
     * @param cipher Cipher to use on this app. It is 2023, the only reasonable setting for this is @ref cipher_type::aes128.
     * @param aid Application id to create. Make sure it does not exist.
     * @param rng Random number generator used to create the key.
     * @return A randomized master key for the app, or any of the error codes returned by @ref tag::create_application.
     */
    [[nodiscard]] result<any_key> create_app_for_ro(tag &tag, cipher_type cipher, app_id aid, random_oracle rng);

    /**
     * @brief Creates a new AES128 app with the given @p master_key, allowing for a certain number of @p extra_keys.
     * The caller is responsible for selecting the root app and authenticating. On successful exit, the tag
     * will have @p aid selected and @p master_key authenticated.
     * @ingroup fsHelpers
     * @param tag Tag on which to operate.
     * @param aid Application id to create. Make sure it does not exist.
     * @param master_key The key number is ignored, the key is used as master key with key number zero.
     * @param rights These key rights will be applied to the app **after** the key has been changed.
     * @param extra_keys Number of extra keys to allow in the app. Note that if you
     *  set @ref key_rights::allowed_to_change_keys to @ref desfire::no_key in @p rights, you will never be able to change
     *  any of the extra keys.
     * @return Either `mlab::result_success` or any of the @ref error codes returned by @ref tag::select_application,
     *  @ref tag::create_application, @ref tag::change_app_settings, @ref tag::authenticate, @ref tag::change_key.
     */
    result<> create_app(tag &tag, app_id aid, any_key master_key, key_rights const &rights, std::uint8_t extra_keys = 0);

    /**
     * @brief Deletes a file in the current app if existing.
     * This uses @ref does_file_exist to check for existence before calling @ref tag::delete_file, therefore the app must
     * allow a call to @ref tag::get_file_ids.
     * The caller is responsible for selecting the app and authenticating. No change in app and authentication is performed by this method.
     * @ingroup fsHelpers
     * @param tag Tag on which to operate.
     * @param fid File to delete.
     * @return Either `mlab::result_success` or any of the @ref error codes returned by @ref tag::get_file_ids
     *  or @ref tag::delete_file.
     */
    result<> delete_file_if_exists(tag &tag, file_id fid);

    /**
     * @brief Deletes app in if it exists.
     * This uses @ref does_app_exist to check for existence before calling @ref tag::delete_application, therefore the card
     * settings must allow a call to @ref tag::get_application_ids. The caller is responsible for selecting the root app and
     * authenticating. No change in app and authentication is performed by this method.
     * @ingroup fsHelpers
     * @param tag Tag on which to operate.
     * @param aid App to delete.
     * @return Either `mlab::result_success` or any of the @ref error codes returned by @ref tag::get_application_ids
     *  or @ref tag::delete_application.
     */
    result<> delete_app_if_exists(tag &tag, app_id aid);

    /**
     * @brief Searches for a file id @p fid in the list of files of the current app.
     * This method uses @ref tag::get_file_ids to retrieve the list of files, therefore the app must allow directory access,
     * either with the currently authenticated key or by having @ref key_rights::dir_access_without_auth set to true.
     * The caller is responsible for selecting the app and authenticating. No change in app and authentication is performed by this method.
     * @ingroup fsHelpers
     * @param tag Tag on which to operate.
     * @param fid File to search for.
     * @return A boolean representing whether the file was found or not, or any error returned by @ref tag::get_file_ids.
     */
    [[nodiscard]] result<bool> does_file_exist(tag &tag, file_id fid);

    /**
     * @brief List all the files in the current app, and returns those among @p fids that exist.
     * This method uses @ref tag::get_file_ids to retrieve the list of files, therefore the app must allow directory access,
     * either with the currently authenticated key or by having @ref key_rights::dir_access_without_auth set to true.
     * The caller is responsible for selecting the app and authenticating. No change in app and authentication is performed by this method.
     * @ingroup fsHelpers
     * @param tag Tag on which to operate.
     * @param fids Vector of file IDs to search for.
     * @return A **sorted** list of items of @p fids that exist (possibly empty), or any error returned by @ref tag::get_file_ids.
     */
    [[nodiscard]] result<std::vector<file_id>> which_files_exist(tag &tag, std::vector<file_id> fids);

    /**
     * @brief Searches for an app @p aid in the list of applications.
     * This method uses @ref tag::get_application_ids to retrieve the list of files, therefore the root app must allow listing,
     * either with the root key or by having @ref key_rights::dir_access_without_auth set to true.
     * The caller is responsible for selecting the root app and authenticating. No change in app and authentication is performed by this method.
     * @ingroup fsHelpers
     * @param tag Tag on which to operate.
     * @param aid App to search for.
     * @return A boolean representing whether the app was found or not, or any error returned by @ref tag::get_application_ids.
     */
    [[nodiscard]] result<bool> does_app_exist(tag &tag, app_id aid);
}// namespace desfire::fs

#endif//DESFIRE_FS_HPP
