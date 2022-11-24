//
// Created by spak on 11/24/22.
//

#ifndef DESFIRE_FS_HPP
#define DESFIRE_FS_HPP

#include <desfire/tag.hpp>

#ifndef DESFIRE_NO_FS_MACROS

#ifndef DESFIRE_FS_LOG_PREFIX
#define DESFIRE_FS_LOG_PREFIX "DESFIRE-FS"
#endif

#define DESFIRE_CMD_WITH_NAMED_RESULT(CMD, RESULT_NAME)                                                        \
    if (const auto RESULT_NAME = (CMD); not RESULT_NAME) {                                                     \
        ESP_LOGW(DESFIRE_FS_LOG_PREFIX, "Failed " #CMD " with %s", ::desfire::to_string(RESULT_NAME.error())); \
        return RESULT_NAME.error();                                                                            \
    }

#define TRY(CMD) DESFIRE_CMD_WITH_NAMED_RESULT(CMD, _r)
#define TRY_RESULT(CMD)                   \
    DESFIRE_CMD_WITH_NAMED_RESULT(CMD, r) \
    else
#define TRY_RESULT_AS(CMD, RES_VAR)             \
    DESFIRE_CMD_WITH_NAMED_RESULT(CMD, RES_VAR) \
    else

#endif

namespace desfire::fs {

    template <class... Tn>
    using r = tag::result<Tn...>;

    /**
     * @addtogroup Creating read-only, free-access files
     * @brief Creates a read-only value file with free unencrypted access in the current application.
     * The file can only be deleted afterwards, it is not possible to write on it, only read and it requires no authentication to read.
     * This assumes the app is already selected, the user is already authenticated, if the security settings require so,
     * and file @p fid does not exists.
     * @param fid Id of the file to create
     * @param value Value of the file
     * @return A result representing whether the operation was successful or not.
     * @{
     */
    r<> create_ro_free_plain_value_file(tag &tag, file_id fid, std::int32_t value);
    r<> create_ro_free_plain_data_file(tag &tag, file_id fid, mlab::bin_data const &value);
    /**
     * @}
     */

    /**
     * @brief Makes the current app read only.
     * This is achieved by preventing any change in the master key and configuration, and allowing
     * no key to further change keys.
     * @note If any other key is set up, then those keys will still be able to modify the application. Make
     * sure the current key is the only allowed key in the app.
     * @param list_requires_auth True to require authentication with a key for listing files
     * @return A result representing whether the operation succeeded.
     */
    r<> make_app_ro(tag &tag, bool list_requires_auth);

    /**
     * @brief Creates an app with a unique, randomized key, suitable for being turned into a read-only app later.
     * @param tag
     * @param aid
     * @return
     */
    [[nodiscard]] r<any_key> create_app_for_ro(tag &tag, cipher_type cipher, app_id aid, random_oracle rng);

    /**
     * Creates a new app with key zero set to @p master_key, allowing for @p extra_keys extra keys.
     * @param master_key The key number is ignored, the key is used as master key with key number zero.
     * @param rights These key rights will be applied to the app after the key has been changed.
     * @param extra_keys Number of extra keys to allow in the app. Note that if you forbid changing keys, you will never be able to change them.
     */
    r<> create_app(tag &tag, app_id aid, any_key master_key, key_rights const &rights, std::uint8_t extra_keys = 0);

    /**
     * @brief Deletes a file in the current app if existing.
     * This assumes the app is already selected and the user is already authenticated, if the security settings require so.
     * @param fid File to delete.
     * @return A result representing whether the operation was successful.
     */
    r<> delete_file_if_exists(tag &tag, file_id fid);

    /**
     * @brief Deletes app in if it exists.
     * This assumes that the root app is unlocked, if the security settings require so.
     * @param aid App to delete.
     * @return A result representing whether the operation was successful.
     */
    r<> delete_app_if_exists(tag &tag, app_id aid);

    /**
     * @brief Searches for a file id @p fid in the list of files of the current app.
     * This assumes the app is already selected and the user is already authenticated, if the security settings require so.
     * @param fid File to search for.
     * @return A boolean representing whether the file was found (or an error).
     */
    [[nodiscard]] r<bool> does_file_exist(tag &tag, file_id fid);

    /**
     * @brief Searches for an app @p aid in the list of applications.
     * This assumes the user is already authenticated, if the security settings require so.
     * @param aid App to search for.
     * @return A boolean representing whether the app was found (or an error).
     */
    [[nodiscard]] r<bool> does_app_exist(tag &tag, app_id fid);
}// namespace desfire::fs

#endif//DESFIRE_FS_HPP
