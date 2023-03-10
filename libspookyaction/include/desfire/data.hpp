//
// Created by Pietro Saccardi on 03/01/2021.
//

#ifndef DESFIRE_DATA_HPP
#define DESFIRE_DATA_HPP

#include <desfire/bits.hpp>
#include <desfire/key_actor.hpp>
#include <desfire/log.h>
#include <memory>
#include <mlab/any_of.hpp>
#include <mlab/bin_data.hpp>
#include <type_traits>

namespace desfire {
    struct app_id_tag {};

    /**
     * A Desfire application ID (AID), i.e. a 24-bit numeric identifier.
     * @see tag::select_application
     */
    using app_id = mlab::tagged_array<app_id_tag, bits::app_id_length>;

    /**
     * @brief The root application with app id 0.
     * This is the first app that is selected when activating the tag, and the app which allows to create sub apps.
     */
    static constexpr app_id root_app{0x0, 0x0, 0x0};

    /**
     * A Desfire file ID, i.e. a simple byte.
     */
    using file_id = std::uint8_t;

    /**
     * @brief A Desfire error code.
     * This contains all proper Desfire error codes that represent an actual error (i.e. there is no "ok" and "no change" entry in this enum),
     * plus three extra error codes for the layers introduced by libSpookyAction, @ref desfire::error::controller_error, @ref desfire::error::crypto_error and
     * @ref desfire::error::malformed.
     */
    enum struct error : std::uint8_t {
        out_of_eeprom = static_cast<std::uint8_t>(bits::status::out_of_eeprom),              ///< Insufficient memory.
        illegal_command = static_cast<std::uint8_t>(bits::status::illegal_command),          ///< Command not supported.
        integrity_error = static_cast<std::uint8_t>(bits::status::integrity_error),          ///< Invalid CRC or MAC, might indicate data corruption.
        no_such_key = static_cast<std::uint8_t>(bits::status::no_such_key),                  ///< Invalid specified key number.
        length_error = static_cast<std::uint8_t>(bits::status::length_error),                ///< The length of the command is invalid, might indicate a bug.
        permission_denied = static_cast<std::uint8_t>(bits::status::permission_denied),      ///< The current status (or configuration) does not allow this command.
        parameter_error = static_cast<std::uint8_t>(bits::status::parameter_error),          ///< A parameter that was passed is invalid.
        app_not_found = static_cast<std::uint8_t>(bits::status::app_not_found),              ///< The specified app does not exist.
        app_integrity_error = static_cast<std::uint8_t>(bits::status::app_integrity_error),  ///< Uncommon, indicates corruption in the app.
        authentication_error = static_cast<std::uint8_t>(bits::status::authentication_error),///< The current authentication status does not allow this command.
        boundary_error = static_cast<std::uint8_t>(bits::status::boundary_error),            ///< Attempt to read or write beyond limits.
        picc_integrity_error = static_cast<std::uint8_t>(bits::status::picc_integrity_error),///< Uncommon, indicates corruption in the PICC.
        command_aborted = static_cast<std::uint8_t>(bits::status::command_aborted),          ///< The previous command was not completed.
        picc_disabled_error = static_cast<std::uint8_t>(bits::status::picc_disabled_error),  ///< The PICC is disabled due to unrecoverable error.
        count_error = static_cast<std::uint8_t>(bits::status::count_error),                  ///< Reached the maximum number of apps.
        duplicate_error = static_cast<std::uint8_t>(bits::status::duplicate_error),          ///< The specified file or app already exist.
        eeprom_error = static_cast<std::uint8_t>(bits::status::eeprom_error),                ///< Uncommon, unable to write to the NV memory.
        file_not_found = static_cast<std::uint8_t>(bits::status::file_not_found),            ///< The specified file does not exist.
        file_integrity_error = static_cast<std::uint8_t>(bits::status::file_integrity_error),///< Uncommon, indicates corruption in the file.
        controller_error,                                                                    ///< The @ref pcd implementation could not transmit data and returned an error.
        malformed,                                                                           ///< No data or incorrect data received when some specific format was expected. Might indicate a bug.
        crypto_error                                                                         /**< Something went wrong with crypto (invalid @ref comm_mode perhaps).
                                                                                               * This could mean invalid MAC, CMAC, or CRC, or data length is not a multiple of block
                                                                                               * size when encrypted; this depends on the specified communication config.
                                                                                               */
    };

    /**
     * @brief Converts an internal `bits::status` object into its corresponding error code.
     * @param s A status that represents an error.
     * @return Simply the cast of @p s to @ref error; if @p s does not represent an error, returns @ref error::malformed.
     */
    [[nodiscard]] error error_from_status(bits::status s);

    /**
     * @brief Monostate structure representing a special @ref key_rights value.
     * The unique instance of this structure, @ref same_key, represent that to change a key, the same key must be used for authentication.
     */
    struct same_key_t {};

    /**
     * Used in @ref key_rights to represent that to change a key, the same key must be used for authentication.
     * @see key_rights::allowed_to_change_keys
     */
    static constexpr same_key_t same_key{};

    /**
     * Sets the capabilities of the master/root/general keys at an app or PICC level.
     * @see
     *  - app_settings
     *  - tag::create_application
     *  - tag::change_app_settings
     */
    struct key_rights {
        /**
         * @brief Who is allowed to change a key.
         * Possible values:
         *  - @ref same_key (default): authentication with a given key is necessary to change that very same key
         *  - @ref no_key : key change is not possible
         *  - any other numeric value: authentication with the key with that number is needed to change any other key.
         */
        key_actor<same_key_t> allowed_to_change_keys{same_key};

        /**
         * Whether the master key (or root key, for @ref root_app) can be changed or not.
         */
        bool master_key_changeable = true;

        /**
         * @brief Controls directory access permission.
         * On an app level, it is possible to list file IDs, get their settings and the key settings.
         * On a PICC level (i.e. on @ref root_app), it is possible to list app IDs and key settings.
         */
        bool dir_access_without_auth = true;

        /**
         * @brief Controls app and file creation permissions.
         * On an app level, this means files can be created or deleted without authenticating with the master key.
         * On a PICC level (i.e. on @ref root_app), applications can be created without authentication and deleted with their own master keys.
         */
        bool create_delete_without_master_key = false;

        /**
         * @brief Controls key rights change permission.
         * Setting this to false freezes the configuration of the PICC or the app.
         * Changing still requires to authenticate with the appropriate master key.
         */
        bool config_changeable = true;

        /**
         * @name Comparison operators
         * @{
         */
        [[nodiscard]] inline bool operator==(desfire::key_rights const &other) const;
        [[nodiscard]] inline bool operator!=(desfire::key_rights const &other) const;
        /**
         * @}
         */

        /**
         * Default-constructs a key rights object
         */
        constexpr key_rights() = default;

        /**
         * Constructs a key rights object.
         * @note Unfortunately the arguments are a list of four booleans. Be mindful that order of the arguments matter; having
         *  C-style named initializers would be helpful here.
         * @param allowed_to_change_keys_ Goes into @ref allowed_to_change_keys.
         * @param master_key_changeable_ Goes into @ref master_key_changeable.
         * @param dir_access_without_auth_ Goes into @ref dir_access_without_auth.
         * @param create_delete_without_master_key_ Goes into @ref create_delete_without_master_key.
         * @param config_changeable_ Goes into @ref config_changeable.
         */
        constexpr key_rights(key_actor<same_key_t> allowed_to_change_keys_,
                             bool master_key_changeable_,
                             bool dir_access_without_auth_,
                             bool create_delete_without_master_key_,
                             bool config_changeable_)
            : allowed_to_change_keys{allowed_to_change_keys_},
              master_key_changeable{master_key_changeable_},
              dir_access_without_auth{dir_access_without_auth_},
              create_delete_without_master_key{create_delete_without_master_key_},
              config_changeable{config_changeable_} {}
    };

    /**
     * @brief Monostate structure representing a special @ref file_access_rights permission.
     * The unique instance of this structure, @ref free_access, represent that no authentication is to be used to complete a certain
     * operation.
     * @warning Using free access also means that the communication mode is degraded to @ref comm_mode::plain (or in certain cases,
     *  @ref comm_mode::maced). There is thus no such a thing as **confidential** free access.
     */
    struct free_access_t {};

    /**
     * Used in @ref file_access_rights to represent that no authentication is needed to perform an operation and @ref comm_mode can
     * be degraded to @ref comm_mode::plain or @ref comm_mode::maced.
     */
    static constexpr free_access_t free_access{};

    /**
     * Type of file access operations.
     */
    enum struct file_access {
        change,///< Changing the file settings.
        read,  ///< Reading the file content, or getting the value.
        write  ///< Writing the file content, or debiting/crediting a value.
    };

    /**
     * @brief Struct representing the access rights for any file type.
     * All the members of this struct support having a @ref free_access option.
     */
    struct file_access_rights {
        key_actor<free_access_t> change;    //!< Right to change the file settings.
        key_actor<free_access_t> read_write;//!< Read **and** write right. This is combined with @ref read or @ref write with an "or" logical operator.
        key_actor<free_access_t> write;     //!< Right to change the file content (covers @ref tag::debit and @ref tag::credit as well).
        key_actor<free_access_t> read;      //!< Right to read the file content or value.

        /**
         * Default-constructs the structure. Only the master key holds all rights.
         */
        constexpr file_access_rights() = default;

        /**
         * Constructs the structure in such a way that no key has any right.
         */
        constexpr file_access_rights(no_key_t);

        /**
         * Constructs the structure in such a way that no authentication is required for any operation.
         */
        constexpr file_access_rights(free_access_t);

        /**
         * Constructs the structure in such a way that only @p single_key holds all the rights.
         * @param single_key Key number
         */
        constexpr explicit file_access_rights(std::uint8_t single_key);

        /**
         * Prevent accidental cast from bool.
         */
        file_access_rights(bool) = delete;

        /**
         * Constructs the structure assigning read and write rights simultaneously.
         * @param rw Read and write rights. This will be copied to @ref read and @ref write.
         * @param chg Change right value.
         */
        constexpr file_access_rights(key_actor<free_access_t> rw, key_actor<free_access_t> chg);

        /**
         * Construts the structure assigning explicitly all members
         * @param rw Goes to @ref read_write.
         * @param chg Goes to @ref change.
         * @param r Goes to @ref read.
         * @param w Goes to @ref write.
         */
        constexpr file_access_rights(key_actor<free_access_t> rw, key_actor<free_access_t> chg, key_actor<free_access_t> r, key_actor<free_access_t> w);

        /**
         * @brief Unpacks @p v into the various members of this struct.
         * Meant for internal use.
         * @param v Word-packed access rights.
         */
        inline void set_word(std::uint16_t v);

        /**
         * @brief Packs the various members of this struct into a single word.
         * Meant for internal use.
         * @return Word-packed access rights.
         */
        [[nodiscard]] inline std::uint16_t get_word() const;

        /**
         * @brief Factory method that calls @ref set_word.
         * Meant for internal use.
         * @param word Word-packed access rights.
         * @return A @ref file_access_rights data structure on which @ref set_word was called.
         */
        [[nodiscard]] inline static file_access_rights from_word(std::uint16_t word);

        /**
         * @brief Checks if the given @ref file_access @p access is @ref free_access.
         * @param access Access to test.
         * @return True if there is @ref free_access for this type of operation.
         */
        [[nodiscard]] bool is_free(file_access access) const;

        /**
         * @name Comparison operators
         * @{
         */
        [[nodiscard]] inline bool operator==(file_access_rights const &other) const;
        [[nodiscard]] inline bool operator!=(file_access_rights const &other) const;
        /**
         * @}
         */
    };

    /**
     * @addtogroup FileSettings File settings
     * Data structures describing shared (@ref common_file_settings) and @ref file_type -specific settings.
     * @{
     */

    /**
     * File settings shared between all file types.
     */
    struct common_file_settings {
        file_security security = file_security::none;//!< Security to apply to this file.
        file_access_rights rights;                   //!< Access rights.

        constexpr common_file_settings() = default;
        constexpr common_file_settings(file_security security_, file_access_rights rights_);
    };

    /**
     * Settings specific to @ref file_type::standard and @ref file_type::backup. This is only the file size.
     */
    struct data_file_settings {
        /**
         * Size of the file in bytes.
         * @note This is actually a 24bit value, so the maximum value is 0xffffff. It will be clamped upon transmission.
         */
        std::uint32_t size = 0;

        constexpr data_file_settings() = default;
        explicit constexpr data_file_settings(std::uint32_t size_) : size{size_} {}
    };

    /**
     * Settings specific to @ref file_type::value.
     */
    struct value_file_settings {
        std::int32_t lower_limit = 0;//!< Lower limit for the value.
        std::int32_t upper_limit = 0;//!< Upper limit for the value.
        /**
         * Value of the file.
         * @note For @ref tag::get_file_settings, this includes the limited credit, if enabled.
         * For the method @ref tag::create_file(file_id, file_settings<file_type::value> const &), this is the initial value.
         */
        std::int32_t value = 0;

        bool limited_credit_enabled = false;//!< Whether limited crediting is enabled for this file.

        constexpr value_file_settings() = default;

        constexpr value_file_settings(std::int32_t lowlim, std::int32_t uplim, std::int32_t v, bool enable_lim_credit = false)
            : lower_limit{lowlim},
              upper_limit{uplim},
              value{v},
              limited_credit_enabled{enable_lim_credit} {}
    };

    /**
     * Settings specific to @ref file_type::linear_record and @ref file_type::cyclic_record.
     */
    struct record_file_settings {
        /**
         * Size in bytes of a single record.
         * @note This is actually a 24bit value, so the maximum value is 0xffffff. It will be clamped upon transmission.
         */
        std::uint32_t record_size = 0;

        /**
         * Maximum number of records allowed in the file.
         * @note This is actually a 24bit value, so the maximum value is 0xffffff. It will be clamped upon transmission.
         */
        std::uint32_t max_record_count = 0;

        /**
         * @brief Contains the total number of records. Unused for file creation.
         * @note This is actually a 24bit value, so the maximum value is 0xffffff. It will be clamped upon transmission.
         */
        std::uint32_t record_count = 0;

        constexpr record_file_settings() = default;

        constexpr record_file_settings(std::uint32_t rec_size, std::uint32_t max_rec_count, std::uint32_t rec_count = 0)
            : record_size{rec_size},
              max_record_count{max_rec_count},
              record_count{rec_count} {}
    };

    /**
     * Template struct used only for template specialization.
     * Each of the template specialization contains a @ref common_file_settings member and one of
     * @ref data_file_settings, @ref value_file_settings, @ref record_file_settings as a mixin.
     */
    template <file_type>
    struct file_settings {};

    /**
     * @brief Specialization for standard data files.
     * This class has no logic other than merging together the two base classes and providing constructors for both.
     * @see
     *  - common_file_settings
     *  - data_file_settings
     */
    template <>
    struct file_settings<file_type::standard> : public common_file_settings, public data_file_settings {
        using specific_file_settings = data_file_settings;

        constexpr file_settings() : common_file_settings{}, data_file_settings{} {}

        constexpr file_settings(common_file_settings generic, data_file_settings specific)
            : common_file_settings{generic}, data_file_settings{specific} {}

        constexpr file_settings(file_security security, file_access_rights rights, std::uint32_t size)
            : common_file_settings{security, rights}, data_file_settings{size} {}

        constexpr file_settings(common_file_settings generic, std::uint32_t size)
            : common_file_settings{generic}, data_file_settings{size} {}

        constexpr file_settings(file_security security, file_access_rights rights, data_file_settings specific)
            : common_file_settings{security, rights}, data_file_settings{specific} {}
    };

    /**
     * @brief Specialization for backup data files.
     * This class has no logic other than merging together the two base classes and providing constructors for both.
     * @see
     *  - common_file_settings
     *  - data_file_settings
     */
    template <>
    struct file_settings<file_type::backup> : public common_file_settings, public data_file_settings {
        using specific_file_settings = data_file_settings;

        constexpr file_settings() : common_file_settings{}, data_file_settings{} {}

        constexpr file_settings(common_file_settings generic, data_file_settings specific)
            : common_file_settings{generic}, data_file_settings{specific} {}

        constexpr file_settings(file_security security, file_access_rights rights, std::uint32_t size)
            : common_file_settings{security, rights}, data_file_settings{size} {}

        constexpr file_settings(common_file_settings generic, std::uint32_t size)
            : common_file_settings{generic}, data_file_settings{size} {}

        constexpr file_settings(file_security security, file_access_rights rights, data_file_settings specific)
            : common_file_settings{security, rights}, data_file_settings{specific} {}
    };

    /**
     * @brief Specialization for value files.
     * This class has no logic other than merging together the two base classes and providing constructors for both.
     * @see
     *  - common_file_settings
     *  - value_file_settings
     */
    template <>
    struct file_settings<file_type::value> : public common_file_settings, public value_file_settings {
        using specific_file_settings = value_file_settings;
        constexpr file_settings()
            : common_file_settings{},
              value_file_settings{0, 0, 0, false} {}

        constexpr file_settings(common_file_settings generic, value_file_settings specific)
            : common_file_settings{generic}, value_file_settings{specific} {}

        constexpr file_settings(file_security security, file_access_rights rights,
                                std::int32_t lowlim, std::int32_t uplim, std::int32_t v, bool enable_lim_credit = false)
            : common_file_settings{security, rights},
              value_file_settings{lowlim, uplim, v, enable_lim_credit} {}

        constexpr file_settings(common_file_settings generic,
                                std::int32_t lowlim, std::int32_t uplim, std::int32_t v, bool enable_lim_credit = false)
            : common_file_settings{generic},
              value_file_settings{lowlim, uplim, v, enable_lim_credit} {}

        constexpr file_settings(file_security security, file_access_rights rights,
                                value_file_settings specific)
            : common_file_settings{security, rights},
              value_file_settings{specific} {}
    };

    /**
     * @brief Specialization for linear record files.
     * This class has no logic other than merging together the two base classes and providing constructors for both.
     * @see
     *  - common_file_settings
     *  - record_file_settings
     */
    template <>
    struct file_settings<file_type::linear_record> : public common_file_settings, public record_file_settings {
        using specific_file_settings = record_file_settings;

        constexpr file_settings()
            : common_file_settings{},
              record_file_settings{0, 0, 0} {}

        constexpr file_settings(common_file_settings generic, record_file_settings specific)
            : common_file_settings{generic}, record_file_settings{specific} {}

        constexpr file_settings(file_security security, file_access_rights rights,
                                std::uint32_t rec_size, std::uint32_t max_rec_count, std::uint32_t rec_count = 0)
            : common_file_settings{security, rights},
              record_file_settings{rec_size, max_rec_count, rec_count} {}


        constexpr file_settings(common_file_settings generic,
                                std::uint32_t rec_size, std::uint32_t max_rec_count, std::uint32_t rec_count = 0)
            : common_file_settings{generic},
              record_file_settings{rec_size, max_rec_count, rec_count} {}

        constexpr file_settings(file_security security, file_access_rights rights,
                                record_file_settings specific)
            : common_file_settings{security, rights},
              record_file_settings{specific} {}
    };

    /**
     * @brief Specialization for cyclic record files.
     * This class has no logic other than merging together the two base classes and providing constructors for both.
     * @see
     *  - common_file_settings
     *  - record_file_settings
     */
    template <>
    struct file_settings<file_type::cyclic_record> : public common_file_settings, public record_file_settings {
        using specific_file_settings = record_file_settings;

        constexpr file_settings()
            : common_file_settings{},
              record_file_settings{0, 0, 0} {}

        constexpr file_settings(common_file_settings generic, record_file_settings specific)
            : common_file_settings{generic}, record_file_settings{specific} {}

        constexpr file_settings(file_security security, file_access_rights rights,
                                std::uint32_t rec_size, std::uint32_t max_rec_count, std::uint32_t rec_count = 0)
            : common_file_settings{security, rights},
              record_file_settings{rec_size, max_rec_count, rec_count} {}

        constexpr file_settings(common_file_settings generic,
                                std::uint32_t rec_size, std::uint32_t max_rec_count, std::uint32_t rec_count = 0)
            : common_file_settings{generic},
              record_file_settings{rec_size, max_rec_count, rec_count} {}


        constexpr file_settings(file_security security, file_access_rights rights,
                                record_file_settings specific)
            : common_file_settings{security, rights},
              record_file_settings{specific} {}
    };


    /**
     * @brief Variant-like type which can hold the file settings for a file of a given type.
     * All file types have the @ref common_settings property.
     */
    class any_file_settings : public mlab::any_of<file_type, file_settings, file_type::standard> {
    public:
        using mlab::any_of<file_type, file_settings, file_type::standard>::any_of;

        /**
         * Settings common to all @ref file_type.
         */
        [[nodiscard]] common_file_settings const &common_settings() const;

        /**
         * @brief Settings for @ref file_type::standard and @ref file_type::backup.
         * Test the type before calling this method, as it will return an invalid reference if the type is not the correct one.
         */
        [[nodiscard]] data_file_settings const &data_settings() const;

        /**
         * @brief Settings for @ref file_type::linear_record and @ref file_type::cyclic_record.
         * Test the type before calling this method, as it will return an invalid reference if the type is not the correct one.
         */
        [[nodiscard]] record_file_settings const &record_settings() const;

        /**
         * @brief Settings for @ref file_type::value.
         * Test the type before calling this method, as it will return an invalid reference if the type is not the correct one.
         */
        [[nodiscard]] value_file_settings const &value_settings() const;

        /**
         * @copydoc common_settings
         */
        [[nodiscard]] common_file_settings &common_settings();

        /**
         * @copydoc data_settings
         */
        [[nodiscard]] data_file_settings &data_settings();

        /**
         * @copydoc record_settings
         */
        [[nodiscard]] record_file_settings &record_settings();

        /**
         * @copydoc value_settings
         */
        [[nodiscard]] value_file_settings &value_settings();
    };
    /**
     * @}
     */


    /**
     * Represents the settings for an application.
     * @see tag::create_application
     */
    struct app_settings {
        key_rights rights;        //!< Permission for the various app keys.
        std::uint8_t max_num_keys;//!< Maximum number of keys in the app (at least 1).
        app_crypto crypto;        //!< Cryptography settings for this app.

        /**
         * Constructs a new @ref app_settings object.
         * @param crypto_ Cryptography to use, defaults to DES (which is **insecure**).
         * @param rights_ Key rights, defaults to the master key holding all rights.
         * @param max_num_keys_ Number of keys in the app, defaults to 14 (the maximum).
         */
        constexpr explicit app_settings(app_crypto crypto_ = app_crypto::legacy_des_2k3des,
                                        key_rights rights_ = key_rights{},
                                        std::uint8_t max_num_keys_ = bits::max_keys_per_app);

        /**
         * Constructs a new @ref app_settings objects starting from a @ref cipher_type.
         * @param cipher Cipher to use for this app. This better be **AES128**.
         * @param rights_ Key rights, defaults to the master key holding all rights.
         * @param max_num_keys_ Number of keys in the app, defaults to 14 (the maximum).
         */
        constexpr explicit app_settings(cipher_type cipher,
                                        key_rights rights_ = key_rights{},
                                        std::uint8_t max_num_keys_ = bits::max_keys_per_app);
    };

    /**
     * @brief Structure representing an approximate (sic) storage size in a Desfire card.
     * It seems that on Desfire cards we do not get an exact storage size, but just the exponent and
     * a bit representing whether the number is exact or "within the range". This structure abstracts
     * this behavior.
     * Used in @ref manufacturing_info only.
     * @see tag::get_info
     */
    class storage_size {
        std::uint8_t _flag;

        [[nodiscard]] inline unsigned exponent() const;
        [[nodiscard]] inline bool approx() const;

    public:
        /**
         * @brief Initializes a new structure from a (potentially approximate) number of bytes.
         * This constructor is meant for internal use only.
         * @param nbytes Number read from the card. This might have an "approximate bit" set,
         *  so it should not be taken as an exact number.
         */
        explicit storage_size(std::size_t nbytes = 0);

        /**
         * @brief Lower bound to the storage size.
         * Might coincide with @ref bytes_upper_bound.
         * @return A number of bytes.
         */
        [[nodiscard]] inline std::size_t bytes_lower_bound() const;

        /**
         * @brief Upper bound to the storage size.
         * Might coincide with @ref bytes_lower_bound.
         * @return A number of bytes.
         */
        [[nodiscard]] inline std::size_t bytes_upper_bound() const;

        mlab::bin_stream &operator>>(mlab::bin_stream &s);
        mlab::bin_data &operator<<(mlab::bin_data &s) const;
    };

    /**
     * Software or hardware information used in @ref manufacturing_info.
     * @see tag::get_info
     */
    struct ware_info {
        std::uint8_t vendor_id = 0;         //!< Vendor ID.
        std::uint8_t type = 0;              //!< Hardware type
        std::uint8_t subtype = 0;           //!< Hardware subtype
        std::uint8_t version_major = 0;     //!< Major version **salutes**.
        std::uint8_t version_minor = 0;     //!< Minor version.
        storage_size size;                  //!< Software size.
        std::uint8_t comm_protocol_type = 0;//!< I genuinely do not know what this is.
    };

    /**
     * Information about a card's hardware and software.
     * @see tag::get_info
     */
    struct manufacturing_info {
        ware_info hardware;//!< Hardware information.
        ware_info software;//!< Software (firmware?) information.
        /**
         * @brief Serial number.
         * @note Usually coincides with the transmitted @ref pn532::nfcid_2t, unless random id has been
         *  enabled via @ref tag::set_configuration.
         */
        std::array<std::uint8_t, 7> serial_no{};
        std::array<std::uint8_t, 5> batch_no{};//!< Production batch number.

        /**
         * @brief Production week.
         * @note It seems that in the cards sometimes this value is set as hex, while it should presumably
         *  set as decimal; i.e. value 0x23 means 23rd week of the year, not the 35th.
         */
        std::uint8_t production_week = 0;

        /**
         * @brief Production year.
         * @note It seems that in the cards sometimes this value is set as hex, while it should presumably
         *  set as decimal; i.e. value 0x17 means 2017, not 2023.
         */
        std::uint8_t production_year = 0;
    };

}// namespace desfire

namespace mlab {

    /**
     * @addtogroup IOOperators
     * @{
     */
    bin_stream &operator>>(bin_stream &s, desfire::key_rights &kr);
    bin_stream &operator>>(bin_stream &s, desfire::app_settings &ks);
    bin_stream &operator>>(bin_stream &s, std::vector<desfire::app_id> &ids);
    bin_stream &operator>>(bin_stream &s, desfire::ware_info &wi);
    bin_stream &operator>>(bin_stream &s, desfire::manufacturing_info &mi);

    bin_stream &operator>>(bin_stream &s, desfire::file_access_rights &ar);
    bin_stream &operator>>(bin_stream &s, desfire::common_file_settings &fs);
    bin_stream &operator>>(bin_stream &s, desfire::data_file_settings &fs);
    bin_stream &operator>>(bin_stream &s, desfire::value_file_settings &fs);
    bin_stream &operator>>(bin_stream &s, desfire::record_file_settings &fs);
    bin_stream &operator>>(bin_stream &s, desfire::any_file_settings &fs);

    template <desfire::file_type Type>
    bin_stream &operator>>(bin_stream &s, desfire::file_settings<Type> &fs);

    bin_data &operator<<(bin_data &bd, desfire::key_rights const &kr);
    bin_data &operator<<(bin_data &bd, desfire::app_settings const &ks);

    bin_data &operator<<(bin_data &bd, desfire::file_access_rights const &ar);
    bin_data &operator<<(bin_data &bd, desfire::common_file_settings const &fs);
    bin_data &operator<<(bin_data &bd, desfire::data_file_settings const &fs);
    bin_data &operator<<(bin_data &bd, desfire::value_file_settings const &fs);
    bin_data &operator<<(bin_data &bd, desfire::record_file_settings const &fs);
    bin_data &operator<<(bin_data &bd, desfire::any_file_settings const &fs);

    template <desfire::file_type Type>
    bin_data &operator<<(bin_data &bd, desfire::file_settings<Type> const &fs);
    /**
     * @}
     */
}// namespace mlab

namespace desfire {

    constexpr app_settings::app_settings(app_crypto crypto_, key_rights rights_, std::uint8_t max_num_keys_) : rights{rights_}, max_num_keys{max_num_keys_}, crypto{crypto_} {}

    constexpr app_settings::app_settings(cipher_type cipher, key_rights rights_, std::uint8_t max_num_keys_) : rights{rights_}, max_num_keys{max_num_keys_}, crypto{app_crypto_from_cipher(cipher)} {}

    unsigned storage_size::exponent() const {
        return _flag >> bits::storage_size_exponent_shift;
    }
    bool storage_size::approx() const {
        return 0 != (_flag & bits::storage_size_approx_bit);
    }
    std::size_t storage_size::bytes_lower_bound() const {
        return 1 << exponent();
    }
    std::size_t storage_size::bytes_upper_bound() const {
        return 1 << (approx() ? exponent() + 1 : exponent());
    }

    constexpr file_access_rights::file_access_rights(std::uint8_t single_key) : change{single_key}, read_write{single_key}, write{single_key}, read{single_key} {
        // TODO: when C++20 is enabled, used is_constant_evaluated to issue a warning if single_key is out of range
    }

    constexpr file_access_rights::file_access_rights(no_key_t) : change{no_key}, read_write{no_key}, write{no_key}, read{no_key} {}

    constexpr file_access_rights::file_access_rights(free_access_t) : change{free_access}, read_write{free_access}, write{free_access}, read{free_access} {}

    constexpr file_access_rights::file_access_rights(key_actor<free_access_t> rw, key_actor<free_access_t> chg) : file_access_rights{no_key} {
        read_write = rw;
        change = chg;
    }

    constexpr file_access_rights::file_access_rights(key_actor<free_access_t> rw, key_actor<free_access_t> chg, key_actor<free_access_t> r, key_actor<free_access_t> w)
        : file_access_rights{no_key} {
        read_write = rw;
        change = chg;
        read = r;
        write = w;
    }

    std::uint16_t file_access_rights::get_word() const {
        return (std::uint16_t(read_write.get_nibble()) << bits::file_access_rights_read_write_shift) |
               (std::uint16_t(change.get_nibble()) << bits::file_access_rights_change_shift) |
               (std::uint16_t(read.get_nibble()) << bits::file_access_rights_read_shift) |
               (std::uint16_t(write.get_nibble()) << bits::file_access_rights_write_shift);
    }

    void file_access_rights::set_word(std::uint16_t v) {
        read_write.set_nibble(std::uint8_t((v >> bits::file_access_rights_read_write_shift) & 0b1111));
        change.set_nibble(std::uint8_t((v >> bits::file_access_rights_change_shift) & 0b1111));
        read.set_nibble(std::uint8_t((v >> bits::file_access_rights_read_shift) & 0b1111));
        write.set_nibble(std::uint8_t((v >> bits::file_access_rights_write_shift) & 0b1111));
    }

    file_access_rights file_access_rights::from_word(std::uint16_t word) {
        file_access_rights retval;
        retval.set_word(word);
        return retval;
    }

    bool file_access_rights::operator==(file_access_rights const &other) const {
        return change == other.change and
               read_write == other.read_write and
               write == other.write and
               read == other.read;
    }

    bool file_access_rights::operator!=(file_access_rights const &other) const {
        return change != other.change or
               read_write != other.read_write or
               write != other.write or
               read != other.read;
    }


    constexpr common_file_settings::common_file_settings(file_security security_, file_access_rights rights_) : security{security_}, rights{rights_} {}


    bool desfire::key_rights::operator==(desfire::key_rights const &other) const {
        return other.allowed_to_change_keys == allowed_to_change_keys and
               other.create_delete_without_master_key == create_delete_without_master_key and
               other.dir_access_without_auth == dir_access_without_auth and
               other.config_changeable == config_changeable and
               other.master_key_changeable == master_key_changeable;
    }

    bool desfire::key_rights::operator!=(desfire::key_rights const &other) const {
        return not operator==(other);
    }
}// namespace desfire

namespace mlab {

    template <desfire::file_type Type>
    bin_stream &operator>>(bin_stream &s, desfire::file_settings<Type> &fs) {
        if (not s.bad()) {
            s >> static_cast<desfire::common_file_settings &>(fs);
        }
        if (not s.bad()) {
            s >> static_cast<typename desfire::file_settings<Type>::specific_file_settings &>(fs);
        }
        return s;
    }

    template <desfire::file_type Type>
    bin_data &operator<<(bin_data &bd, desfire::file_settings<Type> const &fs) {
        return bd
               << static_cast<desfire::common_file_settings const &>(fs)
               << static_cast<typename desfire::file_settings<Type>::specific_file_settings const &>(fs);
    }
}// namespace mlab

#endif//DESFIRE_DATA_HPP
