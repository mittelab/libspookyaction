//
// Created by Pietro Saccardi on 03/01/2021.
//

#ifndef DESFIRE_DATA_HPP
#define DESFIRE_DATA_HPP

#include "bits.hpp"
#include "crypto_algo.hpp"
#include "key_actor.hpp"
#include <memory>
#include <mlab/any_of.hpp>
#include <mlab/bin_data.hpp>
#include <type_traits>

namespace desfire {
    namespace {
        using mlab::bin_data;
        using mlab::bin_stream;
    }// namespace

    using bits::all_records;
    using bits::app_crypto;
    using bits::cipher_mode;
    using bits::cipher_type;
    using bits::command_code;
    using bits::file_security;
    using bits::file_type;
    using bits::status;

    [[nodiscard]] inline cipher_mode cipher_mode_most_secure(cipher_mode l, cipher_mode r);

    using app_id = std::array<std::uint8_t, bits::app_id_length>;
    using file_id = std::uint8_t;

    static constexpr app_id root_app{0x0, 0x0, 0x0};

    [[nodiscard]] constexpr app_crypto app_crypto_from_cipher(cipher_type c);

    /**
     * @note Misses @ref status::ok, @ref status::no_changes, @ref status::additional_frame. The first two represent
     * success conditions, the latter has to be handled at communication level.
     */
    enum struct error : std::uint8_t {
        out_of_eeprom = static_cast<std::uint8_t>(status::out_of_eeprom),
        illegal_command = static_cast<std::uint8_t>(status::illegal_command),
        integrity_error = static_cast<std::uint8_t>(status::integrity_error),
        no_such_key = static_cast<std::uint8_t>(status::no_such_key),
        length_error = static_cast<std::uint8_t>(status::length_error),
        permission_denied = static_cast<std::uint8_t>(status::permission_denied),
        parameter_error = static_cast<std::uint8_t>(status::parameter_error),
        app_not_found = static_cast<std::uint8_t>(status::app_not_found),
        app_integrity_error = static_cast<std::uint8_t>(status::app_integrity_error),
        authentication_error = static_cast<std::uint8_t>(status::authentication_error),
        boundary_error = static_cast<std::uint8_t>(status::boundary_error),
        picc_integrity_error = static_cast<std::uint8_t>(status::picc_integrity_error),
        command_aborted = static_cast<std::uint8_t>(status::command_aborted),
        picc_disabled_error = static_cast<std::uint8_t>(status::picc_disabled_error),
        count_error = static_cast<std::uint8_t>(status::count_error),
        duplicate_error = static_cast<std::uint8_t>(status::duplicate_error),
        eeprom_error = static_cast<std::uint8_t>(status::eeprom_error),
        file_not_found = static_cast<std::uint8_t>(status::file_not_found),
        file_integrity_error = static_cast<std::uint8_t>(status::file_integrity_error),
        controller_error,///< Specific for PCD error
        malformed,       ///< No data or incorrect data received when some specific format was expected
        crypto_error     /**< @brief Something went wrong with crypto (@ref cipher_mode)
                          *
                          * This could mean invalid MAC, CMAC, or CRC, or data length is not a multiple of block
                          * size when encrypted; this depends on the specified communication config.
                          */
    };

    [[nodiscard]] error error_from_status(status s);
    [[nodiscard]] command_code auth_command(cipher_type t);

    struct same_key_t {};
    static constexpr same_key_t same_key{};

    struct key_rights {
        key_actor<same_key_t> allowed_to_change_keys;

        /**
         * Settings this to false freezes the master key.
         */
        bool master_key_changeable = true;

        /**
         * On an app level, it is possible to list file IDs, get their settings and the key settings.
         * On a PICC level, it is possible to list app IDs and key settings.
         */
        bool dir_access_without_auth = true;

        /**
         * On an app level, this means files can be created or deleted without authentication.
         * On a PICC level, applications can be created without authentication and deleted with their own master keys.
         */
        bool create_delete_without_auth = true;

        /**
         * Setting this to false freezes the configuration of the PICC or the app. Changing still requires to
         * authenticate with the appropriate master key.
         */
        bool config_changeable = true;

        [[nodiscard]] inline bool operator==(desfire::key_rights const &other) const;
        [[nodiscard]] inline bool operator!=(desfire::key_rights const &other) const;
    };

    struct all_keys_t {};
    static constexpr all_keys_t all_keys{};

    enum struct file_access {
        change,
        read,
        write
    };

    struct access_rights {
        key_actor<all_keys_t> change;
        key_actor<all_keys_t> read_write;
        key_actor<all_keys_t> write;
        key_actor<all_keys_t> read;

        constexpr access_rights() = default;
        constexpr access_rights(no_key_t);
        constexpr access_rights(all_keys_t);

        constexpr explicit access_rights(std::uint8_t single_key);
        constexpr access_rights(key_actor<all_keys_t> rw, key_actor<all_keys_t> chg);
        constexpr access_rights(key_actor<all_keys_t> rw, key_actor<all_keys_t> chg, key_actor<all_keys_t> r, key_actor<all_keys_t> w);

        inline void set_word(std::uint16_t v);
        [[nodiscard]] inline std::uint16_t get_word() const;

        [[nodiscard]] inline static access_rights from_word(std::uint16_t word);

        [[nodiscard]] bool is_free(file_access access, std::uint8_t active_key_num) const;
    };

    struct generic_file_settings {
        file_security security = file_security::none;
        access_rights rights;

        constexpr generic_file_settings() = default;
        constexpr generic_file_settings(file_security security_, access_rights rights_);
    };

    struct data_file_settings {
        /**
         * @note This is actually a 24bit value, so the maximum value is 0xffffff. It will be clamped upon trasmission.
         */
        std::uint32_t size;
    };

    struct value_file_settings {
        std::int32_t lower_limit;
        std::int32_t upper_limit;
        /**
         * @note For @ref tag::get_file_settings, this includes the limited credit, if enabled.
         * For the method @ref tag::create_value_file, this is the initial value.
         */
        std::int32_t value;
        bool limited_credit_enabled;
    };

    struct record_file_settings {
        /**
         * @note This is actually a 24bit value, so the maximum value is 0xffffff. It will be clamped upon trasmission.
         */
        std::uint32_t record_size;

        /**
         * @note This is actually a 24bit value, so the maximum value is 0xffffff. It will be clamped upon trasmission.
         */
        std::uint32_t max_record_count;

        /**
         * @note This is actually a 24bit value, so the maximum value is 0xffffff. It will be clamped upon trasmission.
         */
        std::uint32_t record_count;
    };

    template <file_type Type>
    struct file_settings {};

    template <>
    struct file_settings<file_type::standard> : public generic_file_settings, public data_file_settings {
        using specific_file_settings = data_file_settings;
        constexpr file_settings() : generic_file_settings{}, data_file_settings{.size = 0} {}
        constexpr file_settings(generic_file_settings generic, data_file_settings specific) : generic_file_settings{generic}, data_file_settings{specific} {}
    };

    template <>
    struct file_settings<file_type::backup> : public generic_file_settings, public data_file_settings {
        using specific_file_settings = data_file_settings;
        constexpr file_settings() : generic_file_settings{}, data_file_settings{.size = 0} {}
        constexpr file_settings(generic_file_settings generic, data_file_settings specific) : generic_file_settings{generic}, data_file_settings{specific} {}
    };

    template <>
    struct file_settings<file_type::value> : public generic_file_settings, public value_file_settings {
        using specific_file_settings = value_file_settings;
        constexpr file_settings() : generic_file_settings{},
                                    value_file_settings{.lower_limit = 0, .upper_limit = 0, .value = 0, .limited_credit_enabled = false} {}

        constexpr file_settings(generic_file_settings generic, value_file_settings specific) : generic_file_settings{generic}, value_file_settings{specific} {}
    };

    template <>
    struct file_settings<file_type::linear_record> : public generic_file_settings, public record_file_settings {
        using specific_file_settings = record_file_settings;
        constexpr file_settings() : generic_file_settings{},
                                    record_file_settings{.record_size = 0, .max_record_count = 0, .record_count = 0} {}

        constexpr file_settings(generic_file_settings generic, record_file_settings specific) : generic_file_settings{generic}, record_file_settings{specific} {}
    };

    template <>
    struct file_settings<file_type::cyclic_record> : public generic_file_settings, public record_file_settings {
        using specific_file_settings = record_file_settings;
        constexpr file_settings() : generic_file_settings{},
                                    record_file_settings{.record_size = 0, .max_record_count = 0, .record_count = 0} {}

        constexpr file_settings(generic_file_settings generic, record_file_settings specific) : generic_file_settings{generic}, record_file_settings{specific} {}
    };


    class any_file_settings : public mlab::any_of<file_type, file_settings, file_type::standard> {
    public:
        using mlab::any_of<file_type, file_settings, file_type::standard>::any_of;

        [[nodiscard]] generic_file_settings const &generic_settings() const;
        [[nodiscard]] generic_file_settings &generic_settings();
        [[nodiscard]] data_file_settings const &data_settings() const;
        [[nodiscard]] data_file_settings &data_settings();
        [[nodiscard]] record_file_settings const &record_settings() const;
        [[nodiscard]] record_file_settings &record_settings();
        [[nodiscard]] value_file_settings const &value_settings() const;
        [[nodiscard]] value_file_settings &value_settings();
    };

    struct app_settings {
        key_rights rights;
        std::uint8_t max_num_keys;
        app_crypto crypto;

        constexpr explicit app_settings(app_crypto crypto_ = app_crypto::legacy_des_2k3des,
                                        key_rights rights_ = key_rights{},
                                        std::uint8_t max_num_keys_ = bits::max_keys_per_app);

        constexpr explicit app_settings(cipher_type cipher,
                                        key_rights rights_ = key_rights{},
                                        std::uint8_t max_num_keys_ = bits::max_keys_per_app);
    };

    class storage_size {
        std::uint8_t _flag;

        [[nodiscard]] inline unsigned exponent() const;
        [[nodiscard]] inline bool approx() const;

    public:
        explicit storage_size(std::size_t nbytes = 0);

        [[nodiscard]] inline std::size_t bytes_lower_bound() const;
        [[nodiscard]] inline std::size_t bytes_upper_bound() const;

        mlab::bin_stream &operator>>(mlab::bin_stream &s);
        mlab::bin_data &operator<<(mlab::bin_data &s) const;
    };

    struct ware_info {
        std::uint8_t vendor_id = 0;
        std::uint8_t type = 0;
        std::uint8_t subtype = 0;
        std::uint8_t version_major = 0;
        std::uint8_t version_minor = 0;
        storage_size size;
        std::uint8_t comm_protocol_type = 0;
    };

    struct manufacturing_info {
        ware_info hardware;
        ware_info software;
        std::array<std::uint8_t, 7> serial_no{};
        std::array<std::uint8_t, 5> batch_no{};
        std::uint8_t production_week = 0;
        std::uint8_t production_year = 0;
    };

    using random_oracle = void (*)(void *, std::size_t);

    template <cipher_type Cipher>
    struct key {
        static constexpr cipher_type cipher = Cipher;
    };

    class any_key : public mlab::any_of<cipher_type, key, cipher_type::none> {
    public:
        using mlab::any_of<cipher_type, key, cipher_type::none>::any_of;

        any_key() = default;

        template <cipher_type Cipher>
        any_key(key<Cipher> obj);

        any_key(any_key const &other);
        any_key &operator=(any_key const &other);
        any_key(any_key &&other) noexcept = default;
        any_key &operator=(any_key &&other) noexcept = default;

        explicit any_key(cipher_type cipher);
        any_key(cipher_type cipher, mlab::range<std::uint8_t const *> k, std::uint8_t key_no = 0);
        any_key(cipher_type cipher, mlab::range<std::uint8_t const *> k, std::uint8_t key_no, std::uint8_t v);
        any_key(cipher_type cipher, random_oracle rng, std::uint8_t key_no = 0);
        any_key(cipher_type cipher, random_oracle rng, std::uint8_t key_no, std::uint8_t v);

        [[nodiscard]] std::uint8_t key_number() const;
        [[nodiscard]] std::uint8_t version() const;
        [[nodiscard]] mlab::range<std::uint8_t const *> data() const;

        void set_key_number(std::uint8_t v);
        void set_version(std::uint8_t v);
        void set_data(mlab::range<std::uint8_t const *> k);
        void randomize(random_oracle rng);

        [[nodiscard]] any_key with_key_number(std::uint8_t v);

        /**
         * Size in bytes of the key. Does not account for the fact that DES key in Desfire cards are stored as 16 bytes,
         * that is, will return 8 for a DES key.
         */
        [[nodiscard]] std::size_t size() const;

        [[nodiscard]] bool parity_bits_are_version() const;

        /**
         * Does not include version for keys that do not use @ref parity_bits_are_version.
         */
        [[nodiscard]] bin_data get_packed_key_body() const;

        /**
         * @note Assume that keys which do not use parity bits as version will dump the version byte last in a
         * @ref bin_data.
         */
        [[nodiscard]] bin_data xored_with(any_key const &key_to_xor_with) const;

        bin_data &operator<<(bin_data &bd) const;
    };

    template <std::size_t KeyLength, bool ParityBitsAreVersion>
    class key_storage;

    template <std::size_t KeyLength>
    class key_storage<KeyLength, true /* ParityBitsAreVersion */> {
    public:
        static constexpr std::size_t size = KeyLength;
        using key_data = std::array<std::uint8_t, size>;

        [[nodiscard]] inline mlab::range<std::uint8_t const *> as_range() const;

        key_storage() = default;

        inline explicit key_storage(random_oracle rng);
        inline key_storage(random_oracle rng, std::uint8_t v);

        inline explicit key_storage(key_data k);
        inline key_storage(key_data k, std::uint8_t v);

        [[nodiscard]] inline std::uint8_t version() const;
        inline void set_version(std::uint8_t v);

        [[nodiscard]] inline key_data const &data() const;
        inline void set_data(key_data k);

        void randomize(random_oracle rng);

    protected:
        key_data _data{};
    };

    template <std::size_t KeyLength>
    class key_storage<KeyLength, false /* ParityBitsAreVersion */> : private key_storage<KeyLength, true> {
    public:
        using key_data = typename key_storage<KeyLength, true>::key_data;

        using key_storage<KeyLength, true>::size;
        using key_storage<KeyLength, true>::as_range;

        key_storage() = default;

        inline explicit key_storage(random_oracle rng, std::uint8_t v = 0);
        inline explicit key_storage(key_data k, std::uint8_t v = 0);

        // Deliberately shadowing the method.
        [[nodiscard]] inline std::uint8_t version() const;
        inline void set_version(std::uint8_t v);
        void randomize(random_oracle rng);

        using key_storage<KeyLength, true>::data;
        using key_storage<KeyLength, true>::set_data;

    private:
        std::uint8_t _version{};
    };


    template <std::size_t KeyLength, bool ParityBitsAreVersion, class CRTPSubclass>
    class key_base : public key_storage<KeyLength, ParityBitsAreVersion> {
    public:
        using storage = key_storage<KeyLength, ParityBitsAreVersion>;

        static constexpr bool parity_bits_are_version = ParityBitsAreVersion;

        using typename storage::key_data;

        using storage::as_range;
        using storage::data;
        using storage::randomize;
        using storage::set_data;
        using storage::set_version;
        using storage::size;
        using storage::version;

        key_base() = default;
        explicit key_base(random_oracle rng);
        key_base(std::uint8_t key_no, random_oracle rng);
        key_base(std::uint8_t key_no, key_data k);
        key_base(std::uint8_t key_no, random_oracle rng, std::uint8_t v);
        key_base(std::uint8_t key_no, key_data k, std::uint8_t v);

        [[nodiscard]] inline CRTPSubclass with_key_number(std::uint8_t key_no) const;

        [[nodiscard]] inline std::uint8_t key_number() const;
        inline void set_key_number(std::uint8_t key_no);

    private:
        std::uint8_t _key_no{0};
    };

    template <>
    struct key<cipher_type::des> : public key_base<8, true, key<cipher_type::des>> {
        using key_base = key_base<8, true, key<cipher_type::des>>;
        static constexpr cipher_type cipher = cipher_type::des;
        using key_base::data;
        using key_base::key_base;
        using key_base::key_number;
        using key_base::randomize;
        using key_base::set_data;
        using key_base::set_key_number;
        using key_base::set_version;
        using key_base::size;
        using key_base::version;
        using key_base::with_key_number;
    };

    template <>
    struct key<cipher_type::des3_2k> : public key_base<16, true, key<cipher_type::des3_2k>> {
        using key_base = key_base<16, true, key<cipher_type::des3_2k>>;
        static constexpr cipher_type cipher = cipher_type::des3_2k;
        using key_base::data;
        using key_base::key_base;
        using key_base::key_number;
        using key_base::randomize;
        using key_base::set_data;
        using key_base::set_key_number;
        using key_base::set_version;
        using key_base::size;
        using key_base::version;
        using key_base::with_key_number;
    };

    template <>
    struct key<cipher_type::des3_3k> : public key_base<24, true, key<cipher_type::des3_3k>> {
        using key_base = key_base<24, true, key<cipher_type::des3_3k>>;
        static constexpr cipher_type cipher = cipher_type::des3_3k;
        using key_base::data;
        using key_base::key_base;
        using key_base::key_number;
        using key_base::randomize;
        using key_base::set_data;
        using key_base::set_key_number;
        using key_base::set_version;
        using key_base::size;
        using key_base::version;
        using key_base::with_key_number;
    };

    template <>
    struct key<cipher_type::aes128> : public key_base<16, false, key<cipher_type::aes128>> {
        using key_base = key_base<16, false, key<cipher_type::aes128>>;
        static constexpr cipher_type cipher = cipher_type::aes128;
        using key_base::data;
        using key_base::key_base;
        using key_base::key_number;
        using key_base::randomize;
        using key_base::set_data;
        using key_base::set_key_number;
        using key_base::set_version;
        using key_base::size;
        using key_base::version;
        using key_base::with_key_number;
    };

}// namespace desfire

namespace mlab {

    bin_stream &operator>>(bin_stream &s, desfire::key_rights &kr);
    bin_stream &operator>>(bin_stream &s, desfire::app_settings &ks);
    bin_stream &operator>>(bin_stream &s, std::vector<desfire::app_id> &ids);
    bin_stream &operator>>(bin_stream &s, desfire::ware_info &wi);
    bin_stream &operator>>(bin_stream &s, desfire::manufacturing_info &mi);

    bin_stream &operator>>(bin_stream &s, desfire::access_rights &ar);
    bin_stream &operator>>(bin_stream &s, desfire::generic_file_settings &fs);
    bin_stream &operator>>(bin_stream &s, desfire::data_file_settings &fs);
    bin_stream &operator>>(bin_stream &s, desfire::value_file_settings &fs);
    bin_stream &operator>>(bin_stream &s, desfire::record_file_settings &fs);
    bin_stream &operator>>(bin_stream &s, desfire::any_file_settings &fs);

    template <desfire::file_type Type>
    bin_stream &operator>>(bin_stream &s, desfire::file_settings<Type> &fs);

    bin_data &operator<<(bin_data &bd, desfire::key_rights const &kr);
    bin_data &operator<<(bin_data &bd, desfire::app_settings const &ks);
    bin_data &operator<<(bin_data &bd, desfire::any_key const &k);

    bin_data &operator<<(bin_data &bd, desfire::access_rights const &ar);
    bin_data &operator<<(bin_data &bd, desfire::generic_file_settings const &fs);
    bin_data &operator<<(bin_data &bd, desfire::data_file_settings const &fs);
    bin_data &operator<<(bin_data &bd, desfire::value_file_settings const &fs);
    bin_data &operator<<(bin_data &bd, desfire::record_file_settings const &fs);
    bin_data &operator<<(bin_data &bd, desfire::any_file_settings const &fs);

    template <desfire::file_type Type>
    bin_data &operator<<(bin_data &bd, desfire::file_settings<Type> const &fs);
}// namespace mlab

namespace desfire {

    template <std::size_t KeyLength>
    key_storage<KeyLength, false>::key_storage(key_data k, std::uint8_t v) : key_storage<KeyLength, true>{k}, _version{v} {}

    template <std::size_t KeyLength>
    key_storage<KeyLength, false>::key_storage(random_oracle rng, std::uint8_t v) : key_storage<KeyLength, true>{rng}, _version{v} {}

    template <std::size_t KeyLength>
    std::uint8_t key_storage<KeyLength, false>::version() const {
        return _version;
    }

    template <std::size_t KeyLength>
    void key_storage<KeyLength, false>::set_version(std::uint8_t v) {
        _version = v;
    }

    template <std::size_t KeyLength>
    void key_storage<KeyLength, false>::randomize(random_oracle rng) {
        rng(key_storage<KeyLength, true>::_data.data(), key_storage<KeyLength, true>::_data.size());
    }

    template <std::size_t KeyLength>
    mlab::range<std::uint8_t const *> key_storage<KeyLength, true>::as_range() const {
        return mlab::make_range(_data);
    }

    template <std::size_t KeyLength>
    key_storage<KeyLength, true>::key_storage(key_data k) : _data{k} {}

    template <std::size_t KeyLength>
    key_storage<KeyLength, true>::key_storage(random_oracle rng) : key_storage{} {
        rng(_data.data(), _data.size());
    }

    template <std::size_t KeyLength>
    key_storage<KeyLength, true>::key_storage(random_oracle rng, std::uint8_t v) : key_storage{} {
        rng(_data.data(), _data.size());
        set_version(v);
    }

    template <std::size_t KeyLength>
    key_storage<KeyLength, true>::key_storage(key_data k, std::uint8_t v) : _data{k} {
        set_version(v);
    }

    template <std::size_t KeyLength>
    std::uint8_t key_storage<KeyLength, true>::version() const {
        return get_key_version(_data);
    }

    template <std::size_t KeyLength>
    void key_storage<KeyLength, true>::set_version(std::uint8_t v) {
        set_key_version(_data, v);
    }

    template <std::size_t KeyLength>
    void key_storage<KeyLength, true>::randomize(random_oracle rng) {
        const auto v = version();
        rng(_data.data(), _data.size());
        set_version(v);
    }

    template <std::size_t KeyLength>
    typename key_storage<KeyLength, true>::key_data const &key_storage<KeyLength, true>::data() const {
        return _data;
    }

    template <std::size_t KeyLength>
    void key_storage<KeyLength, true>::set_data(key_data k) {
        _data = k;
    }

    template <std::size_t KeyLength, bool ParityBitsAreVersion, class CRTPSubclass>
    key_base<KeyLength, ParityBitsAreVersion, CRTPSubclass>::key_base(std::uint8_t key_no, key_data k_) : storage{k_}, _key_no{key_no} {}

    template <std::size_t KeyLength, bool ParityBitsAreVersion, class CRTPSubclass>
    key_base<KeyLength, ParityBitsAreVersion, CRTPSubclass>::key_base(std::uint8_t key_no, key_data k_, std::uint8_t v_) : storage{k_, v_}, _key_no{key_no} {}

    template <std::size_t KeyLength, bool ParityBitsAreVersion, class CRTPSubclass>
    key_base<KeyLength, ParityBitsAreVersion, CRTPSubclass>::key_base(random_oracle rng) : storage{rng}, _key_no{0} {}

    template <std::size_t KeyLength, bool ParityBitsAreVersion, class CRTPSubclass>
    key_base<KeyLength, ParityBitsAreVersion, CRTPSubclass>::key_base(std::uint8_t key_no, random_oracle rng) : storage{rng}, _key_no{key_no} {}

    template <std::size_t KeyLength, bool ParityBitsAreVersion, class CRTPSubclass>
    key_base<KeyLength, ParityBitsAreVersion, CRTPSubclass>::key_base(std::uint8_t key_no, random_oracle rng, std::uint8_t v) : storage{rng, v}, _key_no{key_no} {}

    template <std::size_t KeyLength, bool ParityBitsAreVersion, class CRTPSubclass>
    CRTPSubclass key_base<KeyLength, ParityBitsAreVersion, CRTPSubclass>::with_key_number(std::uint8_t key_no) const {
        return CRTPSubclass{key_no, data(), version()};
    }

    template <std::size_t KeyLength, bool ParityBitsAreVersion, class CRTPSubclass>
    std::uint8_t key_base<KeyLength, ParityBitsAreVersion, CRTPSubclass>::key_number() const {
        return _key_no;
    }

    template <std::size_t KeyLength, bool ParityBitsAreVersion, class CRTPSubclass>
    void key_base<KeyLength, ParityBitsAreVersion, CRTPSubclass>::set_key_number(std::uint8_t key_no) {
        _key_no = key_no;
    }

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

    cipher_mode cipher_mode_most_secure(cipher_mode l, cipher_mode r) {
        if (l == cipher_mode::ciphered or r == cipher_mode::ciphered) {
            return cipher_mode::ciphered;
        } else if (l == cipher_mode::ciphered_no_crc or r == cipher_mode::ciphered_no_crc) {
            return cipher_mode::ciphered_no_crc;
        } else if (l == cipher_mode::maced or r == cipher_mode::maced) {
            return cipher_mode::maced;
        } else {
            return cipher_mode::plain;
        }
    }

    constexpr access_rights::access_rights(std::uint8_t single_key) : change{single_key}, read_write{single_key}, write{single_key}, read{single_key} {
        // TODO: when C++20 is enabled, used is_constant_evaluated to issue a warning if single_key is out of range
    }

    constexpr access_rights::access_rights(no_key_t) : change{no_key}, read_write{no_key}, write{no_key}, read{no_key} {}

    constexpr access_rights::access_rights(all_keys_t) : change{all_keys}, read_write{all_keys}, write{all_keys}, read{all_keys} {}

    constexpr access_rights::access_rights(key_actor<all_keys_t> rw, key_actor<all_keys_t> chg) : access_rights{no_key} {
        read_write = rw;
        change = chg;
    }

    constexpr access_rights::access_rights(key_actor<all_keys_t> rw, key_actor<all_keys_t> chg, key_actor<all_keys_t> r, key_actor<all_keys_t> w)
        : access_rights{no_key} {
        read_write = rw;
        change = chg;
        read = r;
        write = w;
    }

    std::uint16_t access_rights::get_word() const {
        return (std::uint16_t(read_write.get_nibble()) << bits::file_access_rights_read_write_shift) |
               (std::uint16_t(change.get_nibble()) << bits::file_access_rights_change_shift) |
               (std::uint16_t(read.get_nibble()) << bits::file_access_rights_read_shift) |
               (std::uint16_t(write.get_nibble()) << bits::file_access_rights_write_shift);
    }

    void access_rights::set_word(std::uint16_t v) {
        read_write.set_nibble(std::uint8_t((v >> bits::file_access_rights_read_write_shift) & 0b1111));
        change.set_nibble(std::uint8_t((v >> bits::file_access_rights_change_shift) & 0b1111));
        read.set_nibble(std::uint8_t((v >> bits::file_access_rights_read_shift) & 0b1111));
        write.set_nibble(std::uint8_t((v >> bits::file_access_rights_write_shift) & 0b1111));
    }

    access_rights access_rights::from_word(std::uint16_t word) {
        access_rights retval;
        retval.set_word(word);
        return retval;
    }

    template <cipher_type Cipher>
    any_key::any_key(key<Cipher> obj) : mlab::any_of<cipher_type, key, cipher_type::none>{std::move(obj)} {}

    constexpr generic_file_settings::generic_file_settings(file_security security_, access_rights rights_) : security{security_}, rights{rights_} {}

    constexpr app_crypto app_crypto_from_cipher(cipher_type c) {
        switch (c) {
            case cipher_type::none:
                DESFIRE_LOGE("cipher_type::none cannot be converted to app_crypto!.");
                return app_crypto::legacy_des_2k3des;
            case cipher_type::des:
                [[fallthrough]];
            case cipher_type::des3_2k:
                return app_crypto::legacy_des_2k3des;
            case cipher_type::des3_3k:
                return app_crypto::iso_3k3des;
            case cipher_type::aes128:
                return app_crypto::aes_128;
        }
        return app_crypto::legacy_des_2k3des;
    }

    bool desfire::key_rights::operator==(desfire::key_rights const &other) const {
        return other.allowed_to_change_keys == allowed_to_change_keys and
               other.create_delete_without_auth == create_delete_without_auth and
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
            s >> static_cast<desfire::generic_file_settings &>(fs);
        }
        if (not s.bad()) {
            s >> static_cast<typename desfire::file_settings<Type>::specific_file_settings &>(fs);
        }
        return s;
    }

    template <desfire::file_type Type>
    bin_data &operator<<(bin_data &bd, desfire::file_settings<Type> const &fs) {
        return bd
               << static_cast<desfire::generic_file_settings const &>(fs)
               << static_cast<typename desfire::file_settings<Type>::specific_file_settings const &>(fs);
    }
}// namespace mlab

#endif//DESFIRE_DATA_HPP
