//
// Created by Pietro Saccardi on 02/01/2021.
//

#ifndef DESFIRE_TAG_HPP
#define DESFIRE_TAG_HPP

#include <memory>
#include <list>
#include "mlab/result.hpp"
#include "cipher.hpp"
#include "controller.hpp"
#include "data.hpp"
#include "msg.hpp"


namespace ut {
    struct session;
}

namespace desfire {

    enum struct file_security : std::uint8_t {
        none = static_cast<std::uint8_t>(comm_mode::plain),
        cipher = static_cast<std::uint8_t>(comm_mode::cipher),
        mac = static_cast<std::uint8_t>(comm_mode::mac),
        automatic,     ///< Will determine the appropriate mode based on access rights
        plain = none   ///< Alias for @ref file_security::none
    };

    inline comm_mode comm_mode_from_security(file_security security);

    class tag {
    public:

        struct comm_cfg;

        template <class ...Tn>
        using r = mlab::result<error, Tn...>;

        inline explicit tag(controller &controller);

        tag(tag const &) = delete;

        tag(tag &&) = default;

        tag &operator=(tag const &) = delete;

        tag &operator=(tag &&) = default;

        r<bin_data> raw_command_response(bin_data const &payload);

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
         */
        r<status, bin_data> command_status_response(command_code cmd, bin_stream &data, comm_cfg const &cfg);
        r<status, bin_data> command_status_response(command_code cmd, bin_data const &data, comm_cfg const &cfg);

        /**
         * Will automatically fetch all additional frames if requested to do so by @p cfg, and at the end will parse the
         * status byte to decide whether the command was successful (@ref status::ok or @ref status::no_changes).
         */
        r<bin_data> command_response(command_code cmd, bin_data const &payload, comm_cfg const &cfg);

        template <class Data, class = typename std::enable_if<bin_stream::is_extractable<Data>::value>::type>
        r<Data> command_parse_response(command_code cmd, bin_data const &payload, comm_cfg const &cfg);

        /**
         * @return Always returns something but it may be @ref cipher_dummy if no authentication has took place.
         */
        inline cipher const &active_cipher() const;

        /**
         * @return @ref root_app if no app was selected, otherwise the app id.
         * @todo Make sure active_app is always in sync
         */
        inline app_id const &active_app() const;

        /**
         * @todo Rename this to active_key_type
         */
        inline cipher_type active_cipher_type() const;

        /**
         * @return ''std::numeric_limits<std::uint8_t>::max'' when no authentication has took place, the the key number.
         */
        inline std::uint8_t active_key_no() const;

        template <cipher_type Type>
        r<> authenticate(key<Type> const &k);
        r<> authenticate(any_key const &k);

        /**
         * @note After selecting a new application, the controller is logged out and a new authentication is necessary.
         */
        r<> select_application(app_id const &app = root_app);

        /**
         * @note Must be on the @ref root_app for this to succeed.
         */
        r<> create_application(app_id const &new_app_id, key_settings settings);

        r<> change_key_settings(key_rights new_rights);

        r<key_settings> get_key_settings();

        r<std::uint8_t> get_key_version(std::uint8_t key_num);

        /**
         * @note Must be on the @ref root_app, possibly authenticated.
         */
        r<std::vector<app_id>> get_application_ids();

        /**
         * @note Must be on the @ref root_app or in @p app, with the appropriate master key.
         */
        r<> delete_application(app_id const &app);


        r<manufacturing_info> get_info();


        /**
         * @note Must be on the @ref root_app for this to succeed, and authenticated with the master key. After
         * formatting the controller will be logged out and on the @ref root_app.
         */
        r<> format_picc();

        /**
         * @note Assumes authentication has happened and the key settings allow the change.
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

        r<std::vector<file_id>> get_file_ids();

        r<any_file_settings> get_file_settings(file_id fid);

        template <file_type Type>
        r<file_settings<Type>> get_specific_file_settings(file_id fid);

        r<> change_file_settings(file_id fid, generic_file_settings const &settings, file_security security = file_security::automatic);

        /**
         * @param fid Max @ref bits::max_standard_data_file_id.
         */
        r<> create_file(file_id fid, file_settings<file_type::standard> const &settings);

        r<> create_file(file_id fid, any_file_settings const &settings);

        /**
         * @param fid Max @ref bits::max_backup_data_file_id.
         */
        r<> create_file(file_id fid, file_settings<file_type::backup> const &settings);

        /**
         * @param fid Max @ref bits::max_value_file_id.
         * @param settings Must have @ref value_file_settings::upper_limit greater than or equal to
         *  @ref value_file_settings::lower_limit.
         */
        r<> create_file(file_id fid, file_settings<file_type::value> const &settings);

        /**
         * @param fid Max @ref bits::max_record_file_id.
         * @param settings Must have @ref record_file_settings::record_size > 0 and
         *  @ref record_file_settings::max_record_count > 0.
         */
        r<> create_file(file_id fid, file_settings<file_type::linear_record> const &settings);

        /**
         * @param fid Max @ref bits::max_record_file_id.
         * @param settings Must have @ref record_file_settings::record_size > 0 and
         *  @ref record_file_settings::max_record_count > 1 (at least 2).
         */
        r<> create_file(file_id fid, file_settings<file_type::cyclic_record> const &settings);

        r<> delete_file(file_id fid);

        /**
         * @param fid Max @ref bits::max_record_file_id.
         */
        r<> clear_record_file(file_id fid);

        r<> commit_transaction();
        r<> abort_transaction();

        /**
         *
         * @param offset Limited to 24 bits, i.e. must be below 0xFFFFFF.
         * @param length Limited to 24 bits, i.e. must be below 0xFFFFFF.
         */
        r<bin_data> read_data(file_id fid, std::uint32_t offset, std::uint32_t length, file_security security = file_security::automatic);

        /**
         *
         * @param offset Limited to 24 bits, i.e. must be below 0xFFFFFF.
         * @param data Limited to 24 bits, i.e. must be below 0xFFFFFF.
         */
        r<> write_data(file_id fid, std::uint32_t offset, bin_data const &data, file_security = file_security::automatic);

    private:
        /**
         * The power of friendship, cit. Wifasoi, 2020
         */
        friend struct ut::session;

        /**
         * Simulate a new session without the @ref authenticate random component
         */
        template <cipher_type Cipher>
        void ut_init_session(desfire::key<Cipher> const &session_key, desfire::app_id app, std::uint8_t key_no);

        r<comm_mode> determine_file_comm_mode(file_id fid, file_access access, file_security requested_security);

        inline controller &ctrl();
        inline cipher &active_cipher();
        r<> change_key_internal(any_key const *current_key, std::uint8_t key_no_to_change, any_key const &new_key);

        /**
         * Clears data __locally__ (i.e. it may be out of sync with the card if not called at the right time).
         */
        void logout(bool due_to_error);

        struct auto_logout;


        controller *_controller;

        std::unique_ptr<cipher> _active_cipher;
        cipher_type _active_cipher_type;
        std::uint8_t _active_key_number;
        app_id _active_app;
    };


    struct tag::comm_cfg {
        cipher::config tx = cipher_cfg_plain;
        cipher::config rx = cipher_cfg_plain;
        std::size_t tx_secure_data_offset = 0;
        bool rx_auto_fetch_additional_frames = true;
        cipher *override_cipher = nullptr;

        inline comm_cfg(comm_mode txrx, std::size_t sec_data_ofs = 1, bool fetch_af = true, cipher *custom_c = nullptr);
        inline comm_cfg(cipher::config txrx, std::size_t sec_data_ofs = 1, bool fetch_af = true, cipher *custom_c = nullptr);
        inline comm_cfg(comm_mode tx, comm_mode rx, std::size_t sec_data_ofs = 1, bool fetch_af = true, cipher *custom_c = nullptr);
        inline comm_cfg(cipher::config tx, cipher::config rx, std::size_t sec_data_ofs = 1, bool fetch_af = true, cipher *custom_c = nullptr);

        inline comm_cfg with(std::size_t new_ofs, bool fetch_af) const;
    };
}

namespace desfire {

    comm_mode comm_mode_from_security(file_security security) {
        if (security == file_security::automatic) {
            DESFIRE_LOGE("Cannot convert file_security::automatic to comm_mode. Data will be transmitted plain!");
            return comm_mode::plain;
        }
        return static_cast<comm_mode>(security);
    }

    controller & tag::ctrl() {
        return *_controller;
    }

    tag::tag(controller &controller) :
            _controller{&controller},
            _active_cipher{new cipher_dummy{}},
            _active_cipher_type{cipher_type::none},
            _active_key_number{std::numeric_limits<std::uint8_t>::max()},
            _active_app{root_app}
    {}

    template <cipher_type Type>
    tag::r<> tag::authenticate(key<Type> const &k) {
        return authenticate(any_key{k});
    }
    template <cipher_type Type>
    tag::r<> tag::change_key(key<Type> const &new_key)
    {
        return change_key(any_key{new_key});
    }

    template <cipher_type Type1, cipher_type Type2>
    tag::r<> tag::change_key(key<Type1> const &current_key, std::uint8_t key_no_to_change, key<Type2> const &new_key)
    {
        return change_key(any_key{current_key}, key_no_to_change, any_key{new_key});
    }


    cipher const &tag::active_cipher() const {
        return *_active_cipher;
    }

    cipher &tag::active_cipher() {
        return *_active_cipher;
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

    tag::comm_cfg::comm_cfg(comm_mode txrx, std::size_t sec_data_ofs, bool fetch_af, cipher *custom_c) :
        tx{.mode = txrx, .do_mac = true, .do_cipher = true, .do_crc = true},
        rx{.mode = txrx, .do_mac = true, .do_cipher = true, .do_crc = true},
        tx_secure_data_offset{sec_data_ofs},
        rx_auto_fetch_additional_frames{fetch_af},
        override_cipher{custom_c}
    {}

    tag::comm_cfg::comm_cfg(cipher::config txrx, std::size_t sec_data_ofs, bool fetch_af, cipher *custom_c) :
            tx{txrx},
            rx{txrx},
            tx_secure_data_offset{sec_data_ofs},
            rx_auto_fetch_additional_frames{fetch_af},
            override_cipher{custom_c}
    {}

    tag::comm_cfg::comm_cfg(comm_mode tx, comm_mode rx, std::size_t sec_data_ofs, bool fetch_af, cipher *custom_c) :
            tx{.mode = tx, .do_mac = true, .do_cipher = true, .do_crc = true},
            rx{.mode = rx, .do_mac = true, .do_cipher = true, .do_crc = true},
            tx_secure_data_offset{sec_data_ofs},
            rx_auto_fetch_additional_frames{fetch_af},
            override_cipher{custom_c}
    {}

    tag::comm_cfg::comm_cfg(cipher::config tx, cipher::config rx, std::size_t sec_data_ofs, bool fetch_af, cipher *custom_c) :
            tx{tx},
            rx{rx},
            tx_secure_data_offset{sec_data_ofs},
            rx_auto_fetch_additional_frames{fetch_af},
            override_cipher{custom_c}
    {}

    tag::comm_cfg tag::comm_cfg::with(std::size_t new_ofs, bool fetch_af) const {
        comm_cfg copy = *this;
        copy.tx_secure_data_offset = new_ofs;
        copy.rx_auto_fetch_additional_frames = fetch_af;
        return copy;
    }

    template <class Data, class>
    tag::r<Data> tag::command_parse_response(command_code cmd, bin_data const &payload, comm_cfg const &cfg)
    {
        const auto res_cmd = command_response(cmd, payload, cfg);
        if (not res_cmd) {
            return res_cmd.error();
        }
        bin_stream s{*res_cmd};
        Data data{};
        s >> data;
        if (s.bad()) {
            DESFIRE_LOGE("%s: could not parse result from response data.", to_string(cmd));
            return error::malformed;
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
        auto res_cmd = get_file_settings(fid);
        if (res_cmd) {
            // Assert the file type is correct
            if (res_cmd->type() != Type) {
                return error::malformed;
            }
            return std::move(res_cmd->template get_settings<Type>());
        }
        return res_cmd.error();
    }

}

#endif //DESFIRE_TAG_HPP
