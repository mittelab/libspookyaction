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

namespace desfire {

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

        r<status, bin_data> command_status_response(bin_data &payload, comm_cfg const &cfg);

        inline r<status, bin_data> command_status_response(
                command_code cmd, bin_data const &payload, comm_cfg const &base_cfg);

        /**
         * @param secure_offset Override the secure data offset in TX of @p base_cfg
         *  (@ref comm_cfg::tx_secure_data_offset)
         */
        inline r<status, bin_data> command_status_response(
                command_code cmd, bin_data const &payload, comm_cfg const &base_cfg,
                std::size_t secure_offset);

        /**
         * @param secure_offset Override the secure data offset in TX of @p base_cfg
         *  (@ref comm_cfg::tx_secure_data_offset)
         * @param fetch_additional_frames Override whether new frames will be fetched automatically or not
         *  (@ref comm_cfg::rx_auto_fetch_additional_frames)
         */
        r<status, bin_data> command_status_response(
                command_code cmd, bin_data const &payload, comm_cfg const &base_cfg,
                std::size_t secure_offset, bool fetch_additional_frames);

        /**
         * @addtogroup ReadTillEndCheckStatus
         * Will automatically fetch all additional frames, and at the end will parse the status byte to decide whether
         * the command was successful (@ref status::ok or @ref status::no_changes). These overloads will call the
         * method @ref command_status_response.
         */
        inline r<bin_data> command_response(command_code cmd, bin_data const &payload, comm_cfg const &base_cfg);

        r<bin_data> command_response(
                command_code cmd, bin_data const &payload, comm_cfg const &base_cfg,
                std::size_t secure_offset);
        /**
         * @}
         */

        template <class Data, class = typename std::enable_if<bin_stream::is_extractable<Data>::value>::type>
        r<Data> command_parse_response(command_code cmd, bin_data const &payload, comm_cfg const &base_cfg);

        template <class Data, class = typename std::enable_if<bin_stream::is_extractable<Data>::value>::type>
        r<Data> command_parse_response(command_code cmd, bin_data const &payload, comm_cfg const &base_cfg,
                                       std::size_t secure_offset);

        inline cipher const &active_cipher() const;

        template <cipher_type Type>
        r<> authenticate(key<Type> const &k);
        r<> authenticate(any_key const &k);


        r<> select_application(app_id const &app = root_app);

        void clear_authentication();

    private:
        inline controller &ctrl();
        inline cipher &active_cipher();

        controller *_controller;

        std::unique_ptr<cipher> _active_cipher;
        cipher_type _active_cipher_type;
        std::uint8_t _active_key_number;
    };


    struct tag::comm_cfg {
        cipher::config tx = cipher_cfg_plain;
        cipher::config rx = cipher_cfg_plain;
        std::size_t tx_secure_data_offset = 0;
        bool rx_auto_fetch_additional_frames = true;
        cipher *override_cipher = nullptr;

        inline comm_cfg(comm_mode mode, std::size_t sec_data_ofs = 1, bool fetch_af = true, cipher *custom_c = nullptr);
        inline comm_cfg(cipher::config txrx, std::size_t sec_data_ofs = 1, bool fetch_af = true, cipher *custom_c = nullptr);
        inline comm_cfg(cipher::config tx, cipher::config rx, std::size_t sec_data_ofs = 1, bool fetch_af = true, cipher *custom_c = nullptr);

        inline comm_cfg with(std::size_t new_ofs, bool fetch_af) const;
    };
}

namespace desfire {

    controller & tag::ctrl() {
        return *_controller;
    }

    tag::tag(controller &controller) :
            _controller{&controller},
            _active_cipher{},
            _active_cipher_type{cipher_type::none},
            _active_key_number{std::numeric_limits<std::uint8_t>::max()}
    {
        clear_authentication();
    }

    template <cipher_type Type>
    tag::r<> tag::authenticate(key<Type> const &k) {
        return authenticate(any_key{k});
    }

    cipher const &tag::active_cipher() const {
        return *_active_cipher;
    }

    cipher &tag::active_cipher() {
        return *_active_cipher;
    }

    tag::comm_cfg::comm_cfg(comm_mode mode, std::size_t sec_data_ofs, bool fetch_af, cipher *custom_c) :
        tx{.mode = mode, .do_mac = true, .do_cipher = true, .do_crc = true},
        rx{.mode = mode, .do_mac = true, .do_cipher = true, .do_crc = true},
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

    tag::r<status, bin_data> tag::command_status_response(command_code cmd, bin_data const &payload, tag::comm_cfg const &base_cfg)
    {
        return command_status_response(cmd, payload, base_cfg, base_cfg.tx_secure_data_offset, base_cfg.rx_auto_fetch_additional_frames);
    }
    tag::r<status, bin_data> tag::command_status_response(command_code cmd, bin_data const &payload, tag::comm_cfg const &base_cfg,
                                                std::size_t secure_offset)
    {
        return command_status_response(cmd, payload, base_cfg, secure_offset, base_cfg.rx_auto_fetch_additional_frames);
    }

    tag::r<bin_data> tag::command_response(command_code cmd, bin_data const &payload, tag::comm_cfg const &base_cfg)
    {
        return command_response(cmd, payload, base_cfg, base_cfg.tx_secure_data_offset);
    }

    template <class Data, class>
    tag::r<Data> tag::command_parse_response(command_code cmd, bin_data const &payload, comm_cfg const &base_cfg)
    {
        return command_parse_response<Data>(cmd, payload, base_cfg, base_cfg.tx_secure_data_offset);
    }

    template <class Data, class>
    tag::r<Data> tag::command_parse_response(command_code cmd, bin_data const &payload, comm_cfg const &base_cfg,
                                   std::size_t secure_offset)
    {
        const auto res_cmd = command_response(cmd, payload, base_cfg, secure_offset);
        if (not res_cmd) {
            return res_cmd.error();
        }
        bin_stream s{*res_cmd};
        Data data{};
        s >> data;
        if (s.bad()) {
            /// @todo Log the command being sent
            DESFIRE_LOGE("Could not parse result from response data.");
            return error::malformed;
        }
        return data;
    }
}

#endif //DESFIRE_TAG_HPP
