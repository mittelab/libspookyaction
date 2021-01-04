//
// Created by Pietro Saccardi on 02/01/2021.
//

#ifndef DESFIRE_TAG_HPP
#define DESFIRE_TAG_HPP

#include <memory>
#include "mlab/result.hpp"
#include "cipher.hpp"
#include "controller.hpp"
#include "data.hpp"

namespace desfire {

    class tag {
    public:

        struct tx_config;
        struct rx_config;

        template <class ...Tn>
        using r = mlab::result<error, Tn...>;

        inline explicit tag(controller &controller);

        tag(tag const &) = delete;

        tag(tag &&) = default;

        tag &operator=(tag const &) = delete;

        tag &operator=(tag &&) = default;

        inline cipher const &active_cipher() const;

        template <cipher_type Type>
        r<> authenticate(key<Type> const &k);
        r<> authenticate(any_key const &k);

        r<> select_application(std::array<std::uint8_t, 3> const &aid);

        void clear_authentication();

        r<bin_data> raw_command_response(bin_data const &payload, bool rotate_status);

        r<status, bin_data> command_status_response(bin_data &payload, cipher &cipher,
                                     cipher::config const &tx_cfg, cipher::config const &rx_cfg,
                                     std::size_t secure_data_offset, bool fetch_additional_frames);

        r<bin_data> command_response(bin_data &payload, cipher &cipher,
                                     cipher::config const &tx_cfg, cipher::config const &rx_cfg,
                                     std::size_t secure_data_offset, bool fetch_additional_frames);
    private:
        inline controller &ctrl();
        inline cipher &active_cipher();

        controller *_controller;

        std::unique_ptr<cipher> _active_cipher;
        cipher_type _active_cipher_type;
        std::uint8_t _active_key_number;


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
}

#endif //DESFIRE_TAG_HPP
