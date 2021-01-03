//
// Created by Pietro Saccardi on 02/01/2021.
//

#ifndef DESFIRE_TAG_HPP
#define DESFIRE_TAG_HPP

#include <memory>
#include "mlab/result.hpp"
#include "cipher.hpp"
#include "controller.hpp"

namespace desfire {

    class tag {
    public:
        template <class ...Tn>
        using r = mlab::result<error, Tn...>;

        inline explicit tag(controller &controller);

        tag(tag const &) = delete;

        tag(tag &&) = default;

        tag &operator=(tag const &) = delete;

        tag &operator=(tag &&) = default;

        bool authenticate(any_key const &k);
        void clear_authentication();

        r<bin_data> raw_command_response(bin_data const &payload);
        r<bin_data> command_response(bin_data &payload, std::size_t secure_data_offset, cipher &cipher,
                                     cipher::config const &tx_cfg, cipher::config const &rx_cfg,
                                     bool handle_additional_frames = true);

    private:
        inline controller &ctrl();

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

    tag::tag(controller &controller) : _controller{&controller} {}

}

#endif //DESFIRE_TAG_HPP
