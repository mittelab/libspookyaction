//
// Created by spak on 2/7/21.
//

#ifndef KEYCARD_ACCESS_UTILS_HPP
#define KEYCARD_ACCESS_UTILS_HPP

#include <list>
#include <desfire/controller.hpp>
#include <desfire/tag.hpp>

namespace ut {

    struct assert_comm_controller final : public desfire::controller {
        std::list<std::pair<mlab::bin_data, mlab::bin_data>> txrx_fifo;

        std::pair<mlab::bin_data, bool> communicate(mlab::bin_data const &data) override;

        void append(std::initializer_list<std::uint8_t> tx, std::initializer_list<std::uint8_t> rx);

    };

    struct session {
        desfire::tag &tag;

        template <desfire::cipher_type Cipher>
        inline session(desfire::tag &tag_, desfire::key<Cipher> const &session_key, desfire::app_id app, std::uint8_t key_no);

        inline ~session();
    };

    void enable_detailed_log();
}

namespace ut {

    template <desfire::cipher_type Cipher>
    session::session(desfire::tag &tag_, desfire::key<Cipher> const &session_key, desfire::app_id app, std::uint8_t key_no) :
            tag{tag_}
    {
        tag.template ut_init_session(session_key, app, key_no);
    }

    session::~session() {
        tag.logout(false);
    }
}

#endif //KEYCARD_ACCESS_UTILS_HPP
