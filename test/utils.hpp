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

    class nested_log {
        static unsigned _level;
    public:
        inline nested_log() { ++_level; }
        inline ~nested_log() { --_level; }

        static const char *indent();
    };

    void enable_detailed_log();

    struct test_app {
        desfire::app_id aid = {{0xff, 0xff, 0xff}};
        desfire::cipher_type type = desfire::cipher_type::none;
        desfire::any_key primary_key;
        desfire::any_key secondary_key;

        test_app() = default;

        template <desfire::cipher_type Type>
        test_app(desfire::app_id aid_, desfire::key<Type> sec_key) :
            aid{aid_},
            type{Type},
            primary_key{desfire::key<Type>{}},
            secondary_key{std::move(sec_key)}
        {}

        void ensure_selected_and_primary(desfire::tag &tag) const;
        void ensure_created(desfire::tag &tag, desfire::any_key const &root_key) const;
    };

    struct test_file {
        desfire::file_id fid = 0x00;
        desfire::file_type type = desfire::file_type::standard;
        desfire::any_file_settings settings;

        test_file() = default;

        template <desfire::file_type Type>
        test_file(desfire::file_id fid_, desfire::file_settings<Type> settings_) :
            fid{fid_},
            type{Type},
            settings{std::move(settings_)}
        {}

        void delete_preexisting(desfire::tag &tag) const;
    };

    ut::test_app const &get_test_app(desfire::cipher_type t);
    ut::test_file const &get_test_file(desfire::file_type t);
    ut::test_file get_test_file(desfire::file_type t, desfire::comm_mode mode);
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
