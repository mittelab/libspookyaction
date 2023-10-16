//
// Created by spak on 3/18/21.
//

#ifndef SPOOKY_ACTION_TEST_DESFIRE_MAIN_HPP
#define SPOOKY_ACTION_TEST_DESFIRE_MAIN_HPP

#include "test_pn532.hpp"
#include <desfire/tag.hpp>

namespace ut::desfire {
    using namespace ::desfire;

    [[nodiscard]] std::unique_ptr<tag> try_activate_card(pn532::channel &chn, pn532::controller &ctrl);

    template <pn532::channel_type CT>
    struct card_fixture : ut::pn532::channel_fixture<CT> {
        using ut::pn532::channel_fixture<CT>::chn;
        using ut::pn532::channel_fixture<CT>::ctrl;

        std::unique_ptr<tag> mifare = ctrl != nullptr ? try_activate_card(*chn, *ctrl) : nullptr;

        [[nodiscard]] inline explicit operator bool() const override { return chn and ctrl and mifare; }
    };

    struct card_fixture_setup {
        tag &mifare;

        explicit card_fixture_setup(tag &mifare_);
        ~card_fixture_setup();
    };

    struct test_app {
        cipher_type cipher;
        app_id aid;
        any_key master_key;
        any_key secondary_key;

        explicit test_app(cipher_type cipher_);
    };

    struct app_fixture_setup : card_fixture_setup, test_app {
        any_key root_key;

        explicit app_fixture_setup(desfire::tag &mifare_,
                                   cipher_type cipher = cipher_type::aes128,
                                   any_key root_key_ = key<cipher_type::des>{});

        void select_and_authenticate();

        ~app_fixture_setup();
    };
}// namespace ut::desfire

#endif//SPOOKY_ACTION_TEST_DESFIRE_MAIN_HPP
