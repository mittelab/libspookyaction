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

    struct demo_app {
        app_id aid;
        cipher_type cipher;
        any_key primary_key;
        any_key secondary_key;

        explicit demo_app(cipher_type c);

        void ensure_selected_and_primary(tag &tag) const;
        void ensure_created(tag &tag, any_key const &root_key) const;
    };
}// namespace ut::desfire

#endif//SPOOKY_ACTION_TEST_DESFIRE_MAIN_HPP
