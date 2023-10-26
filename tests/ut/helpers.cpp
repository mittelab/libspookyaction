//
// Created by spak on 26/10/23.
//

#include "helpers.hpp"
#include <catch.hpp>
#include <desfire/esp32/utils.hpp>
#include <desfire/fs.hpp>
#include <mlab/result_macro.hpp>

#define TAG "UT"

namespace ut {
    using desfire::cipher_type;

    namespace {
        constexpr std::uint8_t secondary_keys_version = 0x10;
        constexpr desfire::key_body<8> secondary_des_key = {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe};
        constexpr desfire::key_body<16> secondary_des3_2k_key = {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e};
        constexpr desfire::key_body<24> secondary_des3_3k_key = {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e, 0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e};
        constexpr desfire::key_body<16> secondary_aes_key = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};


        [[nodiscard]] std::vector<desfire::any_key> get_root_key_candidates() {
            std::vector<desfire::any_key> candidates;
            candidates.emplace_back(ensure_card_formatted::default_root_key());

            for (cipher_type cipher : {cipher_type::des, cipher_type::des3_2k,
                                       cipher_type::des3_3k, cipher_type::aes128}) {
                const demo_app app{cipher};
                // Copy the keys from the test apps
                candidates.emplace_back(app.master_key);
                candidates.emplace_back(app.secondary_key);
            }

            return candidates;
        }

    }// namespace


    [[nodiscard]] desfire::any_key const &ensure_card_formatted::default_root_key() {
        static const desfire::any_key _retval = desfire::key<cipher_type::des>{};
        return _retval;
    }

    [[nodiscard]] std::vector<desfire::any_key> const &ensure_card_formatted::root_key_candidates() {
        static const auto _retval = get_root_key_candidates();
        return _retval;
    }

    demo_app::demo_app(desfire::cipher_type cipher_)
        : cipher{cipher_}, aid{}, master_key{}, secondary_key{} {
        switch (cipher) {
            case cipher_type::des:
                aid = {0x00, 0xde, 0x08};
                master_key = desfire::key<cipher_type::des>{};
                secondary_key = desfire::key<cipher_type::des>{0, secondary_des_key, secondary_keys_version};
                break;
            case cipher_type::des3_2k:
                aid = {0x00, 0xde, 0x16};
                master_key = desfire::key<cipher_type::des3_2k>{};
                secondary_key = desfire::key<cipher_type::des3_2k>{0, secondary_des3_2k_key, secondary_keys_version};
                break;
            case cipher_type::des3_3k:
                aid = {0x00, 0xde, 0x24};
                master_key = desfire::key<cipher_type::des3_3k>{};
                secondary_key = desfire::key<cipher_type::des3_3k>{0, secondary_des3_3k_key, secondary_keys_version};
                break;
            case cipher_type::aes128:
                aid = {0x00, 0xae, 0x16};
                master_key = desfire::key<cipher_type::aes128>{};
                secondary_key = desfire::key<cipher_type::aes128>{0, secondary_aes_key, secondary_keys_version};
                break;
            case cipher_type::none:
                break;
        }
    }


    ensure_card_formatted::ensure_card_formatted(std::shared_ptr<desfire::tag> card_) : card{std::move(card_)} {
        REQUIRE(card);
        REQUIRE(card->select_application(desfire::root_app));
        for (auto const &key : root_key_candidates()) {
            auto suppress = desfire::esp32::suppress_log{DESFIRE_LOG_PREFIX};
            if (card->authenticate(key)) {
                suppress.restore();
                if (key == default_root_key()) {
                    return;
                }
                ESP_LOGW(TAG, "Resetting root key to default.");
                REQUIRE(card->change_key(default_root_key()));
                REQUIRE(card->authenticate(default_root_key()));
                return;
            }
        }
        FAIL("Unable to recover root key for tag.");
    }

    bool ensure_card_formatted::format() {
        if (not card) {
            return false;
        }
        return bool([this]() -> desfire::result<> {
            TRY(card->select_application(desfire::root_app));
            TRY(card->authenticate(default_root_key()));
            ESP_LOGW(TAG, "Formatting card.");
            TRY(card->format_picc());
            return mlab::result_success;
        }());
    }

    ensure_card_formatted::~ensure_card_formatted() {
        REQUIRE(format());
    }
    /*
     *
    app_fixture_setup::app_fixture_setup(desfire::tag &mifare_, cipher_type cipher, any_key root_key_)
        : card_fixture_setup{mifare_}, test_app{cipher}, root_key{std::move(root_key_)} {
        REQUIRE(fs::login_app(mifare, root_app, root_key));
        REQUIRE(fs::delete_app_if_exists(mifare, aid));
        REQUIRE(fs::create_app(mifare, aid, master_key, key_rights{}, 0));
    }

    app_fixture_setup::~app_fixture_setup() {
        REQUIRE(fs::login_app(mifare, root_app, root_key));
        REQUIRE(fs::delete_app_if_exists(mifare, aid));
    }

     */

    bool ensure_demo_app::delete_if_exists() {
        if (not card) {
            return false;
        }
        return bool([this]() -> desfire::result<> {
            TRY(desfire::fs::login_app(*card, desfire::root_app, root_key));
            TRY(desfire::fs::delete_app_if_exists(*card, app.aid));
            return mlab::result_success;
        }());
    }

    ensure_demo_app::ensure_demo_app(std::shared_ptr<desfire::tag> card_, ut::demo_app app_, desfire::any_key root_key_)
        : card{std::move(card_)},
          root_key{std::move(root_key_)},
          app{std::move(app_)} {
        REQUIRE(delete_if_exists());
        REQUIRE(desfire::fs::create_app(*card, app.aid, app.master_key, desfire::key_rights{}, 0));
    }

    ensure_demo_app::~ensure_demo_app() {
        REQUIRE(delete_if_exists());
    }

}// namespace ut