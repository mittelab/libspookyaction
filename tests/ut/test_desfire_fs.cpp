//
// Created by spak on 1/7/23.
//

#include "test_desfire_main.hpp"
#include <desfire/esp32/utils.hpp>
#include <desfire/fs.hpp>
#include <esp_random.h>

namespace ut::fs {
    using namespace ut::desfire;
    using namespace ut::pn532;
    using namespace desfire::fs;
    using namespace desfire::esp32;

    namespace {
        template <bool B, class R>
        [[nodiscard]] bool ok_and(R const &r) {
            return r and *r == B;
        }
    }// namespace


    TEMPLATE_TEST_CASE_METHOD_SIG(card_fixture, "0051 FS test RO app", "",
                                  ((channel_type CT), CT),
                                  channel_type::hsu, channel_type::i2c, channel_type::i2c_irq, channel_type::spi, channel_type::spi_irq) {
        if (not status::instance().supports(CT)) {
            SKIP("Unsupported channel type " << ut::pn532::to_string(CT));
        }

        REQUIRE(*this);
        card_fixture_setup fmt{*this->mifare};

        REQUIRE(login_app(*this->mifare, root_app, key<cipher_type::des>{}));
        const auto aid = app_id{0x10, 0x20, 0x30};

        const auto r_key = create_app_for_ro(*this->mifare, cipher_type::aes128, aid, random_oracle{esp_fill_random});
        REQUIRE(r_key);

        CHECK(this->mifare->active_app() == aid);
        CHECK(this->mifare->active_cipher_type() == r_key->type());
        CHECK(this->mifare->active_key_no() == r_key->key_number());

        REQUIRE(this->mifare->create_file(0x00, file_settings<file_type::value>{file_security::none, file_access_rights{}, 0, 0, 0}));
        REQUIRE(this->mifare->delete_file(0x00));

        REQUIRE(this->mifare->authenticate(*r_key));
        auto r_app_settings = this->mifare->get_app_settings();

        REQUIRE(r_app_settings);

        // An app that must be turned into read only should check these all
        CHECK(r_app_settings->rights.config_changeable);
        CHECK(not r_app_settings->rights.create_delete_without_master_key);
        CHECK(r_app_settings->rights.dir_access_without_auth);
        CHECK(r_app_settings->rights.master_key_changeable);
        CHECK(r_app_settings->rights.allowed_to_change_keys == r_key->key_number());

        REQUIRE(make_app_ro(*this->mifare, true));

        REQUIRE(this->mifare->select_application(aid));
        REQUIRE(this->mifare->get_file_ids());

        r_app_settings = this->mifare->get_app_settings();
        REQUIRE(r_app_settings);

        CHECK(not r_app_settings->rights.config_changeable);
        CHECK(not r_app_settings->rights.create_delete_without_master_key);
        CHECK(r_app_settings->rights.dir_access_without_auth);
        CHECK(not r_app_settings->rights.master_key_changeable);
        CHECK(r_app_settings->rights.allowed_to_change_keys == no_key);

        // The key should still work, but once thrashed...
        REQUIRE(this->mifare->authenticate(*r_key));

        REQUIRE(login_app(*this->mifare, root_app, key<cipher_type::des>{}));
        REQUIRE(delete_app_if_exists(*this->mifare, aid));
    }

    TEMPLATE_TEST_CASE_METHOD_SIG(card_fixture, "0050 FS test app", "",
                                  ((channel_type CT), CT),
                                  channel_type::hsu, channel_type::i2c, channel_type::i2c_irq, channel_type::spi, channel_type::spi_irq) {
        if (not status::instance().supports(CT)) {
            SKIP("Unsupported channel type " << ut::pn532::to_string(CT));
        }

        REQUIRE(*this);
        card_fixture_setup fmt{*this->mifare};

        REQUIRE(this->mifare->authenticate(key<cipher_type::des>{}));

        const auto aid = app_id{0x11, 0x22, 0x33};

        REQUIRE(ok_and<false>(does_app_exist(*this->mifare, aid)));
        // Root app is not an app!
        REQUIRE(ok_and<false>(does_app_exist(*this->mifare, root_app)));

        REQUIRE(delete_app_if_exists(*this->mifare, aid));

        // Generate a random key
        const auto master_key = key<cipher_type::aes128>{0, random_oracle{esp_fill_random}};

        REQUIRE(create_app(*this->mifare, aid, master_key, {}));

        // Should fail if the app exists already
        auto suppress = suppress_log{DESFIRE_LOG_PREFIX, "DESFIRE-FS"};
        REQUIRE_FALSE(create_app(*this->mifare, aid, master_key, {}));
        suppress.restore();
        // Should be on the new app
        CHECK(this->mifare->active_app() == aid);

        // So this should fail:
        suppress.suppress();
        REQUIRE_FALSE(does_app_exist(*this->mifare, aid));
        suppress.restore();

        REQUIRE(login_app(*this->mifare, root_app, key<cipher_type::des>{}));

        REQUIRE(ok_and<true>(does_app_exist(*this->mifare, aid)));

        // Should be deletable
        REQUIRE(delete_app_if_exists(*this->mifare, aid));
        REQUIRE(ok_and<false>(does_app_exist(*this->mifare, aid)));

        REQUIRE(delete_app_if_exists(*this->mifare, aid));
    }

    TEMPLATE_TEST_CASE_METHOD_SIG(card_fixture, "0052 FS test file", "",
                                  ((channel_type CT), CT),
                                  channel_type::hsu, channel_type::i2c, channel_type::i2c_irq, channel_type::spi, channel_type::spi_irq) {
        if (not status::instance().supports(CT)) {
            SKIP("Unsupported channel type " << ut::pn532::to_string(CT));
        }

        REQUIRE(*this);
        // Create a temp app which will auto-delete
        app_fixture_setup fmt{*this->mifare};

        const auto fid = file_id{0x00};

        REQUIRE(ok_and<false>(does_file_exist(*this->mifare, fid)));

        REQUIRE(delete_file_if_exists(*this->mifare, fid));

        REQUIRE(this->mifare->create_file(fid, file_settings<file_type::standard>{file_security::none, file_access_rights{}, 1}));

        REQUIRE(ok_and<true>(does_file_exist(*this->mifare, fid)));

        REQUIRE(delete_file_if_exists(*this->mifare, fid));

        REQUIRE(ok_and<false>(does_file_exist(*this->mifare, fid)));
        // Should not fail if run twice
        REQUIRE(ok_and<false>(does_file_exist(*this->mifare, fid)));

        // Create several
        REQUIRE(this->mifare->create_file(fid + 1, file_settings<file_type::standard>{file_security::none, file_access_rights{}, 1}));
        REQUIRE(this->mifare->create_file(fid + 2, file_settings<file_type::standard>{file_security::none, file_access_rights{}, 1}));

        // Check which of those exists
        auto r_exist = which_files_exist(*this->mifare, {fid, fid + 1, fid + 3, fid + 2});
        CHECKED_IF_FAIL(r_exist) {
            CHECK(r_exist->size() == 2);
            if (not r_exist->empty()) {
                std::sort(std::begin(*r_exist), std::end(*r_exist));
                CHECK(r_exist->front() == fid + 1);
                CHECK(r_exist->back() == fid + 2);
            }
        }
    }

    TEMPLATE_TEST_CASE_METHOD_SIG(card_fixture, "0053 FS test RO data file", "",
                                  ((channel_type CT), CT),
                                  channel_type::hsu, channel_type::i2c, channel_type::i2c_irq, channel_type::spi, channel_type::spi_irq) {
        if (not status::instance().supports(CT)) {
            SKIP("Unsupported channel type " << ut::pn532::to_string(CT));
        }

        REQUIRE(*this);

        // Create a temp app which will auto-delete
        app_fixture_setup fmt{*this->mifare};

        const auto fid = file_id{0x00};
        const auto expected_data = bin_data{{0xf0, 0xf1, 0xf2}};

        REQUIRE(create_ro_free_data_file(*this->mifare, fid, expected_data));

        auto r_file_settings = this->mifare->get_file_settings(fid);
        REQUIRE(r_file_settings);

        CHECK(r_file_settings->common_settings().security == file_security::none);
        CHECK(r_file_settings->common_settings().rights.is_free(file_access::read));
        CHECK(r_file_settings->common_settings().rights.write == no_key);
        CHECK(r_file_settings->common_settings().rights.read_write == no_key);
        CHECK(r_file_settings->common_settings().rights.change == no_key);

        REQUIRE(logout_app(*this->mifare));

        const auto r_data = this->mifare->read_data(fid, comm_mode::plain);
        REQUIRE(r_data);

        REQUIRE(*r_data == expected_data);

        // Should fail without authorization
        auto suppress = suppress_log{"DESFIRE-FS", DESFIRE_LOG_PREFIX};
        REQUIRE_FALSE(delete_file_if_exists(*this->mifare, fid));
        suppress.restore();
    }


    TEMPLATE_TEST_CASE_METHOD_SIG(card_fixture, "0054 FS test RO value file", "",
                                  ((channel_type CT), CT),
                                  channel_type::hsu, channel_type::i2c, channel_type::i2c_irq, channel_type::spi, channel_type::spi_irq) {
        if (not status::instance().supports(CT)) {
            SKIP("Unsupported channel type " << ut::pn532::to_string(CT));
        }

        REQUIRE(*this);
        // Create a temp app which will auto-delete
        app_fixture_setup fmt{*this->mifare};

        const auto fid = file_id{0x00};
        const auto expected_data = std::int32_t{0xbadb007};

        REQUIRE(create_ro_free_value_file(*this->mifare, fid, expected_data));

        auto r_file_settings = this->mifare->get_file_settings(fid);

        REQUIRE(r_file_settings);

        CHECK(r_file_settings->common_settings().security == file_security::none);
        CHECK(r_file_settings->common_settings().rights.is_free(file_access::read));
        CHECK(r_file_settings->common_settings().rights.write == no_key);
        CHECK(r_file_settings->common_settings().rights.read_write == no_key);
        CHECK(r_file_settings->common_settings().rights.change == no_key);

        REQUIRE(logout_app(*this->mifare));

        const auto r_value = this->mifare->get_value(fid, comm_mode::plain);
        REQUIRE(r_value);

        CHECK(*r_value == expected_data);

        // Should fail without authorization
        auto suppress = suppress_log{"DESFIRE-FS", DESFIRE_LOG_PREFIX};
        REQUIRE_FALSE(delete_file_if_exists(*this->mifare, fid));
        suppress.restore();
    }

}// namespace ut::fs