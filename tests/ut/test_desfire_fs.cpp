//
// Created by spak on 1/7/23.
//

#include "facility.hpp"
#include "helpers.hpp"
#include <catch.hpp>
#include <desfire/esp32/utils.hpp>
#include <desfire/fs.hpp>
#include <esp_random.h>

namespace ut {

    namespace {
        template <bool B, class R>
        [[nodiscard]] bool ok_and(R const &r) {
            return r and *r == B;
        }
    }// namespace


    TEST_CASE("0050 Filesystem") {
        const auto chn = GENERATE(channel_type::hsu, channel_type::i2c, channel_type::i2c_irq, channel_type::spi, channel_type::spi_irq);
        SECTION(to_string(chn)) {
            if (not facility::instance().supports(chn)) {
                SKIP();
            }

            auto ctrl = facility::instance().activate_channel(chn);
            REQUIRE(ctrl);

            auto tag = facility::instance().get_card();
            REQUIRE(tag);

            ensure_card_formatted raii1{tag};

            SECTION("Generic app") {
                REQUIRE(desfire::fs::login_app(*tag, desfire::root_app, ensure_card_formatted::default_root_key()));

                const auto aid = desfire::app_id{0x11, 0x22, 0x33};

                REQUIRE(ok_and<false>(desfire::fs::does_app_exist(*tag, aid)));
                // Root app is not an app!
                REQUIRE(ok_and<false>(desfire::fs::does_app_exist(*tag, desfire::root_app)));

                REQUIRE(desfire::fs::delete_app_if_exists(*tag, aid));

                // Generate a random key
                const auto master_key = desfire::key<desfire::cipher_type::aes128>{0, desfire::random_oracle{esp_fill_random}};

                REQUIRE(desfire::fs::create_app(*tag, aid, master_key, {}));

                // Should fail if the app exists already
                auto suppress = desfire::esp32::suppress_log{DESFIRE_LOG_PREFIX, "DESFIRE-FS"};
                REQUIRE_FALSE(desfire::fs::create_app(*tag, aid, master_key, {}));
                suppress.restore();
                // Should be on the new app
                CHECK(tag->active_app() == aid);

                // So this should fail:
                suppress.suppress();
                REQUIRE_FALSE(desfire::fs::does_app_exist(*tag, aid));
                suppress.restore();

                REQUIRE(desfire::fs::login_app(*tag, desfire::root_app, ensure_card_formatted::default_root_key()));

                REQUIRE(ok_and<true>(desfire::fs::does_app_exist(*tag, aid)));

                // Should be deletable
                REQUIRE(desfire::fs::delete_app_if_exists(*tag, aid));
                REQUIRE(ok_and<false>(desfire::fs::does_app_exist(*tag, aid)));

                REQUIRE(desfire::fs::delete_app_if_exists(*tag, aid));
            }

            SECTION("Read-only app") {
                REQUIRE(desfire::fs::login_app(*tag, desfire::root_app, ensure_card_formatted::default_root_key()));
                const auto aid = desfire::app_id{0x10, 0x20, 0x30};

                const auto r_key = desfire::fs::create_app_for_ro(*tag, desfire::cipher_type::aes128, aid, desfire::random_oracle{esp_fill_random});
                REQUIRE(r_key);

                CHECK(tag->active_app() == aid);
                CHECK(tag->active_cipher_type() == r_key->type());
                CHECK(tag->active_key_no() == r_key->key_number());

                REQUIRE(tag->create_file(0x00, desfire::file_settings<desfire::file_type::value>{
                                                       desfire::file_security::none, desfire::file_access_rights{}, 0, 0, 0}));
                REQUIRE(tag->delete_file(0x00));

                REQUIRE(tag->authenticate(*r_key));
                auto r_app_settings = tag->get_app_settings();

                REQUIRE(r_app_settings);

                // An app that must be turned into read only should check these all
                CHECK(r_app_settings->rights.config_changeable);
                CHECK(not r_app_settings->rights.create_delete_without_master_key);
                CHECK(r_app_settings->rights.dir_access_without_auth);
                CHECK(r_app_settings->rights.master_key_changeable);
                CHECK(r_app_settings->rights.allowed_to_change_keys == r_key->key_number());

                REQUIRE(desfire::fs::make_app_ro(*tag, true));

                REQUIRE(tag->select_application(aid));
                REQUIRE(tag->get_file_ids());

                r_app_settings = tag->get_app_settings();
                REQUIRE(r_app_settings);

                CHECK(not r_app_settings->rights.config_changeable);
                CHECK(not r_app_settings->rights.create_delete_without_master_key);
                CHECK(r_app_settings->rights.dir_access_without_auth);
                CHECK(not r_app_settings->rights.master_key_changeable);
                CHECK(r_app_settings->rights.allowed_to_change_keys == desfire::no_key);

                // The key should still work, but once thrashed...
                REQUIRE(tag->authenticate(*r_key));

                REQUIRE(desfire::fs::login_app(*tag, desfire::root_app, ensure_card_formatted::default_root_key()));
                REQUIRE(desfire::fs::delete_app_if_exists(*tag, aid));
            }

            SECTION("Files") {
                ensure_demo_app raii2{tag, demo_app{desfire::cipher_type::aes128}};
                REQUIRE(desfire::fs::login_app(*tag, raii2.app.aid, raii2.app.master_key));

                const auto fid = desfire::file_id{0x00};

                REQUIRE(ok_and<false>(desfire::fs::does_file_exist(*tag, fid)));

                REQUIRE(desfire::fs::delete_file_if_exists(*tag, fid));

                REQUIRE(tag->create_file(fid, desfire::file_settings<desfire::file_type::standard>{
                                                      desfire::file_security::none, desfire::file_access_rights{}, 1}));

                REQUIRE(ok_and<true>(desfire::fs::does_file_exist(*tag, fid)));

                REQUIRE(desfire::fs::delete_file_if_exists(*tag, fid));

                REQUIRE(ok_and<false>(desfire::fs::does_file_exist(*tag, fid)));
                // Should not fail if run twice
                REQUIRE(ok_and<false>(desfire::fs::does_file_exist(*tag, fid)));

                // Create several
                REQUIRE(tag->create_file(fid + 1, desfire::file_settings<desfire::file_type::standard>{
                                                          desfire::file_security::none, desfire::file_access_rights{}, 1}));
                REQUIRE(tag->create_file(fid + 2, desfire::file_settings<desfire::file_type::standard>{
                                                          desfire::file_security::none, desfire::file_access_rights{}, 1}));

                // Check which of those exists
                auto r_exist = desfire::fs::which_files_exist(*tag, {fid, fid + 1, fid + 3, fid + 2});
                CHECKED_IF_FAIL(r_exist) {
                    CHECK(r_exist->size() == 2);
                    if (not r_exist->empty()) {
                        std::sort(std::begin(*r_exist), std::end(*r_exist));
                        CHECK(r_exist->front() == fid + 1);
                        CHECK(r_exist->back() == fid + 2);
                    }
                }
            }

            SECTION("Read-only data file") {
                ensure_demo_app raii2{tag, demo_app{desfire::cipher_type::aes128}};
                REQUIRE(desfire::fs::login_app(*tag, raii2.app.aid, raii2.app.master_key));

                const auto fid = desfire::file_id{0x00};
                const auto expected_data = mlab::bin_data{{0xf0, 0xf1, 0xf2}};

                REQUIRE(desfire::fs::create_ro_free_data_file(*tag, fid, expected_data));

                auto r_file_settings = tag->get_file_settings(fid);
                REQUIRE(r_file_settings);

                CHECK(r_file_settings->common_settings().security == desfire::file_security::none);
                CHECK(r_file_settings->common_settings().rights.is_free(desfire::file_access::read));
                CHECK(r_file_settings->common_settings().rights.write == desfire::no_key);
                CHECK(r_file_settings->common_settings().rights.read_write == desfire::no_key);
                CHECK(r_file_settings->common_settings().rights.change == desfire::no_key);

                REQUIRE(desfire::fs::logout_app(*tag));

                const auto r_data = tag->read_data(fid, desfire::comm_mode::plain);
                REQUIRE(r_data);

                REQUIRE(*r_data == expected_data);

                // Should fail without authorization
                auto suppress = desfire::esp32::suppress_log{"DESFIRE-FS", DESFIRE_LOG_PREFIX};
                REQUIRE_FALSE(desfire::fs::delete_file_if_exists(*tag, fid));
                suppress.restore();
            }

            SECTION("Read-only value file") {
                ensure_demo_app raii2{tag, demo_app{desfire::cipher_type::aes128}};
                REQUIRE(desfire::fs::login_app(*tag, raii2.app.aid, raii2.app.master_key));

                const auto fid = desfire::file_id{0x00};
                const auto expected_data = std::int32_t{0xbadb007};

                REQUIRE(desfire::fs::create_ro_free_value_file(*tag, fid, expected_data));

                auto r_file_settings = tag->get_file_settings(fid);

                REQUIRE(r_file_settings);

                CHECK(r_file_settings->common_settings().security == desfire::file_security::none);
                CHECK(r_file_settings->common_settings().rights.is_free(desfire::file_access::read));
                CHECK(r_file_settings->common_settings().rights.write == desfire::no_key);
                CHECK(r_file_settings->common_settings().rights.read_write == desfire::no_key);
                CHECK(r_file_settings->common_settings().rights.change == desfire::no_key);

                REQUIRE(desfire::fs::logout_app(*tag));

                const auto r_value = tag->get_value(fid, desfire::comm_mode::plain);
                REQUIRE(r_value);

                CHECK(*r_value == expected_data);

                // Should fail without authorization
                auto suppress = desfire::esp32::suppress_log{"DESFIRE-FS", DESFIRE_LOG_PREFIX};
                REQUIRE_FALSE(desfire::fs::delete_file_if_exists(*tag, fid));
                suppress.restore();
            }
        }
    }

}// namespace ut