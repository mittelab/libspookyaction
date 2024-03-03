//
// Created by spak on 3/18/21.
//

#include "facility.hpp"
#include "helpers.hpp"
#include <catch.hpp>
#include <desfire/fs.hpp>

#define TAG "UT"

namespace ut {
    using namespace mlab_literals;

    TEST_CASE("0030 DESFire") {
        const auto chn = GENERATE(channel_type::hsu, channel_type::i2c, channel_type::i2c_irq, channel_type::spi, channel_type::spi_irq);
        SECTION(to_string(chn)) {
            if (not facility::instance().supports(chn)) {
                SKIP();
            }

            auto ctrl = facility::instance().activate_channel(chn);
            REQUIRE(ctrl);

            auto tag = facility::instance().get_card();
            REQUIRE(tag);

            ensure_card_formatted raii{tag};

            SECTION("Base test") {
                REQUIRE(desfire::fs::login_app(*tag, desfire::root_app, ensure_card_formatted::default_root_key()));

                auto r_settings = tag->get_app_settings();
                REQUIRE(r_settings);
                r_settings->rights.dir_access_without_auth = true;
                r_settings->rights.create_delete_without_master_key = false;

                REQUIRE(tag->change_app_settings(r_settings->rights));

                const auto r_info = tag->get_info();
                CHECKED_IF_FAIL(r_info) {
                    ESP_LOGI(TAG, "Card info:");
                    ESP_LOGI(TAG, "    vendor id: %02x", r_info->hardware.vendor_id);
                    ESP_LOGI(TAG, "   hw version: %d.%d", r_info->hardware.version_major, r_info->hardware.version_minor);
                    ESP_LOGI(TAG, "   sw version: %d.%d", r_info->software.version_major, r_info->software.version_minor);
                    ESP_LOGI(TAG, "  storage [B]: %s%u",
                             (r_info->hardware.size.bytes_upper_bound() > r_info->hardware.size.bytes_lower_bound() ? "> " : ""),
                             r_info->hardware.size.bytes_lower_bound());
                    ESP_LOGI(TAG, "    serial no: %02x %02x %02x %02x %02x %02x %02x",
                             r_info->serial_no[0], r_info->serial_no[1], r_info->serial_no[2], r_info->serial_no[3],
                             r_info->serial_no[4], r_info->serial_no[5], r_info->serial_no[6]);
                    ESP_LOGI(TAG, "     batch no: %02x %02x %02x %02x %02x",
                             r_info->batch_no[0], r_info->batch_no[1], r_info->batch_no[2], r_info->batch_no[3], r_info->batch_no[4]);
                    ESP_LOGI(TAG, "   production: %02x %02x -> year %02u, week %u", r_info->production_week,
                             r_info->production_year, r_info->production_year, r_info->production_week);

                    // Re-login before requesting the card UID
                    REQUIRE(desfire::fs::login_app(*tag, desfire::root_app, ensure_card_formatted::default_root_key()));

                    const auto r_get_uid = tag->get_card_uid();
                    CHECKED_IF_FAIL(r_get_uid) {
                        CHECK(r_info->serial_no == *r_get_uid);
                    }
                }

                const auto r_mem = tag->get_free_mem();
                CHECKED_IF_FAIL(r_mem) {
                    ESP_LOGI(TAG, " free mem [B]: %lu", *r_mem);
                }
            }

            SECTION("Root-level ops") {
                REQUIRE(desfire::fs::login_app(*tag, desfire::root_app, ensure_card_formatted::default_root_key()));

                const desfire::app_id test_app_id = {0x00, 0x7e, 0x57};

                ESP_LOGI(TAG, "Begin key test cycle.");
                for (auto const &key : ensure_card_formatted::root_key_candidates()) {
                    REQUIRE(tag->change_key(key));
                    ESP_LOGI(TAG, "Changed root key to %s, testing root level ops.", to_string(key.type()));
                    REQUIRE(tag->authenticate(key));
                    // Do a bunch of operations on applications that can only be done at the root level, so that we can verify the
                    // trasmission modes for the root level app
                    auto r_list = tag->get_application_ids();
                    CHECKED_IF_FAIL(r_list) {
                        if (std::find(std::begin(*r_list), std::end(*r_list), test_app_id) != std::end(*r_list)) {
                            // Remove preexisting app
                            REQUIRE(tag->delete_application(test_app_id));
                        }
                    }
                    REQUIRE(tag->create_application(test_app_id, desfire::app_settings{}));
                    r_list = tag->get_application_ids();
                    CHECKED_IF_FAIL(r_list) {
                        CHECKED_IF_FAIL(not r_list->empty()) {
                            REQUIRE(std::find(std::begin(*r_list), std::end(*r_list), test_app_id) != std::end(*r_list));
                        }
                    }
                    REQUIRE(tag->select_application(test_app_id));
                    REQUIRE(tag->select_application(desfire::root_app));
                    REQUIRE(tag->authenticate(key));
                    REQUIRE(tag->delete_application(test_app_id));
                    // Also format picc will CMAC
                    REQUIRE(tag->format_picc());
                    REQUIRE(tag->select_application(desfire::root_app));
                    // Master key survives format
                    REQUIRE(tag->authenticate(key));
                }

                // Cleanup
                REQUIRE(tag->change_key(ensure_card_formatted::default_root_key()));
            }


            SECTION("App creation") {
                constexpr std::array<desfire::cipher_type, 4> all_ciphers = {desfire::cipher_type::des, desfire::cipher_type::des3_2k,
                                                                             desfire::cipher_type::des3_3k, desfire::cipher_type::aes128};
                std::map<desfire::app_id, bool> found_ids{};

                for (desfire::cipher_type cipher : all_ciphers) {
                    const demo_app app{cipher};
                    ESP_LOGI(TAG, "Creating app with cipher %s.", to_string(cipher));
                    REQUIRE(desfire::fs::login_app(*tag, desfire::root_app, ensure_card_formatted::default_root_key()));
                    REQUIRE(tag->create_application(app.aid, desfire::app_settings{cipher}));
                    REQUIRE(tag->select_application(app.aid));
                    REQUIRE(tag->authenticate(app.master_key));
                    // Check that get-card-uid is correct with all cipher even when an app is selected
                    REQUIRE(tag->get_card_uid());
                    // Save this id
                    found_ids[app.aid] = false;
                }

                REQUIRE(tag->select_application(desfire::root_app));
                const auto r_app_ids = tag->get_application_ids();
                CHECKED_IF_FAIL(r_app_ids) {
                    REQUIRE(r_app_ids->size() >= 4);
                    for (std::size_t i = 0; i < r_app_ids->size(); ++i) {
                        desfire::app_id aid = r_app_ids->at(i);
                        ESP_LOGI(TAG, "  %d. AID %02x %02x %02x", i + 1, aid[0], aid[1], aid[2]);
                        if (auto it = found_ids.find(aid); it != std::end(found_ids)) {
                            REQUIRE_FALSE(it->second);
                            it->second = true;
                        }
                    }
                    REQUIRE(std::all_of(std::begin(found_ids), std::end(found_ids), [](auto kvp) { return kvp.second; }));
                }

                for (desfire::cipher_type cipher : all_ciphers) {
                    const demo_app app{cipher};
                    ESP_LOGI(TAG, "Changing same key of app with cipher %s.", to_string(app.master_key.type()));
                    REQUIRE(tag->select_application(app.aid));
                    if (not tag->authenticate(app.master_key)) {
                        ESP_LOGW(TAG, "Default key not working, attempting secondary key and reset...");
                        REQUIRE(tag->authenticate(app.secondary_key));
                        REQUIRE(tag->change_key(app.master_key));
                        ESP_LOGI(TAG, "Reset app key to default, continuing!");
                        REQUIRE(tag->authenticate(app.master_key));
                    }
                    REQUIRE(tag->change_key(app.secondary_key));
                    REQUIRE(tag->authenticate(app.secondary_key));
                    const auto res_key_version = tag->get_key_version(app.secondary_key.key_number());
                    CHECKED_IF_FAIL(res_key_version) {
                        CHECK(app.secondary_key.version() == *res_key_version);
                    }
                    auto res_key_settings = tag->get_app_settings();
                    REQUIRE(res_key_settings);
                    res_key_settings->rights.dir_access_without_auth = true;
                    REQUIRE(tag->change_app_settings(res_key_settings->rights));
                    res_key_settings->rights.dir_access_without_auth = false;
                    REQUIRE(tag->change_app_settings(res_key_settings->rights));
                    REQUIRE(tag->change_key(app.master_key));

                    REQUIRE(res_key_settings->max_num_keys > 2);
                    res_key_settings->rights.allowed_to_change_keys = 0_b;
                    REQUIRE(tag->authenticate(app.master_key));
                    REQUIRE(tag->change_app_settings(res_key_settings->rights));
                    res_key_settings = tag->get_app_settings();
                    REQUIRE(res_key_settings);
                    REQUIRE(res_key_settings->rights.allowed_to_change_keys == 0_b);
                    REQUIRE(app.master_key.key_number() == 0);
                    REQUIRE(tag->authenticate(app.master_key));
                    const auto next_key_old = desfire::any_key{cipher}.with_key_number(1);
                    REQUIRE(next_key_old.key_number() == 1);
                    REQUIRE(tag->authenticate(next_key_old));
                    REQUIRE(tag->authenticate(app.master_key));
                    const auto next_key_new = app.secondary_key.with_key_number(1);
                    REQUIRE(next_key_new.key_number() == 1);
                    REQUIRE(tag->change_key(next_key_old, next_key_new));
                    REQUIRE(tag->authenticate(next_key_new));
                    REQUIRE(tag->authenticate(app.master_key));
                    REQUIRE(tag->change_key(next_key_new, next_key_old));
                }
            }
        }
    }


}// namespace ut
