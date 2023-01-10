//
// Created by spak on 1/7/23.
//

#include "test_desfire_fs.hpp"
#include "utils.hpp"
#include <desfire/esp32/utils.hpp>
#include <desfire/fs.hpp>
#include <esp_random.h>
#include <unity.h>

namespace ut::fs {

    namespace {
        constexpr auto missing_instance_msg = "desfire::fs test instance missing";

        using namespace ::desfire::fs;
        using namespace ::desfire::esp32;


        template <bool B, class R>
        [[nodiscard]] bool ok_and(R const &r) {
            return r and *r == B;
        }

        struct temp_app {
            desfire::tag &tag;
            any_key root_key;
            app_id aid;
            any_key master_key;

            explicit temp_app(desfire::tag &tag_, any_key root_key_ = key<cipher_type::des>{}, app_id aid_ = {0x11, 0x22, 0x33}, cipher_type cipher = cipher_type::aes128)
                : tag{tag_},
                  root_key{std::move(root_key_)},
                  aid{aid_},
                  master_key{any_key{cipher, random_oracle{esp_fill_random}}}
            {
                TEST_ASSERT(login_app(tag, root_app, root_key));
                TEST_ASSERT(delete_app_if_exists(tag, aid));
                TEST_ASSERT(create_app(tag, aid, master_key, key_rights{}, 0));
            }

            ~temp_app() {
                TEST_ASSERT(login_app(tag, root_app, root_key));
                TEST_ASSERT(delete_app_if_exists(tag, aid));
            }
        };
    }

    test_data::test_data(std::shared_ptr<ut::desfire_main::test_instance> main_test_instance)
        : _hold_test_instance{std::move(main_test_instance)} {}

    tag &test_data::tag() {
        return _hold_test_instance->tag();
    }

    void test_ro_app() {
        UNITY_PATCH_TEST_FILE;
        auto instance = default_registrar().get<test_instance>();
        if (instance == nullptr) {
            TEST_FAIL_MESSAGE(missing_instance_msg);
            return;
        }
        auto &tag = instance->tag();

        TEST_ASSERT(login_app(tag, root_app, key<cipher_type::des>{}));
        const auto aid = app_id{0x10, 0x20, 0x30};

        const auto r_key = create_app_for_ro(tag, cipher_type::aes128, aid, random_oracle{esp_fill_random});
        TEST_ASSERT(r_key);
        if (not r_key) {
            return;
        }

        TEST_ASSERT(tag.active_app() == aid);
        TEST_ASSERT(tag.active_key_type() == r_key->type());
        TEST_ASSERT(tag.active_key_no() == r_key->key_number());

        TEST_ASSERT(tag.create_file(0x00, file_settings<file_type::value>{file_security::none, access_rights{}, 0, 0, 0}));
        TEST_ASSERT(tag.delete_file(0x00));

        TEST_ASSERT(tag.authenticate(*r_key));
        auto r_app_settings = tag.get_app_settings();

        TEST_ASSERT(r_app_settings);
        if (not r_app_settings) {
            return;
        }

        // An app that must be turned into read only should check these all
        TEST_ASSERT(r_app_settings->rights.config_changeable);
        TEST_ASSERT(not r_app_settings->rights.create_delete_without_master_key);
        TEST_ASSERT(r_app_settings->rights.dir_access_without_auth);
        TEST_ASSERT(r_app_settings->rights.master_key_changeable);
        TEST_ASSERT(r_app_settings->rights.allowed_to_change_keys == r_key->key_number());

        TEST_ASSERT(make_app_ro(tag, true));

        TEST_ASSERT(tag.select_application(aid));
        TEST_ASSERT(tag.get_file_ids());

        r_app_settings = tag.get_app_settings();
        TEST_ASSERT(r_app_settings);
        if (not r_app_settings) {
            return;
        }

        TEST_ASSERT(not r_app_settings->rights.config_changeable);
        TEST_ASSERT(not r_app_settings->rights.create_delete_without_master_key);
        TEST_ASSERT(r_app_settings->rights.dir_access_without_auth);
        TEST_ASSERT(not r_app_settings->rights.master_key_changeable);
        TEST_ASSERT(r_app_settings->rights.allowed_to_change_keys == no_key);

        // The key should still work, but once thrashed...
        TEST_ASSERT(tag.authenticate(*r_key));

        TEST_ASSERT(login_app(tag, root_app, key<cipher_type::des>{}));
        TEST_ASSERT(delete_app_if_exists(tag, aid));
    }

    void test_app() {
        UNITY_PATCH_TEST_FILE;
        auto instance = default_registrar().get<test_instance>();
        if (instance == nullptr) {
            TEST_FAIL_MESSAGE(missing_instance_msg);
            return;
        }
        auto &tag = instance->tag();

        TEST_ASSERT(tag.authenticate(key<cipher_type::des>{}));

        const auto aid = app_id{0x11, 0x22, 0x33};

        TEST_ASSERT(ok_and<false>(does_app_exist(tag, aid)));
        // Root app is not an app!
        TEST_ASSERT(ok_and<false>(does_app_exist(tag, root_app)));

        TEST_ASSERT(delete_app_if_exists(tag, aid));

        // Generate a random key
        const auto master_key = key<cipher_type::aes128>{0, random_oracle{esp_fill_random}};

        TEST_ASSERT(create_app(tag, aid, master_key, {}));

        // Should fail if the app exists already
        auto suppress = suppress_log{DESFIRE_LOG_PREFIX, DESFIRE_FS_LOG_PREFIX};
        TEST_ASSERT_FALSE(create_app(tag, aid, master_key, {}));
        suppress.restore();
        // Should be on the new app
        TEST_ASSERT(tag.active_app() == aid);

        // So this should fail:
        suppress.suppress();
        TEST_ASSERT_FALSE(does_app_exist(tag, aid));
        suppress.restore();

        TEST_ASSERT(login_app(tag, root_app, key<cipher_type::des>{}));

        TEST_ASSERT(ok_and<true>(does_app_exist(tag, aid)));

        // Should be deletable
        TEST_ASSERT(delete_app_if_exists(tag, aid))
        TEST_ASSERT(ok_and<false>(does_app_exist(tag, aid)));

        TEST_ASSERT(delete_app_if_exists(tag, aid));
    }

    void test_file() {
        UNITY_PATCH_TEST_FILE;
        auto instance = default_registrar().get<test_instance>();
        if (instance == nullptr) {
            TEST_FAIL_MESSAGE(missing_instance_msg);
            return;
        }
        auto &tag = instance->tag();

        // Create a temp app which will auto-delete
        temp_app app{tag};
        const auto fid = file_id{0x00};

        TEST_ASSERT(ok_and<false>(does_file_exist(tag, fid)));

        TEST_ASSERT(delete_file_if_exists(tag, fid));

        TEST_ASSERT(tag.create_file(fid, file_settings<file_type::standard>{file_security::none, access_rights{}, 1}));

        TEST_ASSERT(ok_and<true>(does_file_exist(tag, fid)));

        TEST_ASSERT(delete_file_if_exists(tag, fid));

        TEST_ASSERT(ok_and<false>(does_file_exist(tag, fid)));
        // Should not fail if run twice
        TEST_ASSERT(ok_and<false>(does_file_exist(tag, fid)));

        // Create several
        TEST_ASSERT(tag.create_file(fid + 1, file_settings<file_type::standard>{file_security::none, access_rights{}, 1}));
        TEST_ASSERT(tag.create_file(fid + 2, file_settings<file_type::standard>{file_security::none, access_rights{}, 1}));

        // Check which of those exists
        auto r_exist = which_files_exist(tag, {fid, fid + 1, fid + 3, fid + 2});
        TEST_ASSERT(r_exist);

        if (r_exist) {
            TEST_ASSERT_EQUAL(r_exist->size(), 2);
            if (not r_exist->empty()) {
                std::sort(std::begin(*r_exist), std::end(*r_exist));
                TEST_ASSERT_EQUAL(r_exist->front(), fid + 1);
                TEST_ASSERT_EQUAL(r_exist->back(), fid + 2);
            }
        }
    }

    void test_ro_data_file() {
        UNITY_PATCH_TEST_FILE;
        auto instance = default_registrar().get<test_instance>();
        if (instance == nullptr) {
            TEST_FAIL_MESSAGE(missing_instance_msg);
            return;
        }
        auto &tag = instance->tag();

        // Create a temp app which will auto-delete
        temp_app app{tag};

        const auto fid = file_id{0x00};
        const auto expected_data = bin_data{{0xf0, 0xf1, 0xf2}};

        TEST_ASSERT(create_ro_free_plain_data_file(tag, fid, expected_data));

        auto r_file_settings = tag.get_file_settings(fid);

        TEST_ASSERT(r_file_settings);
        if (not r_file_settings) {
            return;
        }

        TEST_ASSERT(r_file_settings->generic_settings().security == file_security::none);
        TEST_ASSERT(r_file_settings->generic_settings().rights.is_free(file_access::read));
        TEST_ASSERT(r_file_settings->generic_settings().rights.write == no_key);
        TEST_ASSERT(r_file_settings->generic_settings().rights.read_write == no_key);
        TEST_ASSERT(r_file_settings->generic_settings().rights.change == no_key);

        TEST_ASSERT(logout_app(tag));

        const auto r_data = tag.read_data(fid, cipher_mode::plain);
        TEST_ASSERT(r_data);

        if (not r_data) {
            return;
        }
        TEST_ASSERT_EQUAL(r_data->size(), expected_data.size());
        if (r_data->size() == expected_data.size()) {
            TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_data.data(), r_data->data(), expected_data.size());
        }

        // Should fail without authorization
        auto suppress = suppress_log{DESFIRE_FS_LOG_PREFIX, DESFIRE_LOG_PREFIX};
        TEST_ASSERT_FALSE(delete_file_if_exists(tag, fid));
        suppress.restore();
    }

    void test_ro_value_file() {
        UNITY_PATCH_TEST_FILE;
        auto instance = default_registrar().get<test_instance>();
        if (instance == nullptr) {
            TEST_FAIL_MESSAGE(missing_instance_msg);
            return;
        }
        auto &tag = instance->tag();

        // Create a temp app which will auto-delete
        temp_app app{tag};

        const auto fid = file_id{0x00};
        const auto expected_data = std::int32_t{0xbadb007};

        TEST_ASSERT(create_ro_free_plain_value_file(tag, fid, expected_data));

        auto r_file_settings = tag.get_file_settings(fid);

        TEST_ASSERT(r_file_settings);
        if (not r_file_settings) {
            return;
        }

        TEST_ASSERT(r_file_settings->generic_settings().security == file_security::none);
        TEST_ASSERT(r_file_settings->generic_settings().rights.is_free(file_access::read));
        TEST_ASSERT(r_file_settings->generic_settings().rights.write == no_key);
        TEST_ASSERT(r_file_settings->generic_settings().rights.read_write == no_key);
        TEST_ASSERT(r_file_settings->generic_settings().rights.change == no_key);

        TEST_ASSERT(logout_app(tag));

        const auto r_value = tag.get_value(fid, cipher_mode::plain);
        TEST_ASSERT(r_value);

        if (not r_value) {
            return;
        }
        TEST_ASSERT_EQUAL(*r_value, expected_data);

        // Should fail without authorization
        auto suppress = suppress_log{DESFIRE_FS_LOG_PREFIX, DESFIRE_LOG_PREFIX};
        TEST_ASSERT_FALSE(delete_file_if_exists(tag, fid));
        suppress.restore();
    }
}