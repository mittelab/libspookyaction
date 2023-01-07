//
// Created by spak on 1/7/23.
//

#include "test_desfire_fs.hpp"
#include "utils.hpp"
#include <desfire/fs.hpp>
#include <esp_random.h>
#include <unity.h>

namespace ut::fs {

    namespace {
        constexpr auto missing_instance_msg = "desfire::fs test instance missing";

        using namespace ::desfire::fs;


        template <bool B, class R>
        [[nodiscard]] bool ok_and(R const &r) {
            return r and *r == B;
        }
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

        TEST_ASSERT(tag.select_application());
        TEST_ASSERT(tag.authenticate(key<cipher_type::des>{}));

        const auto aid = app_id{0x10, 0x20, 0x30};

        const auto r_key = create_app_for_ro(tag, cipher_type::aes128, aid, esp_fill_random);
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
        TEST_ASSERT(not r_app_settings->rights.create_delete_without_auth);
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
        TEST_ASSERT(not r_app_settings->rights.create_delete_without_auth);
        TEST_ASSERT(r_app_settings->rights.dir_access_without_auth);
        TEST_ASSERT(not r_app_settings->rights.master_key_changeable);
        TEST_ASSERT(r_app_settings->rights.allowed_to_change_keys == no_key);

        // The key should still work, but once thrashed...
        TEST_ASSERT(tag.authenticate(*r_key));
    }

    void test_app() {
        UNITY_PATCH_TEST_FILE;
        auto instance = default_registrar().get<test_instance>();
        if (instance == nullptr) {
            TEST_FAIL_MESSAGE(missing_instance_msg);
            return;
        }
        auto &tag = instance->tag();

        TEST_ASSERT(tag.format_picc());
        TEST_ASSERT(tag.authenticate(key<cipher_type::des>{}));

        const auto aid = app_id{0x11, 0x22, 0x33};

        TEST_ASSERT(ok_and<false>(does_app_exist(tag, aid)));
        // Root app is not an app!
        TEST_ASSERT(ok_and<false>(does_app_exist(tag, root_app)));

        TEST_ASSERT(delete_app_if_exists(tag, aid));

        // Generate a random key
        const auto master_key = key<cipher_type::aes128>{0, esp_fill_random};

        TEST_ASSERT(create_app(tag, aid, master_key, {}));

        // Should fail if the app exists already
        auto suppress = suppress_log{DESFIRE_TAG, DESFIRE_FS_LOG_PREFIX};
        TEST_ASSERT_FALSE(create_app(tag, aid, master_key, {}));
        suppress.restore();
        // Should be on the new app
        TEST_ASSERT(tag.active_app() == aid);

        // So this should fail:
        suppress.suppress();
        TEST_ASSERT_FALSE(does_app_exist(tag, aid));
        suppress.restore();

        TEST_ASSERT(tag.select_application());
        TEST_ASSERT(tag.authenticate(key<cipher_type::des>{}));

        TEST_ASSERT(ok_and<true>(does_app_exist(tag, aid)));

        // Should be deletable
        TEST_ASSERT(delete_app_if_exists(tag, aid))
        TEST_ASSERT(ok_and<false>(does_app_exist(tag, aid)));
    }
}