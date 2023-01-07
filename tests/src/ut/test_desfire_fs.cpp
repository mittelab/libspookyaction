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