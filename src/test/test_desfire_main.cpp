//
// Created by spak on 3/18/21.
//

#include "test_desfire_main.hpp"
#include "utils.hpp"
#include <map>
#include <mbcontroller.h>
#include <pn532/msg.hpp>
#include <unity.h>

#define TEST_TAG "UT"

namespace ut::desfire_main {

    namespace {
        constexpr const char *missing_instance_msg = "Desfire test instance was not set up.";

        void issue_format_warning() {
            ESP_LOGW(TEST_TAG, "The following test are destructive and will format the PICC!");
            ESP_LOGW(TEST_TAG, "Remove the tag from RF field if you care for your data.");
            for (unsigned i = 3; i > 0; --i) {
                ESP_LOGW(TEST_TAG, "%d...", i);
                vTaskDelay(pdMS_TO_TICKS(1000));
            }
        }

        constexpr std::uint8_t secondary_keys_version = 0x10;
        constexpr std::array<std::uint8_t, 8> secondary_des_key = {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe};
        constexpr std::array<std::uint8_t, 16> secondary_des3_2k_key = {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e};
        constexpr std::array<std::uint8_t, 24> secondary_des3_3k_key = {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e, 0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e};
        constexpr std::array<std::uint8_t, 16> secondary_aes_key = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};

        app_id get_default_aid(cipher_type c) {
            switch (c) {
                case cipher_type::des:
                    return {0x00, 0xde, 0x08};
                case cipher_type::des3_2k:
                    return {0x00, 0xde, 0x16};
                case cipher_type::des3_3k:
                    return {0x00, 0xde, 0x24};
                case cipher_type::aes128:
                    return {0x00, 0xae, 0x16};
                case cipher_type::none:
                    [[fallthrough]];
                default:
                    return {};
            }
        }

        any_key get_primary_key(cipher_type c) {
            switch (c) {
                case cipher_type::des:
                    return key<cipher_type::des>{};
                case cipher_type::des3_2k:
                    return key<cipher_type::des3_2k>{};
                case cipher_type::des3_3k:
                    return key<cipher_type::des3_3k>{};
                case cipher_type::aes128:
                    return key<cipher_type::aes128>{};
                case cipher_type::none:
                    [[fallthrough]];
                default:
                    return {};
            }
        }

        any_key get_secondary_key(cipher_type c) {
            switch (c) {
                case cipher_type::des:
                    return key<cipher_type::des>{0, secondary_des_key, secondary_keys_version};
                case cipher_type::des3_2k:
                    return key<cipher_type::des3_2k>{0, secondary_des3_2k_key, secondary_keys_version};
                case cipher_type::des3_3k:
                    return key<cipher_type::des3_3k>{0, secondary_des3_3k_key, secondary_keys_version};
                case cipher_type::aes128:
                    return key<cipher_type::aes128>{0, secondary_aes_key, secondary_keys_version};
                case cipher_type::none:
                    [[fallthrough]];
                default:
                    return {};
            }
        }
    }// namespace

    demo_app::demo_app(cipher_type c) : aid{get_default_aid(c)}, cipher{c}, primary_key{get_primary_key(c)}, secondary_key{get_secondary_key(c)} {}

    void demo_app::ensure_selected_and_primary(tag &tag) const {
        if (tag.active_app() != aid) {
            TEST_ASSERT(tag.select_application(aid));
        }
        if (tag.active_key_no() != primary_key.key_number()) {
            if (not tag.authenticate(primary_key)) {
                TEST_ASSERT(tag.authenticate(secondary_key));
                ESP_LOGI("UT", "Resetting key of app %02x %02x %02x.", aid[0], aid[1], aid[2]);
                TEST_ASSERT(tag.change_key(primary_key));
                TEST_ASSERT(tag.authenticate(primary_key));
            }
        }
    }

    void demo_app::ensure_created(tag &tag, any_key const &root_key) const {
        if (tag.active_app() != root_app) {
            TEST_ASSERT(tag.select_application(root_app));
        }
        if (tag.active_key_no() != root_key.key_number()) {
            TEST_ASSERT(tag.authenticate(root_key));
        }
        const auto r_get_aids = tag.get_application_ids();
        TEST_ASSERT(r_get_aids);
        if (std::find(std::begin(*r_get_aids), std::end(*r_get_aids), aid) == std::end(*r_get_aids)) {
            TEST_ASSERT(tag.create_application(aid, app_settings{cipher}));
        }
    }

    test_data::test_data(std::shared_ptr<ut::pn532::test_instance> pn532_test_instance, std::uint8_t card_logical_index)
        : _controller{std::make_unique<pn532::desfire_pcd>(pn532_test_instance->tag_reader(), card_logical_index)},
          _hold_test_instance{std::move(pn532_test_instance)},
          _tag{*_controller} {
        if (_controller == nullptr) {
            ESP_LOGE(TEST_TAG, "desfire::tag object was set up with an invalid controller! If a SEGFAULT did not happen, it is about to.");
        }
    }

    test_data::test_data(std::unique_ptr<pn532::desfire_pcd> controller)
        : _controller{std::move(controller)},
          _hold_test_instance{nullptr},
          _tag{*_controller} {
        if (_controller == nullptr) {
            ESP_LOGE(TEST_TAG, "desfire::tag object was set up with an invalid controller! If a SEGFAULT did not happen, it is about to.");
        }
    }

    pn532::desfire_pcd &test_data::controller() {
        return *_controller;
    }

    tag &test_data::tag() {
        return _tag;
    }


    /**
     * @addtogroup ActualTests
     * @{
     */

    void test_auth_attempt(tag::result<> const &result) {
        auto instance = default_registrar().get<test_instance>();
        if (instance == nullptr) {
            TEST_FAIL_MESSAGE(missing_instance_msg);
            return;
        }
        auto &pcd = instance->controller();

        if (not result) {
            ESP_LOGW(TEST_TAG, "Authentication failed: %s", to_string(result.error()));
            if (not pcd.last_result()) {
                ESP_LOGW(TEST_TAG, "Last PCD error: %s", ::pn532::to_string(pcd.last_result().error()));
            } else {
                ESP_LOGW(TEST_TAG, "Last controller error: %s", ::pn532::to_string(pcd.last_result()->error));
            }
            TEST_FAIL();
        }
    }


    void test_mifare_base() {
        auto instance = default_registrar().get<test_instance>();
        if (instance == nullptr) {
            TEST_FAIL_MESSAGE(missing_instance_msg);
            return;
        }
        auto &mifare = instance->tag();

        issue_format_warning();

        TEST_ASSERT(mifare.select_application(root_app))
        test_auth_attempt(mifare.authenticate(key<cipher_type::des>{}));
        TEST_ASSERT(mifare.format_picc())

        const auto r_info = mifare.get_info();
        TEST_ASSERT(r_info)
        ESP_LOGI(TEST_TAG, "Card info:");
        ESP_LOGI(TEST_TAG, "    vendor id: %02x", r_info->hardware.vendor_id);
        ESP_LOGI(TEST_TAG, "   hw version: %d.%d", r_info->hardware.version_major, r_info->hardware.version_minor);
        ESP_LOGI(TEST_TAG, "   sw version: %d.%d", r_info->software.version_major, r_info->software.version_minor);
        ESP_LOGI(TEST_TAG, "  storage [B]: %s%u",
                 (r_info->hardware.size.bytes_upper_bound() > r_info->hardware.size.bytes_lower_bound() ? "> " : ""),
                 r_info->hardware.size.bytes_lower_bound());
        ESP_LOGI(TEST_TAG, "    serial no: %02x %02x %02x %02x %02x %02x %02x",
                 r_info->serial_no[0], r_info->serial_no[1], r_info->serial_no[2], r_info->serial_no[3],
                 r_info->serial_no[4], r_info->serial_no[5], r_info->serial_no[6]);
        ESP_LOGI(TEST_TAG, "     batch no: %02x %02x %02x %02x %02x",
                 r_info->batch_no[0], r_info->batch_no[1], r_info->batch_no[2], r_info->batch_no[3], r_info->batch_no[4]);
        ESP_LOGI(TEST_TAG, "   production: %02x %02x -> year %02u, week %u", r_info->production_week,
                 r_info->production_year, r_info->production_year, r_info->production_week);

        const auto r_mem = mifare.get_free_mem();
        TEST_ASSERT(r_mem)
        ESP_LOGI(TEST_TAG, " free mem [B]: %d", *r_mem);
    }

    void test_mifare_uid() {
        auto instance = default_registrar().get<test_instance>();
        if (instance == nullptr) {
            TEST_FAIL_MESSAGE(missing_instance_msg);
            return;
        }
        auto &mifare = instance->tag();

        TEST_ASSERT(mifare.select_application(root_app))
        test_auth_attempt(mifare.authenticate(key<cipher_type::des>{}));

        const auto r_info = mifare.get_info();
        TEST_ASSERT(r_info)
        const auto uid = r_info->serial_no;

        const auto r_get_uid = mifare.get_card_uid();
        TEST_ASSERT(r_get_uid)
        TEST_ASSERT_EQUAL_HEX8_ARRAY(uid.data(), r_get_uid->data(), uid.size());
    }

    void test_mifare_create_apps() {
        auto instance = default_registrar().get<test_instance>();
        if (instance == nullptr) {
            TEST_FAIL_MESSAGE(missing_instance_msg);
            return;
        }
        auto &mifare = instance->tag();

        std::map<app_id, bool> found_ids{};

        for (cipher_type cipher : {cipher_type::des, cipher_type::des3_2k,
                                   cipher_type::des3_3k, cipher_type::aes128}) {
            const demo_app app{cipher};
            ESP_LOGI(TEST_TAG, "Creating app with cipher %s.", to_string(cipher));
            TEST_ASSERT(mifare.select_application(root_app))
            TEST_ASSERT(mifare.authenticate(key<cipher_type::des>{}))
            TEST_ASSERT(mifare.create_application(app.aid, app_settings{cipher}))
            TEST_ASSERT(mifare.select_application(app.aid))
            test_auth_attempt(mifare.authenticate(app.primary_key));
            // Save this id
            found_ids[app.aid] = false;
        }

        TEST_ASSERT(mifare.select_application(root_app))
        const auto r_app_ids = mifare.get_application_ids();
        TEST_ASSERT(r_app_ids)
        if (r_app_ids) {
            TEST_ASSERT_GREATER_OR_EQUAL(r_app_ids->size(), 4);
            for (std::size_t i = 0; i < r_app_ids->size(); ++i) {
                app_id const &aid = r_app_ids->at(i);
                ESP_LOGI(TEST_TAG, "  %d. AID %02x %02x %02x", i + 1, aid[0], aid[1], aid[2]);
                if (auto it = found_ids.find(aid); it != std::end(found_ids)) {
                    TEST_ASSERT_FALSE(it->second)
                    it->second = true;
                }
            }
            const bool got_all_ids = std::all_of(std::begin(found_ids), std::end(found_ids), [](auto kvp) { return kvp.second; });
            TEST_ASSERT(got_all_ids)
        }
    }

    void test_mifare_root_operations() {
        auto instance = default_registrar().get<test_instance>();
        if (instance == nullptr) {
            TEST_FAIL_MESSAGE(missing_instance_msg);
            return;
        }
        auto &mifare = instance->tag();

        const any_key default_k = key<cipher_type::des>{};

        std::vector<any_key> keys_to_test;
        keys_to_test.emplace_back(default_k);// Default key

        for (cipher_type cipher : {cipher_type::des, cipher_type::des3_2k,
                                   cipher_type::des3_3k, cipher_type::aes128}) {
            const demo_app app{cipher};
            // Copy the keys from the test apps
            keys_to_test.emplace_back(app.primary_key);
            keys_to_test.emplace_back(app.secondary_key);
        }

        const auto find_current_key = [&]() -> bool {
            ESP_LOGI(TEST_TAG, "Attempt to recover the root key (warnings/errors here are normal).");
            TEST_ASSERT(mifare.select_application(root_app))
            for (auto const &key : keys_to_test) {
                if (mifare.authenticate(key)) {
                    ESP_LOGI(TEST_TAG, "Found the right key, changing to default.");
                    TEST_ASSERT(mifare.change_key(default_k))
                    TEST_ASSERT(mifare.authenticate(default_k))
                    return true;
                }
            }
            ESP_LOGW(TEST_TAG, "All the know default keys failed to authenticate root app.");
            return false;
        };

        ESP_LOGW(TEST_TAG, "Changing root app key. This has a chance of bricking your card.");
        ESP_LOGW(TEST_TAG, "If the implementation of change_key or authenticate is broken,");
        ESP_LOGW(TEST_TAG, "it may set an unexpected root key. If changes were made to those");
        ESP_LOGW(TEST_TAG, "pieces of code, test them in the context of non-root apps first.");
        issue_format_warning();

        TEST_ASSERT(mifare.select_application(root_app))
        TEST_ASSERT(find_current_key())

        const app_id test_app_id = {0x00, 0x7e, 0x57};

        ESP_LOGI(TEST_TAG, "Begin key test cycle.");
        for (auto const &key : keys_to_test) {
            TEST_ASSERT(mifare.change_key(key))
            ESP_LOGI(TEST_TAG, "Changed root key to %s, testing root level ops.", to_string(key.type()));
            TEST_ASSERT(mifare.authenticate(key))
            // Do bunch of operations on applications that can only be done at the root level, so that we can verify the
            // trasmission modes for the root level app
            auto r_list = mifare.get_application_ids();
            TEST_ASSERT(r_list)
            if (std::find(std::begin(*r_list), std::end(*r_list), test_app_id) != std::end(*r_list)) {
                // Remove preexisting app
                TEST_ASSERT(mifare.delete_application(test_app_id))
            }
            TEST_ASSERT(mifare.create_application(test_app_id, app_settings()))
            r_list = mifare.get_application_ids();
            TEST_ASSERT(r_list)
            TEST_ASSERT_GREATER_OR_EQUAL(1, r_list->size());
            TEST_ASSERT(std::find(std::begin(*r_list), std::end(*r_list), test_app_id) != std::end(*r_list))
            TEST_ASSERT(mifare.select_application(test_app_id))
            TEST_ASSERT(mifare.select_application(root_app))
            TEST_ASSERT(mifare.authenticate(key))
            TEST_ASSERT(mifare.delete_application(test_app_id))
            // Also format picc will CMAC
            TEST_ASSERT(mifare.format_picc())
            TEST_ASSERT(mifare.select_application(root_app))
            // Master key survives format
            TEST_ASSERT(mifare.authenticate(key))
        }

        // Cleanup
        TEST_ASSERT(mifare.change_key(default_k))
        TEST_ASSERT(mifare.authenticate(default_k))
        TEST_ASSERT(mifare.format_picc())
    }

    void test_mifare_change_app_key() {
        auto instance = default_registrar().get<test_instance>();
        if (instance == nullptr) {
            TEST_FAIL_MESSAGE(missing_instance_msg);
            return;
        }
        auto &mifare = instance->tag();


        for (cipher_type cipher : {cipher_type::des, cipher_type::des3_2k,
                                   cipher_type::des3_3k, cipher_type::aes128}) {
            const demo_app app{cipher};
            ESP_LOGI(TEST_TAG, "Changing same key of app with cipher %s.", to_string(app.primary_key.type()));
            TEST_ASSERT(mifare.select_application(app.aid))
            if (not mifare.authenticate(app.primary_key)) {
                ESP_LOGW(TEST_TAG, "Default key not working, attempting secondary key and reset...");
                TEST_ASSERT(mifare.authenticate(app.secondary_key))
                TEST_ASSERT(mifare.change_key(app.primary_key))
                ESP_LOGI(TEST_TAG, "Reset app key to default, continuing!");
                TEST_ASSERT(mifare.authenticate(app.primary_key))
            }
            TEST_ASSERT(mifare.change_key(app.secondary_key))
            TEST_ASSERT(mifare.authenticate(app.secondary_key))
            const auto res_key_version = mifare.get_key_version(app.secondary_key.key_number());
            TEST_ASSERT(res_key_version)
            TEST_ASSERT_EQUAL(app.secondary_key.version(), *res_key_version);
            auto res_key_settings = mifare.get_app_settings();
            TEST_ASSERT(res_key_settings)
            res_key_settings->rights.dir_access_without_auth = true;
            TEST_ASSERT(mifare.change_app_settings(res_key_settings->rights))
            res_key_settings->rights.dir_access_without_auth = false;
            TEST_ASSERT(mifare.change_app_settings(res_key_settings->rights))
            TEST_ASSERT(mifare.change_key(app.primary_key))
        }
    }

    /**
     * @}
     */

    namespace {
        using namespace std::chrono_literals;

        std::uint8_t try_find_card(pn532::nfc &tag_reader) {
            ESP_LOGI(TEST_TAG, "Please bring card close now (searching for one passive 106 kbps target)...");
            const auto r_scan = tag_reader.initiator_list_passive_kbps106_typea(1, 10s);
            if (not r_scan or r_scan->empty()) {
                ESP_LOGE(TEST_TAG, "Could not find a suitable card for testing.");
                return std::numeric_limits<std::uint8_t>::max();
            }
            ESP_LOGI(TEST_TAG, "Found one target:");
            auto const &nfcid = r_scan->front().info.nfcid;
            ESP_LOG_BUFFER_HEX_LEVEL(TEST_TAG, nfcid.data(), nfcid.size(), ESP_LOG_INFO);

            return r_scan->front().logical_index;
        }
    }// namespace
    std::shared_ptr<test_instance> try_connect_card(pn532::nfc &tag_reader) {
        if (const auto logical_idx = try_find_card(tag_reader); logical_idx != std::numeric_limits<std::uint8_t>::max()) {
            return std::make_shared<test_instance>(std::make_unique<pn532::desfire_pcd>(tag_reader, logical_idx));
        }
        return nullptr;
    }

    std::shared_ptr<test_instance> try_connect_card(std::shared_ptr<ut::pn532::test_instance> pn532_test_instance) {
        if (pn532_test_instance == nullptr) {
            return nullptr;
        }
        if (const auto logical_idx = try_find_card(pn532_test_instance->tag_reader()); logical_idx != std::numeric_limits<std::uint8_t>::max()) {
            return std::make_shared<test_instance>(std::move(pn532_test_instance), logical_idx);
        }
        return nullptr;
    }
}// namespace ut::desfire_main
