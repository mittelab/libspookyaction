#include "test_desfire.hpp"
#include "test_desfire_ciphers.hpp"
#include "test_desfire_exchanges.hpp"
#include "test_pn532.hpp"
#include "utils.hpp"
#include <mbcontroller.h>
#include <numeric>
#include <unity.h>

#define TEST_TAG "UT"

namespace {

    std::unique_ptr<pn532::desfire_pcd> pcd = nullptr;
    std::unique_ptr<desfire::tag> mifare = nullptr;

    [[nodiscard]] mlab::bin_data const &heavy_load() {
        static mlab::bin_data load;
        if (load.empty()) {
            load.resize(0x100);
            std::iota(std::begin(load), std::end(load), 0x00);
        }
        return load;
    }

    using namespace std::chrono_literals;

}// namespace


void issue_header(std::string const &title) {
    ESP_LOGI(TEST_TAG, "--------------------------------------------------------------------------------");
    const std::size_t tail_length = std::max(68u, title.length()) - title.length();
    const std::string header = "---------- " + title + " " + std::string(tail_length, '-');
    ESP_LOGI(TEST_TAG, "%s", header.c_str());
    vTaskDelay(pdMS_TO_TICKS(2000));
}


struct file_test {
    desfire::file_security security = desfire::file_security::none;
    desfire::cipher_type cipher = desfire::cipher_type::none;
    desfire::file_type ftype = desfire::file_type::standard;

    [[nodiscard]] const char *mode_description() const {
        switch (security) {
            case desfire::file_security::none:
                return "none";
            case desfire::file_security::encrypted:
                return "encrypted";
            case desfire::file_security::authenticated:
                return "maced";
        }
        return nullptr;
    }

    [[nodiscard]] const char *cipher_description() const {
        switch (cipher) {
            case desfire::cipher_type::des:
                return "des";
            case desfire::cipher_type::des3_2k:
                return "des3_2k";
            case desfire::cipher_type::des3_3k:
                return "des3_3k";
            case desfire::cipher_type::aes128:
                return "aes128";
            case desfire::bits::cipher_type::none:
                break;
        }
        return nullptr;
    }

    [[nodiscard]] const char *ftype_description() const {
        switch (ftype) {
            case desfire::file_type::standard:
                return "standard";
            case desfire::file_type::backup:
                return "backup";
            case desfire::file_type::value:
                return "value";
            case desfire::file_type::linear_record:
                return "linear_record";
            case desfire::file_type::cyclic_record:
                return "cyclic_record";
        }
        return nullptr;
    }

    [[nodiscard]] const char *description() const {
        static std::string buffer;
        buffer.reserve(128);
        // Here the buffer get cleared
        buffer = "test_file(desfire::file_security::";
        buffer.append(mode_description());
        buffer.append(", desfire::cipher_type::");
        buffer.append(cipher_description());
        buffer.append(", desfire::file_type::");
        buffer.append(ftype_description());
        buffer.append(")");
        return buffer.c_str();
    }

    static void perform_standard_data_file_test(ut::test_file const &file) {
        TEST_ASSERT(pcd != nullptr and mifare != nullptr)
        TEST_ASSERT(mifare->write_data(file.fid, 0, heavy_load()))
        const auto r_read = mifare->read_data(file.fid, 0, heavy_load().size());
        TEST_ASSERT(r_read)
        TEST_ASSERT_EQUAL(heavy_load().size(), r_read->size());
        TEST_ASSERT_EQUAL_HEX8_ARRAY(heavy_load().data(), r_read->data(), heavy_load().size());
    }

    static void perform_backup_data_file_test(ut::test_file const &file) {
        TEST_ASSERT(pcd != nullptr and mifare != nullptr)
        TEST_ASSERT(mifare->write_data(file.fid, 0, heavy_load()))
        const auto r_read_before_commit = mifare->read_data(file.fid, 0, heavy_load().size());
        TEST_ASSERT(r_read_before_commit)
        TEST_ASSERT_EACH_EQUAL_HEX8(0x00, r_read_before_commit->data(), r_read_before_commit->size());
        TEST_ASSERT(mifare->commit_transaction())
        const auto r_read = mifare->read_data(file.fid, 0, heavy_load().size());
        TEST_ASSERT(r_read)
        TEST_ASSERT_EQUAL(heavy_load().size(), r_read->size());
        TEST_ASSERT_EQUAL_HEX8_ARRAY(heavy_load().data(), r_read->data(), heavy_load().size());
    }

    static void perform_value_file_test(ut::test_file const &file) {
        TEST_ASSERT(pcd != nullptr and mifare != nullptr)

        const auto test_get_value = [&](std::int32_t expected) {
            const auto res_read = mifare->get_value(file.fid);
            TEST_ASSERT(res_read)
            TEST_ASSERT_EQUAL(expected, *res_read);
        };

        test_get_value(0);
        TEST_ASSERT(mifare->credit(file.fid, 2))
        test_get_value(0);// Did not commit yet
        TEST_ASSERT(mifare->commit_transaction())
        test_get_value(2);
        TEST_ASSERT(mifare->debit(file.fid, 5))
        TEST_ASSERT(mifare->commit_transaction())
        test_get_value(-3);
    }

    static void perform_record_file_test(ut::test_file const &file) {
        TEST_ASSERT(pcd != nullptr and mifare != nullptr)

        using record_t = std::array<std::uint8_t, 8>;

        static const mlab::bin_data nibble = {0x00, 0x01, 0x02, 0x03};

        const auto test_get_record_count = [&](std::uint32_t expected) {
            const auto res_settings = mifare->get_file_settings(file.fid);
            TEST_ASSERT(res_settings)
            TEST_ASSERT_EQUAL(expected, res_settings->record_settings().record_count);
        };

        test_get_record_count(0);
        TEST_ASSERT(mifare->write_record(file.fid, 4, nibble))
        TEST_ASSERT(mifare->commit_transaction())
        test_get_record_count(1);
        const auto res_records = mifare->read_parse_records<record_t>(file.fid, 0);
        TEST_ASSERT(res_records)
        TEST_ASSERT_EQUAL(res_records->size(), 1);
        const record_t expected = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03};
        TEST_ASSERT_EQUAL_HEX8_ARRAY(expected.data(), res_records->front().data(), 8);
        TEST_ASSERT(mifare->clear_record_file(file.fid))
        TEST_ASSERT(mifare->commit_transaction())
    }

    void perform_test() const {
        TEST_ASSERT(pcd != nullptr and mifare != nullptr)
        static const desfire::any_key root_key{desfire::key<desfire::cipher_type::des>{}};

        // Make sure there is enough space to run. 1376B is a decent estimate for how much space is needed
        TEST_ASSERT(mifare->select_application(desfire::root_app))
        TEST_ASSERT(mifare->authenticate(root_key))
        const auto r_free_mem = mifare->get_free_mem();
        TEST_ASSERT(r_free_mem)
        if (*r_free_mem < 1376) {
            ESP_LOGI(TEST_TAG, "Formatting to recover space (only %d B free).", *r_free_mem);
            TEST_ASSERT(mifare->format_picc())
        }

        ut::test_app const &app = ut::get_test_app(cipher);
        ut::test_file const &file = ut::get_test_file(ftype, security);
        app.ensure_created(*mifare, root_key);
        app.ensure_selected_and_primary(*mifare);
        TEST_ASSERT_EQUAL_HEX8_ARRAY(app.aid.data(), mifare->active_app().data(), 3);
        TEST_ASSERT_EQUAL(app.primary_key.key_number(), mifare->active_key_no());
        file.delete_preexisting(*mifare);
        TEST_ASSERT(mifare->create_file(file.fid, file.settings))

        switch (ftype) {
            case desfire::file_type::standard:
                perform_standard_data_file_test(file);
                break;
            case desfire::file_type::backup:
                perform_backup_data_file_test(file);
                break;
            case desfire::file_type::value:
                perform_value_file_test(file);
                break;
            case desfire::file_type::linear_record:
                [[fallthrough]];
            case desfire::file_type::cyclic_record:
                perform_record_file_test(file);
                break;
        }
        TEST_ASSERT(mifare->delete_file(file.fid))
    }

    [[nodiscard]] static file_test &instance() {
        static file_test _instance{};
        return _instance;
    }

    static void run() {
        instance().perform_test();
    }
};

void unity_perform_cipher_tests() {
    issue_header("MIFARE CIPHER TEST (no card)");
    RUN_TEST(test::desfire::test_crc16);
    RUN_TEST(test::desfire::test_crc32);
    RUN_TEST(test::desfire::test_des);
    RUN_TEST(test::desfire::test_2k3des);
    RUN_TEST(test::desfire::test_3k3des);
    RUN_TEST(test::desfire::test_aes);
    RUN_TEST(test::desfire::test_change_key_aes);
    RUN_TEST(test::desfire::test_change_key_des);
    RUN_TEST(test::desfire::test_change_key_2k3des);
    RUN_TEST(test::desfire::test_create_write_file_rx_cmac);
    RUN_TEST(test::desfire::test_get_key_version_rx_cmac);
    RUN_TEST(test::desfire::test_write_data_cmac_des);
}

std::shared_ptr<ut::pn532::test_instance> unity_perform_pn532_tests(ut::pn532::channel_type channel) {
    auto instance = ut::pn532::try_activate_channel(channel);
    if (instance == nullptr) {
        ESP_LOGE(TEST_TAG, "Unsupported channel %s.", ut::pn532::to_string(channel));
        // Still run the tests so that Unity can read the failure, if this is not the CI/CD machine
#ifndef KEYCARD_CI_CD_MACHINE
        return nullptr;
#endif
    } else {
        ut::default_registrar().register_instance(instance);
    }

    issue_header("PN532 TEST AND DIAGNOSTICS (no card)");
    RUN_TEST(ut::pn532::test_wake_channel);
    // Just skip this bunch if the channel does not work there is no hope
    if (instance->channel_did_wake()) {
        RUN_TEST(ut::pn532::test_get_fw);
        RUN_TEST(ut::pn532::test_diagnostics);
        issue_header("PN532 SCAN TEST (optionally requires card)");
        RUN_TEST(ut::pn532::test_scan_mifare);
        RUN_TEST(ut::pn532::test_pn532_cycle_rf);
        RUN_TEST(ut::pn532::test_scan_all);
        RUN_TEST(ut::pn532::test_pn532_cycle_rf);
        issue_header("PN532 MIFARE COMM TEST (requires card)");
        RUN_TEST(ut::pn532::test_data_exchange);
        RUN_TEST(ut::pn532::test_pn532_cycle_rf);
    } else {
        ESP_LOGE(TEST_TAG, "Channel %s did not wake.", ut::pn532::to_string(channel));
    }
    // Return the instance in case the user wants to do sth else with it
    return instance;
}

std::shared_ptr<test::desfire::instance> unity_perform_desfire_live_test(pn532::nfc &nfc) {
    test::desfire::auto_cleanup cleanup{};
    auto instance = test::desfire::build_instance(nfc);
    if (instance == nullptr) {
        ESP_LOGW(TEST_TAG, "Could not find any card.");
        // Still run the tests so that Unity can read the failure.
    }
    RUN_TEST(test::desfire::get_test_mifare_base(instance));
    RUN_TEST(test::desfire::get_test_mifare_uid(instance));
    RUN_TEST(test::desfire::get_test_mifare_create_apps(instance));
    RUN_TEST(test::desfire::get_test_mifare_change_app_key(instance));
    // Note: better to first test apps, before fiddling with the root app.
    RUN_TEST(test::desfire::get_test_mifare_root_operations(instance));
    return instance;
}

void unity_perform_pn532_mifare_tests() {
    issue_header("MIFARE TEST (requires card)");
    /**
     * @todo Migrate this block
     */
    /**
     * Test file creation, deletion, and read/write cycle.
     *
     * @note Since Unity does not allow parms in RUN_TEST, let's store those into a structure and then use them to call
     * the actual test function. This will generate a separate test entry for each mode.
     */
    for (desfire::file_security sec : {desfire::file_security::none, desfire::file_security::authenticated, desfire::file_security::encrypted}) {
        for (desfire::cipher_type cipher : {desfire::cipher_type::des, desfire::cipher_type::des3_2k,
                                            desfire::cipher_type::des3_3k, desfire::cipher_type::aes128}) {
            for (desfire::file_type ftype : {desfire::file_type::standard, desfire::file_type::backup,
                                             desfire::file_type::value, desfire::file_type::linear_record,
                                             desfire::file_type::cyclic_record}) {
                file_test::instance().security = sec;
                file_test::instance().cipher = cipher;
                file_test::instance().ftype = ftype;
                UnityDefaultTestRun(&file_test::run, file_test::instance().description(), __LINE__);
            }
        }
    }
}


void unity_perform_all_tests() {
    using ut::pn532::channel_type;

    UNITY_BEGIN();
    esp_log_level_set("*", ESP_LOG_INFO);

    // No hardware required for these
    unity_perform_cipher_tests();

    // Itereate through all available transmission channels. Those that cannot be activated will be skipped
    for (channel_type channel : {channel_type::hsu, channel_type::i2c, channel_type::i2c_irq, channel_type::spi}) {
        if (auto pn532_instance = unity_perform_pn532_tests(channel); pn532_instance != nullptr) {
            if (auto mifare_instance = unity_perform_desfire_live_test(pn532_instance->tag_reader()); mifare_instance) {
                // @todo Do the file tests with this instance.
            }
        }
    }
    UNITY_END();
}

#ifdef KEYCARD_UNIT_TEST_MAIN

#ifdef __cplusplus
extern "C" {
#endif

void app_main() {
    unity_perform_all_tests();
}

#ifdef __cplusplus
}
#endif

#endif
