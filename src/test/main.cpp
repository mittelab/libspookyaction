#include "pn532_pinout.hpp"
#include "test_desfire_ciphers.hpp"
#include "test_desfire_exchanges.hpp"
#include "test_desfire_files.hpp"
#include "test_desfire_main.hpp"
#include "test_pn532.hpp"
#include <mbcontroller.h>
#include <unity.h>

#define TEST_TAG "UT"

void issue_header(std::string const &title) {
    ESP_LOGI(TEST_TAG, "--------------------------------------------------------------------------------");
    const std::size_t tail_length = std::max(68u, title.length()) - title.length();
    const std::string header = "---------- " + title + " " + std::string(tail_length, '-');
    ESP_LOGI(TEST_TAG, "%s", header.c_str());
    vTaskDelay(pdMS_TO_TICKS(2000));
}

void unity_perform_cipher_tests() {
    issue_header("MIFARE CIPHER TEST (no card)");
    RUN_TEST(ut::desfire_ciphers::test_crc16);
    RUN_TEST(ut::desfire_ciphers::test_crc32);
    RUN_TEST(ut::desfire_ciphers::test_des);
    RUN_TEST(ut::desfire_ciphers::test_2k3des);
    RUN_TEST(ut::desfire_ciphers::test_3k3des);
    RUN_TEST(ut::desfire_ciphers::test_aes);
    RUN_TEST(ut::desfire_exchanges::test_change_key_aes);
    RUN_TEST(ut::desfire_exchanges::test_change_key_des);
    RUN_TEST(ut::desfire_exchanges::test_change_key_2k3des);
    RUN_TEST(ut::desfire_exchanges::test_change_key_2k3des_regression);
    RUN_TEST(ut::desfire_exchanges::test_create_write_file_rx_cmac);
    RUN_TEST(ut::desfire_exchanges::test_get_key_version_rx_cmac);
    RUN_TEST(ut::desfire_exchanges::test_write_data_cmac_des);
}

std::shared_ptr<ut::pn532::test_instance> unity_perform_pn532_tests(ut::pn532::channel_type channel) {
    if (not ut::pn532::channel_is_supported(channel)) {
        ESP_LOG_LEVEL(
                (ut::pn532::supports_cicd_machine ? ESP_LOG_ERROR : ESP_LOG_WARN),
                TEST_TAG,
                "Unsupported channel %s.", ut::pn532::to_string(channel));
        return nullptr;
    }
    auto instance = ut::pn532::try_activate_channel(channel);
    // Still run the tests so that Unity can read the failure, if this is not the CI/CD machine
    if (instance != nullptr) {
        ut::default_registrar().register_instance(instance);
    }

    issue_header("PN532 TEST AND DIAGNOSTICS (no card)");
    RUN_TEST(ut::pn532::test_wake_channel);
    // Just skip this bunch if the channel does not work there is no hope
    if (instance != nullptr and instance->channel_did_wake()) {
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

std::shared_ptr<ut::desfire_main::test_instance> unity_perform_desfire_main_test(std::shared_ptr<ut::pn532::test_instance> pn532_test) {
    auto instance = ut::desfire_main::try_connect_card(std::move(pn532_test));
    ut::default_registrar().register_instance(instance);
    if (instance == nullptr) {
        ESP_LOGW(TEST_TAG, "Could not find any card.");
        // Still run the tests so that Unity can read the failure.
    }
    RUN_TEST(ut::desfire_main::test_mifare_base);
    RUN_TEST(ut::desfire_main::test_mifare_uid);
    RUN_TEST(ut::desfire_main::test_mifare_create_apps);
    RUN_TEST(ut::desfire_main::test_mifare_change_app_key);
    // Note: better to first test apps, before fiddling with the root app.
    RUN_TEST(ut::desfire_main::test_mifare_root_operations);
    return instance;
}

std::shared_ptr<ut::desfire_files::test_instance> unity_perform_desfire_files_test(std::shared_ptr<ut::desfire_main::test_instance> desfire_test) {
    using desfire::cipher_type;
    using desfire::file_security;
    using desfire::file_type;

    auto instance = std::make_shared<ut::desfire_files::test_instance>(std::move(desfire_test));
    ut::default_registrar().register_instance(instance);
    issue_header("MIFARE TEST (requires card)");

    /**
     * Test file creation, deletion, and read/write cycle.
     *
     * @note Since Unity does not allow parms in RUN_TEST, let's store those into a structure and then use them to call
     * the actual test function. This will generate a separate test entry for each mode.
     */
    for (file_security sec : {file_security::none, file_security::authenticated, file_security::encrypted}) {
        for (cipher_type cipher : {cipher_type::des, cipher_type::des3_2k,
                                   cipher_type::des3_3k, cipher_type::aes128}) {
            for (file_type ftype : {file_type::standard, file_type::backup,
                                    file_type::value, file_type::linear_record,
                                    file_type::cyclic_record}) {
                instance->file().security = sec;
                instance->file().cipher = cipher;
                instance->file().type = ftype;
                const std::string desc = instance->file().get_description();
                UnityDefaultTestRun(&ut::desfire_files::test_file, desc.c_str(), __LINE__);
            }
        }
    }
    return instance;
}


void unity_perform_all_tests() {
    using ut::pn532::channel_type;

    UNITY_BEGIN();
    esp_log_level_set("*", ESP_LOG_INFO);

    // No hardware required for these
    unity_perform_cipher_tests();

    // Itereate through all available transmission channels. Those that cannot be activated will be skipped
    for (channel_type channel : {channel_type::hsu, channel_type::i2c, channel_type::i2c_irq, channel_type::spi, channel_type::spi_irq}) {
        if (auto pn532_instance = unity_perform_pn532_tests(channel); pn532_instance != nullptr) {
            if (auto mifare_instance = unity_perform_desfire_main_test(pn532_instance); mifare_instance) {
                unity_perform_desfire_files_test(mifare_instance);
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
