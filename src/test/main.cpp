#include "test_desfire_ciphers.hpp"
#include "test_desfire_exchanges.hpp"
#include "utils.hpp"
#include <map>
#include <numeric>
#include <pn532/desfire_pcd.hpp>
#include <pn532/hsu.hpp>
#include <pn532/i2c.hpp>
#include <unity.h>

#define TEST_TAG "UT"

#define PN532_SERIAL_RX (GPIO_NUM_16)
#define PN532_SERIAL_TX (GPIO_NUM_17)

#define PN532_I2C_SCL (GPIO_NUM_16)
#define PN532_I2C_SDA (GPIO_NUM_17)

#define PN532_SPI_MISO (GPIO_NUM_27)
#define PN532_SPI_MOSI (GPIO_NUM_25)
#define PN532_SPI_SCK (GPIO_NUM_14)
#define PN532_SPI_SS (GPIO_NUM_26)

#define PN532_I0 (GPIO_NUM_18)
#define PN532_I1 (GPIO_NUM_19)
#define PN532_RSTN (GPIO_NUM_21)

#define PN532_IRQ (GPIO_NUM_13)


namespace {
    constexpr uart_config_t uart_config = {
            .baud_rate = 115200,
            .data_bits = UART_DATA_8_BITS,
            .parity = UART_PARITY_DISABLE,
            .stop_bits = UART_STOP_BITS_1,
            .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
            .rx_flow_ctrl_thresh = 122,
            .source_clk = UART_SCLK_REF_TICK};

    constexpr i2c_config_t i2c_config = {
            .mode = I2C_MODE_MASTER,
            .sda_io_num = PN532_I2C_SDA,
            .scl_io_num = PN532_I2C_SCL,
            .sda_pullup_en = GPIO_PULLUP_ENABLE,
            .scl_pullup_en = GPIO_PULLUP_ENABLE,
            .master = {.clk_speed = 400000}};

    std::unique_ptr<pn532::channel> channel = nullptr;
    std::unique_ptr<pn532::nfc> tag_reader = nullptr;
    std::unique_ptr<pn532::desfire_pcd> pcd = nullptr;
    std::unique_ptr<desfire::tag> mifare = nullptr;
    bool did_pass_wake_test = false;

    [[nodiscard]] bool is_ok(pn532::nfc::r<bool> const &r) {
        return r and *r;
    }

    [[nodiscard]] mlab::bin_data const &heavy_load() {
        static mlab::bin_data load;
        if (load.empty()) {
            load.resize(0x100);
            std::iota(std::begin(load), std::end(load), 0x00);
        }
        return load;
    }

    void setup_channel_switch() {
#ifdef KEYCARD_CI_CD_MACHINE
        gpio_set_direction(PN532_RSTN, GPIO_MODE_OUTPUT);
        gpio_set_direction(PN532_I0, GPIO_MODE_OUTPUT);
        gpio_set_direction(PN532_I1, GPIO_MODE_OUTPUT);
        gpio_set_level(PN532_RSTN, 1);
#else
        ESP_LOGW(TEST_TAG, "Not running on multi-channel CI/CD machine. Only the selected channels will be tested.");
#endif
    }

    bool switch_channel(ut::channel_type type) {
        // Clear all variables
        mifare = nullptr;
        pcd = nullptr;
        tag_reader = nullptr;
        channel = nullptr;
        // Check which channels are allowed
#ifndef KEYCARD_HSU
        if (type == ut::channel_type::hsu) {
            return false;
        }
#endif
#ifndef KEYCARD_I2C
        if (type == ut::channel_type::i2c) {
            return false;
        }
#endif
#ifndef KEYCARD_I2C_IRQ
        if (type == ut::channel_type::i2c_irq) {
            return false;
        }
#endif
#ifndef KEYCARD_SPI
        if (type == ut::channel_type::spi) {
            return false;
        }
#endif
        ESP_LOGI(TEST_TAG, "Activating channel %s...", ut::to_string(type));
#ifdef KEYCARD_CI_CD_MACHINE
        // Configure I0/I1 for the selected mode
        switch (type) {
            case ut::channel_type::hsu:
                gpio_set_level(PN532_I0, 0);
                gpio_set_level(PN532_I1, 0);
                break;
            case ut::channel_type::i2c:
                [[fallthrough]];
            case ut::channel_type::i2c_irq:
                gpio_set_level(PN532_I0, 1);
                gpio_set_level(PN532_I1, 0);
                break;
            case ut::channel_type::spi:
                gpio_set_level(PN532_I0, 0);
                gpio_set_level(PN532_I1, 1);
                break;
        }
        // Power cycle the pn532
        gpio_set_level(PN532_RSTN, 0);
        vTaskDelay(pdMS_TO_TICKS(500));
        // Release reset line
        gpio_set_level(PN532_RSTN, 1);
        vTaskDelay(pdMS_TO_TICKS(500));
#endif
        switch (type) {
            case ut::channel_type::hsu:
                channel = std::make_unique<pn532::hsu_channel>(UART_NUM_1, uart_config, PN532_SERIAL_TX, PN532_SERIAL_RX);
                break;
            case ut::channel_type::i2c:
                channel = std::make_unique<pn532::i2c_channel>(I2C_NUM_0, i2c_config);
                break;
            case ut::channel_type::i2c_irq:
                channel = std::make_unique<pn532::i2c_channel>(I2C_NUM_0, i2c_config, PN532_IRQ, true);
                break;
            case ut::channel_type::spi:
                ESP_LOGE(TEST_TAG, "SPI is not yet supported.");
                break;
        }
        tag_reader = std::make_unique<pn532::nfc>(*channel);
        ESP_LOGI(TEST_TAG, "Channel %s ready.", ut::to_string(type));
        return true;
    }

    using namespace std::chrono_literals;

}// namespace

void test_wake_channel() {
    TEST_ASSERT_NOT_EQUAL(channel, nullptr)
    TEST_ASSERT_NOT_EQUAL(tag_reader, nullptr)

    TEST_ASSERT(channel->wake())
    const auto r_sam = tag_reader->sam_configuration(pn532::sam_mode::normal, 1s);
    TEST_ASSERT(r_sam)

    did_pass_wake_test = bool(r_sam);
}

void test_get_fw() {
    TEST_ASSERT_NOT_EQUAL(tag_reader, nullptr)

    const auto r_fw = tag_reader->get_firmware_version();
    TEST_ASSERT(r_fw)
    ESP_LOGI(TEST_TAG, "IC version %u, version: %u.%u", r_fw->ic, r_fw->version, r_fw->revision);
}

void test_diagnostics() {
    TEST_ASSERT_NOT_EQUAL(tag_reader, nullptr)

    TEST_ASSERT(is_ok(tag_reader->diagnose_rom()))
    TEST_ASSERT(is_ok(tag_reader->diagnose_ram()))
    TEST_ASSERT(is_ok(tag_reader->diagnose_comm_line()))
    TEST_ASSERT(
            is_ok(tag_reader->diagnose_self_antenna(pn532::low_current_thr::mA_25, pn532::high_current_thr::mA_150)))
}

void test_scan_mifare() {
    TEST_ASSERT_NOT_EQUAL(tag_reader, nullptr)
    ESP_LOGI(TEST_TAG, "Please bring card close now (searching for one passive 106 kbps target)...");
    const auto r_scan = tag_reader->initiator_list_passive_kbps106_typea();
    TEST_ASSERT(r_scan)
    ESP_LOGI(TEST_TAG, "Found %u targets (passive, 106 kbps, type A).", r_scan->size());
    if (r_scan) {
        for (pn532::target_kbps106_typea const &target : *r_scan) {
            ESP_LOGI(TEST_TAG, "Logical index %u; NFC ID:", target.logical_index);
            ESP_LOG_BUFFER_HEX_LEVEL(TEST_TAG, target.info.nfcid.data(), target.info.nfcid.size(), ESP_LOG_INFO);
        }
    }
}

void test_scan_all() {
    TEST_ASSERT_NOT_EQUAL(tag_reader, nullptr)
    ESP_LOGI(TEST_TAG, "Please bring card close now (searching for any target)...");
    const auto r_scan = tag_reader->initiator_auto_poll();
    TEST_ASSERT(r_scan)
    ESP_LOGI(TEST_TAG, "Found %u targets.", r_scan->size());
    if (r_scan) {
        for (std::size_t i = 0; i < r_scan->size(); ++i) {
            ESP_LOGI(TEST_TAG, "%u. %s", i + 1, pn532::to_string(r_scan->at(i).type()));
        }
    }
}

void test_pn532_cycle_rf() {
    TEST_ASSERT_NOT_EQUAL(tag_reader, nullptr)
    const auto r_status = tag_reader->get_general_status();
    TEST_ASSERT(r_status)
    for (auto const &target : r_status->targets) {
        TEST_ASSERT(tag_reader->initiator_deselect(target.logical_index))
    }
    TEST_ASSERT(tag_reader->rf_configuration_field(true, false))
}

void test_data_exchange() {
    TEST_ASSERT_NOT_EQUAL(tag_reader, nullptr)
    ESP_LOGI(TEST_TAG, "Please bring card close now (searching for one passive 106 kbps target)...");
    const auto r_scan = tag_reader->initiator_list_passive_kbps106_typea(1, 10s);
    if (not r_scan or r_scan->empty()) {
        TEST_FAIL_MESSAGE("Could not find a suitable card for testing.");
        return;
    }
    ESP_LOGI(TEST_TAG, "Found one target:");
    auto const &nfcid = r_scan->front().info.nfcid;
    ESP_LOG_BUFFER_HEX_LEVEL(TEST_TAG, nfcid.data(), nfcid.size(), ESP_LOG_INFO);
    ESP_LOGI(TEST_TAG, "Exchanging data.");
    const auto idx = r_scan->front().logical_index;
    const auto r_exchange = tag_reader->initiator_data_exchange(idx, {0x5a, 0x00, 0x00, 0x00});
    if (not r_exchange) {
        TEST_FAIL_MESSAGE("Exchange failed.");
        return;
    }
    ESP_LOGI(TEST_TAG, "Exchange successful, received:");
    ESP_LOG_BUFFER_HEX_LEVEL(TEST_TAG, r_exchange->second.data(), r_exchange->second.size(), ESP_LOG_INFO);
    TEST_ASSERT_EQUAL(r_exchange->first.error, pn532::controller_error::none);
    TEST_ASSERT_EQUAL(r_exchange->second.size(), 1);
    TEST_ASSERT_EQUAL(r_exchange->second.front(), 0x0);
}

void issue_header(std::string const &title) {
    ESP_LOGI(TEST_TAG, "--------------------------------------------------------------------------------");
    const std::size_t tail_length = std::max(68u, title.length()) - title.length();
    const std::string header = "---------- " + title + " " + std::string(tail_length, '-');
    ESP_LOGI(TEST_TAG, "%s", header.c_str());
    vTaskDelay(pdMS_TO_TICKS(2000));
}

void issue_format_warning() {
    ESP_LOGW(TEST_TAG, "The following test are destructive and will format the PICC!");
    ESP_LOGW(TEST_TAG, "Remove the tag from RF field if you care for your data.");
    for (unsigned i = 3; i > 0; --i) {
        ESP_LOGW(TEST_TAG, "%d...", i);
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

void test_auth_attempt(desfire::tag::r<> const &r) {
    TEST_ASSERT_NOT_EQUAL(tag_reader, nullptr)
    if (not r) {
        ESP_LOGW(TEST_TAG, "Authentication failed: %s", desfire::to_string(r.error()));
        if (not pcd->last_result()) {
            ESP_LOGW(TEST_TAG, "Last PCD error: %s", pn532::to_string(pcd->last_result().error()));
        } else {
            ESP_LOGW(TEST_TAG, "Last controller error: %s", pn532::to_string(pcd->last_result()->error));
        }
        TEST_FAIL();
    }
}

void setup_mifare() {
    TEST_ASSERT_NOT_EQUAL(tag_reader, nullptr)

    ESP_LOGI(TEST_TAG, "Please bring card close now (searching for one passive 106 kbps target)...");
    const auto r_scan = tag_reader->initiator_list_passive_kbps106_typea(1, 10s);
    if (not r_scan or r_scan->empty()) {
        TEST_FAIL_MESSAGE("Could not find a suitable card for testing.");
        return;
    }
    ESP_LOGI(TEST_TAG, "Found one target:");
    auto const &nfcid = r_scan->front().info.nfcid;
    ESP_LOG_BUFFER_HEX_LEVEL(TEST_TAG, nfcid.data(), nfcid.size(), ESP_LOG_INFO);

    pcd = std::make_unique<pn532::desfire_pcd>(*tag_reader, r_scan->front().logical_index);
    mifare = std::make_unique<desfire::tag>(*pcd);
}

void test_mifare_base() {
    TEST_ASSERT_NOT_EQUAL(pcd, nullptr)
    TEST_ASSERT_NOT_EQUAL(mifare, nullptr)

    issue_format_warning();

    TEST_ASSERT(mifare->select_application(desfire::root_app))
    test_auth_attempt(mifare->authenticate(desfire::key<desfire::cipher_type::des>{}));
    TEST_ASSERT(mifare->format_picc())

    const auto r_info = mifare->get_info();
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

    const auto r_mem = mifare->get_free_mem();
    TEST_ASSERT(r_mem)
    ESP_LOGI(TEST_TAG, " free mem [B]: %d", *r_mem);
}

void test_mifare_uid() {
    TEST_ASSERT_NOT_EQUAL(pcd, nullptr)
    TEST_ASSERT_NOT_EQUAL(mifare, nullptr)

    TEST_ASSERT(mifare->select_application(desfire::root_app))
    test_auth_attempt(mifare->authenticate(desfire::key<desfire::cipher_type::des>{}));

    const auto r_info = mifare->get_info();
    TEST_ASSERT(r_info)
    const auto uid = r_info->serial_no;

    const auto r_get_uid = mifare->get_card_uid();
    TEST_ASSERT(r_get_uid)
    TEST_ASSERT_EQUAL_HEX8_ARRAY(uid.data(), r_get_uid->data(), uid.size());
}

void test_mifare_create_apps() {
    TEST_ASSERT_NOT_EQUAL(pcd, nullptr)
    TEST_ASSERT_NOT_EQUAL(mifare, nullptr)

    std::map<desfire::app_id, bool> found_ids{};

    for (desfire::cipher_type cipher : {desfire::cipher_type::des, desfire::cipher_type::des3_2k,
                                        desfire::cipher_type::des3_3k, desfire::cipher_type::aes128}) {
        ut::test_app const &app = ut::get_test_app(cipher);
        ESP_LOGI(TEST_TAG, "Creating app with cipher %s.", desfire::to_string(cipher));
        TEST_ASSERT(mifare->select_application(desfire::root_app))
        TEST_ASSERT(mifare->authenticate(desfire::key<desfire::cipher_type::des>{}))
        TEST_ASSERT(mifare->create_application(app.aid, desfire::app_settings{cipher}))
        TEST_ASSERT(mifare->select_application(app.aid))
        test_auth_attempt(mifare->authenticate(app.primary_key));
        // Save this id
        found_ids[app.aid] = false;
    }

    TEST_ASSERT(mifare->select_application(desfire::root_app))
    const auto r_app_ids = mifare->get_application_ids();
    TEST_ASSERT(r_app_ids)
    if (r_app_ids) {
        TEST_ASSERT_GREATER_OR_EQUAL(r_app_ids->size(), 4);
        for (std::size_t i = 0; i < r_app_ids->size(); ++i) {
            desfire::app_id const &aid = r_app_ids->at(i);
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
    TEST_ASSERT(pcd != nullptr and mifare != nullptr)

    const desfire::any_key default_k = desfire::key<desfire::cipher_type::des>{};

    std::vector<desfire::any_key> keys_to_test;
    keys_to_test.emplace_back(default_k);// Default key

    for (desfire::cipher_type cipher : {desfire::cipher_type::des, desfire::cipher_type::des3_2k,
                                        desfire::cipher_type::des3_3k, desfire::cipher_type::aes128}) {
        ut::test_app const &app = ut::get_test_app(cipher);
        // Copy the keys from the test apps
        keys_to_test.emplace_back(app.primary_key);
        keys_to_test.emplace_back(app.secondary_key);
    }

    const auto find_current_key = [&]() -> bool {
        ESP_LOGI(TEST_TAG, "Attempt to recover the root key (warnings/errors here are normal).");
        TEST_ASSERT(mifare->select_application(desfire::root_app))
        for (auto const &key : keys_to_test) {
            if (mifare->authenticate(key)) {
                ESP_LOGI(TEST_TAG, "Found the right key, changing to default.");
                TEST_ASSERT(mifare->change_key(default_k))
                TEST_ASSERT(mifare->authenticate(default_k))
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

    TEST_ASSERT(mifare->select_application(desfire::root_app))
    TEST_ASSERT(find_current_key())

    const desfire::app_id test_app_id = {0x00, 0x7e, 0x57};

    ESP_LOGI(TEST_TAG, "Begin key test cycle.");
    for (auto const &key : keys_to_test) {
        TEST_ASSERT(mifare->change_key(key))
        ESP_LOGI(TEST_TAG, "Changed root key to %s, testing root level ops.", desfire::to_string(key.type()));
        TEST_ASSERT(mifare->authenticate(key))
        // Do bunch of operations on applications that can only be done at the root level, so that we can verify the
        // trasmission modes for the root level app
        auto r_list = mifare->get_application_ids();
        TEST_ASSERT(r_list)
        if (std::find(std::begin(*r_list), std::end(*r_list), test_app_id) != std::end(*r_list)) {
            // Remove preexisting app
            TEST_ASSERT(mifare->delete_application(test_app_id))
        }
        TEST_ASSERT(mifare->create_application(test_app_id, desfire::app_settings()))
        r_list = mifare->get_application_ids();
        TEST_ASSERT(r_list)
        TEST_ASSERT_GREATER_OR_EQUAL(1, r_list->size());
        TEST_ASSERT(std::find(std::begin(*r_list), std::end(*r_list), test_app_id) != std::end(*r_list))
        TEST_ASSERT(mifare->select_application(test_app_id))
        TEST_ASSERT(mifare->select_application(desfire::root_app))
        TEST_ASSERT(mifare->authenticate(key))
        TEST_ASSERT(mifare->delete_application(test_app_id))
        // Also format picc will CMAC
        TEST_ASSERT(mifare->format_picc())
        TEST_ASSERT(mifare->select_application(desfire::root_app))
        // Master key survives format
        TEST_ASSERT(mifare->authenticate(key))
    }

    // Cleanup
    TEST_ASSERT(mifare->change_key(default_k))
    TEST_ASSERT(mifare->authenticate(default_k))
    TEST_ASSERT(mifare->format_picc())
}

void test_mifare_change_app_key() {
    TEST_ASSERT(pcd != nullptr and mifare != nullptr)


    for (desfire::cipher_type cipher : {desfire::cipher_type::des, desfire::cipher_type::des3_2k,
                                        desfire::cipher_type::des3_3k, desfire::cipher_type::aes128}) {
        ut::test_app const &app = ut::get_test_app(cipher);
        ESP_LOGI(TEST_TAG, "Changing same key of app with cipher %s.", desfire::to_string(app.primary_key.type()));
        TEST_ASSERT(mifare->select_application(app.aid))
        if (not mifare->authenticate(app.primary_key)) {
            ESP_LOGW(TEST_TAG, "Default key not working, attempting secondary key and reset...");
            TEST_ASSERT(mifare->authenticate(app.secondary_key))
            TEST_ASSERT(mifare->change_key(app.primary_key))
            ESP_LOGI(TEST_TAG, "Reset app key to default, continuing!");
            TEST_ASSERT(mifare->authenticate(app.primary_key))
        }
        TEST_ASSERT(mifare->change_key(app.secondary_key))
        TEST_ASSERT(mifare->authenticate(app.secondary_key))
        const auto res_key_version = mifare->get_key_version(app.secondary_key.key_number());
        TEST_ASSERT(res_key_version)
        TEST_ASSERT_EQUAL(app.secondary_key.version(), *res_key_version);
        auto res_key_settings = mifare->get_app_settings();
        TEST_ASSERT(res_key_settings)
        res_key_settings->rights.dir_access_without_auth = true;
        TEST_ASSERT(mifare->change_app_settings(res_key_settings->rights))
        res_key_settings->rights.dir_access_without_auth = false;
        TEST_ASSERT(mifare->change_app_settings(res_key_settings->rights))
        TEST_ASSERT(mifare->change_key(app.primary_key))
    }
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

void unity_perform_pn532_mifare_tests() {
    issue_header("PN532 TEST AND DIAGNOSTICS (no card)");
    did_pass_wake_test = false;
    RUN_TEST(test_wake_channel);
    if (not did_pass_wake_test) {
        ESP_LOGE(TEST_TAG, "Unable to wake up PN532 via this channel, skipping all tests.");
    } else {
        RUN_TEST(test_get_fw);
        RUN_TEST(test_diagnostics);
        issue_header("PN532 SCAN TEST (optionally requires card)");
        RUN_TEST(test_scan_mifare);
        RUN_TEST(test_pn532_cycle_rf);
        RUN_TEST(test_scan_all);
        RUN_TEST(test_pn532_cycle_rf);
        issue_header("PN532 MIFARE COMM TEST (requires card)");
        RUN_TEST(test_data_exchange);
        RUN_TEST(test_pn532_cycle_rf);
        issue_header("MIFARE TEST (requires card)");
        RUN_TEST(setup_mifare);
        RUN_TEST(test_mifare_base);
        RUN_TEST(test_mifare_uid);
        RUN_TEST(test_mifare_create_apps);
        RUN_TEST(test_mifare_change_app_key);
        // Note: better to first test apps, before fiddling with the root app.
        RUN_TEST(test_mifare_root_operations);

        /**
     * Test file creation, deletion, and read/write cycle.
     *
     * @note Since Unity does not allow parms in RUN_TEST, let's store those into a structure and then use them to call
     * the actual test function. This will generate a separate test entry for each mode.
     */
        issue_format_warning();
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

    /**
     * Teardown.
     */
    mifare = nullptr;
    if (tag_reader != nullptr) {
        if (pcd != nullptr) {
            tag_reader->initiator_deselect(pcd->target_logical_index());
            pcd = nullptr;
        }
        tag_reader->rf_configuration_field(true, false);
        tag_reader = nullptr;
    }
    channel = nullptr;
}

void unity_main() {
    UNITY_BEGIN();
    esp_log_level_set("*", ESP_LOG_INFO);
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

    setup_channel_switch();
    for (ut::channel_type chn : {ut::channel_type::hsu, ut::channel_type::i2c, ut::channel_type::i2c_irq, ut::channel_type::spi}) {
        if (not switch_channel(chn)) {
#ifdef KEYCARD_CI_CD_MACHINE
            ESP_LOGW(TEST_TAG, "Unsupported channel %s, skipping...", ut::to_string(chn));
#endif
            continue;
        }
        unity_perform_pn532_mifare_tests();
    }
    UNITY_END();
}

#ifdef KEYCARD_UNIT_TEST_MAIN

#ifdef __cplusplus
extern "C" {
#endif

void app_main() {
    unity_main();
}

#ifdef __cplusplus
}
#endif

#endif
