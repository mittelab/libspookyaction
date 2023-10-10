//
// Created by spak on 3/18/21.
//

#include "test_desfire_main.hpp"
#include <desfire/esp32/cipher_provider.hpp>
#include <desfire/esp32/utils.hpp>

#define TEST_TAG "UT"

using namespace std::chrono_literals;

namespace ut::desfire {

    namespace {
        constexpr std::uint8_t secondary_keys_version = 0x10;
        constexpr desfire::key_body<8> secondary_des_key = {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe};
        constexpr desfire::key_body<16> secondary_des3_2k_key = {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e};
        constexpr desfire::key_body<24> secondary_des3_3k_key = {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e, 0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e};
        constexpr desfire::key_body<16> secondary_aes_key = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};

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

        [[nodiscard]] any_key const &default_key() {
            static const any_key _retval = key<cipher_type::des>{};
            return _retval;
        }

        [[nodiscard]] std::vector<any_key> get_root_key_candidates() {
            std::vector<any_key> candidates;
            candidates.emplace_back(default_key());// Default key

            for (cipher_type cipher : {cipher_type::des, cipher_type::des3_2k,
                                       cipher_type::des3_3k, cipher_type::aes128}) {
                const demo_app app{cipher};
                // Copy the keys from the test apps
                candidates.emplace_back(app.primary_key);
                candidates.emplace_back(app.secondary_key);
            }

            return candidates;
        }

        [[nodiscard]] std::vector<any_key> const &root_key_candidates() {
            static const auto _retval = get_root_key_candidates();
            return _retval;
        }

    }// namespace

    std::unique_ptr<tag> try_activate_card(pn532::channel &chn, pn532::controller &ctrl) {
        if (not chn.wake()) {
            ESP_LOGE(TEST_TAG, "Unable to wake channel.");
            return nullptr;
        }
        if (const auto r = ctrl.sam_configuration(pn532::sam_mode::normal, 1s); not r) {
            ESP_LOGE(TEST_TAG, "Unable to configure SAM, %s", ::pn532::to_string(r.error()));
            return nullptr;
        }
        ESP_LOGI(TEST_TAG, "Please bring card close now (searching for one passive 106 kbps target)...");
        if (const auto r_scan = ctrl.initiator_list_passive_kbps106_typea(1); r_scan) {
            if (not r_scan->empty()) {
                ESP_LOGI(TEST_TAG, "Found a target:");
                auto const &nfcid = r_scan->front().nfcid;
                ESP_LOG_BUFFER_HEX_LEVEL(TEST_TAG, nfcid.data(), nfcid.size(), ESP_LOG_INFO);

                return std::make_unique<tag>(
                        tag::make<desfire::esp32::default_cipher_provider>(ctrl, r_scan->front().logical_index));
            }
            ESP_LOGE(TEST_TAG, "No tag found.");
        } else {
            ESP_LOGE(TEST_TAG, "Unable to scan for targets: %s", ::pn532::to_string(r_scan.error()));
        }
        return nullptr;
    }

    card_fixture_setup::card_fixture_setup(desfire::tag &mifare_) : mifare{mifare_} {
        ESP_LOGI(TEST_TAG, "Attempt to recover the root key.");
        REQUIRE(mifare.select_application(root_app));
        for (auto const &key : root_key_candidates()) {
            auto suppress = desfire::esp32::suppress_log{DESFIRE_LOG_PREFIX};
            if (mifare.authenticate(key)) {
                suppress.restore();
                ESP_LOGI(TEST_TAG, "Found the right key, changing to default.");
                if (key == default_key()) {
                    return;
                }
                REQUIRE(mifare.change_key(default_key()));
                REQUIRE(mifare.authenticate(default_key()));
            }
        }
        ESP_LOGE(TEST_TAG, "All the know default keys failed to authenticate root app.");
    }

    card_fixture_setup::~card_fixture_setup() {
        REQUIRE(mifare.select_application(root_app));
        REQUIRE(mifare.authenticate(default_key()));
        ESP_LOGW(TEST_TAG, "Formatting card.");
        REQUIRE(mifare.format_picc());
    }

    demo_app::demo_app(cipher_type c)
        : aid{get_default_aid(c)},
          cipher{c},
          primary_key{get_primary_key(c)},
          secondary_key{get_secondary_key(c)} {}

    void demo_app::ensure_selected_and_primary(tag &tag) const {
        if (tag.active_app() != aid) {
            REQUIRE(tag.select_application(aid));
        }
        if (tag.active_key_no() != primary_key.key_number()) {
            if (not tag.authenticate(primary_key)) {
                REQUIRE(tag.authenticate(secondary_key));
                ESP_LOGI("UT", "Resetting key of app %02x %02x %02x.", aid[0], aid[1], aid[2]);
                REQUIRE(tag.change_key(primary_key));
                REQUIRE(tag.authenticate(primary_key));
            }
        }
    }

    void demo_app::ensure_created(tag &tag, any_key const &root_key) const {
        if (tag.active_app() != root_app) {
            REQUIRE(tag.select_application(root_app));
        }
        if (tag.active_key_no() != root_key.key_number()) {
            REQUIRE(tag.authenticate(root_key));
        }
        const auto r_get_aids = tag.get_application_ids();
        REQUIRE(r_get_aids);
        if (std::find(std::begin(*r_get_aids), std::end(*r_get_aids), aid) == std::end(*r_get_aids)) {
            REQUIRE(tag.create_application(aid, app_settings{cipher}));
        }
    }

    using pn532::channel_type;

    TEMPLATE_TEST_CASE_METHOD_SIG(card_fixture, "0030 Mifare base test", "",
                                  ((channel_type CT), CT),
                                  channel_type::hsu, channel_type::i2c, channel_type::i2c_irq, channel_type::spi, channel_type::spi_irq) {
        if (not channel_is_supported(CT)) {
            SKIP("Unsupported channel type " << ut::pn532::to_string(CT));
        }

        REQUIRE(*this);
        card_fixture_setup fmt{*this->mifare};

        REQUIRE(this->mifare->select_application(root_app));
        REQUIRE(this->mifare->authenticate(key<cipher_type::des>{}));

        auto r_settings = this->mifare->get_app_settings();
        REQUIRE(r_settings);
        r_settings->rights.dir_access_without_auth = true;
        r_settings->rights.create_delete_without_master_key = false;

        REQUIRE(this->mifare->change_app_settings(r_settings->rights));

        const auto r_info = this->mifare->get_info();
        CHECKED_IF(r_info) {
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

            const auto r_get_uid = this->mifare->get_card_uid();
            CHECKED_IF(r_get_uid) {
                CHECK(r_info->serial_no == *r_get_uid);
            }
        }

        const auto r_mem = this->mifare->get_free_mem();
        CHECKED_IF(r_mem) {
            ESP_LOGI(TEST_TAG, " free mem [B]: %lu", *r_mem);
        }
    }


    TEMPLATE_TEST_CASE_METHOD_SIG(card_fixture, "0031 Mifare root-level operations", "",
                                  ((channel_type CT), CT),
                                  channel_type::hsu, channel_type::i2c, channel_type::i2c_irq, channel_type::spi, channel_type::spi_irq) {
        if (not channel_is_supported(CT)) {
            SKIP("Unsupported channel type " << ut::pn532::to_string(CT));
        }
        REQUIRE(*this);
        card_fixture_setup fmt{*this->mifare};

        REQUIRE(this->mifare->active_app() == root_app);
        REQUIRE(this->mifare->active_key_no() == 0);

        const app_id test_app_id = {0x00, 0x7e, 0x57};

        ESP_LOGI(TEST_TAG, "Begin key test cycle.");
        for (auto const &key : root_key_candidates()) {
            REQUIRE(this->mifare->change_key(key));
            ESP_LOGI(TEST_TAG, "Changed root key to %s, testing root level ops.", to_string(key.type()));
            REQUIRE(this->mifare->authenticate(key));
            // Do bunch of operations on applications that can only be done at the root level, so that we can verify the
            // trasmission modes for the root level app
            auto r_list = this->mifare->get_application_ids();
            CHECKED_IF(r_list) {
                if (std::find(std::begin(*r_list), std::end(*r_list), test_app_id) != std::end(*r_list)) {
                    // Remove preexisting app
                    REQUIRE(this->mifare->delete_application(test_app_id));
                }
            }
            REQUIRE(this->mifare->create_application(test_app_id, app_settings()));
            r_list = this->mifare->get_application_ids();
            CHECKED_IF(r_list) {
                CHECKED_IF(not r_list->empty()) {
                    REQUIRE(std::find(std::begin(*r_list), std::end(*r_list), test_app_id) != std::end(*r_list));
                }
            }
            REQUIRE(this->mifare->select_application(test_app_id));
            REQUIRE(this->mifare->select_application(root_app));
            REQUIRE(this->mifare->authenticate(key));
            REQUIRE(this->mifare->delete_application(test_app_id));
            // Also format picc will CMAC
            REQUIRE(this->mifare->format_picc());
            REQUIRE(this->mifare->select_application(root_app));
            // Master key survives format
            REQUIRE(this->mifare->authenticate(key));
        }

        // Cleanup
        REQUIRE(this->mifare->change_key(default_key()));
    }

    TEMPLATE_TEST_CASE_METHOD_SIG(card_fixture, "0032 Mifare create apps", "",
                                  ((channel_type CT), CT),
                                  channel_type::hsu, channel_type::i2c, channel_type::i2c_irq, channel_type::spi, channel_type::spi_irq) {
        if (not channel_is_supported(CT)) {
            SKIP("Unsupported channel type " << ut::pn532::to_string(CT));
        }
        using namespace mlab_literals;

        REQUIRE(*this);
        card_fixture_setup fmt{*this->mifare};

        std::map<app_id, bool> found_ids{};

        for (cipher_type cipher : {cipher_type::des, cipher_type::des3_2k,
                                   cipher_type::des3_3k, cipher_type::aes128}) {
            const demo_app app{cipher};
            ESP_LOGI(TEST_TAG, "Creating app with cipher %s.", to_string(cipher));
            REQUIRE(this->mifare->select_application(root_app));
            REQUIRE(this->mifare->authenticate(default_key()));
            REQUIRE(this->mifare->create_application(app.aid, app_settings{cipher}));
            REQUIRE(this->mifare->select_application(app.aid));
            REQUIRE(this->mifare->authenticate(app.primary_key));
            // Save this id
            found_ids[app.aid] = false;
        }

        REQUIRE(this->mifare->select_application(root_app));
        const auto r_app_ids = this->mifare->get_application_ids();
        CHECKED_IF(r_app_ids) {
            REQUIRE(r_app_ids->size() >= 4);
            for (std::size_t i = 0; i < r_app_ids->size(); ++i) {
                app_id const &aid = r_app_ids->at(i);
                ESP_LOGI(TEST_TAG, "  %d. AID %02x %02x %02x", i + 1, aid[0], aid[1], aid[2]);
                if (auto it = found_ids.find(aid); it != std::end(found_ids)) {
                    REQUIRE_FALSE(it->second);
                    it->second = true;
                }
            }
            REQUIRE(std::all_of(std::begin(found_ids), std::end(found_ids), [](auto kvp) { return kvp.second; }));
        }

        for (cipher_type cipher : {cipher_type::des, cipher_type::des3_2k,
                                   cipher_type::des3_3k, cipher_type::aes128}) {
            const demo_app app{cipher};
            ESP_LOGI(TEST_TAG, "Changing same key of app with cipher %s.", to_string(app.primary_key.type()));
            REQUIRE(this->mifare->select_application(app.aid));
            if (not this->mifare->authenticate(app.primary_key)) {
                ESP_LOGW(TEST_TAG, "Default key not working, attempting secondary key and reset...");
                REQUIRE(this->mifare->authenticate(app.secondary_key));
                REQUIRE(this->mifare->change_key(app.primary_key));
                ESP_LOGI(TEST_TAG, "Reset app key to default, continuing!");
                REQUIRE(this->mifare->authenticate(app.primary_key));
            }
            REQUIRE(this->mifare->change_key(app.secondary_key));
            REQUIRE(this->mifare->authenticate(app.secondary_key));
            const auto res_key_version = this->mifare->get_key_version(app.secondary_key.key_number());
            CHECKED_IF(res_key_version) {
                CHECK(app.secondary_key.version() == *res_key_version);
            }
            auto res_key_settings = this->mifare->get_app_settings();
            REQUIRE(res_key_settings);
            res_key_settings->rights.dir_access_without_auth = true;
            REQUIRE(this->mifare->change_app_settings(res_key_settings->rights));
            res_key_settings->rights.dir_access_without_auth = false;
            REQUIRE(this->mifare->change_app_settings(res_key_settings->rights));
            REQUIRE(this->mifare->change_key(app.primary_key));

            REQUIRE(res_key_settings->max_num_keys > 2);
            res_key_settings->rights.allowed_to_change_keys = 0_b;
            REQUIRE(this->mifare->authenticate(app.primary_key));
            REQUIRE(this->mifare->change_app_settings(res_key_settings->rights));
            res_key_settings = this->mifare->get_app_settings();
            REQUIRE(res_key_settings);
            REQUIRE(res_key_settings->rights.allowed_to_change_keys == 0_b);
            REQUIRE(app.primary_key.key_number() == 0);
            REQUIRE(this->mifare->authenticate(app.primary_key));
            const auto next_key_old = any_key{cipher}.with_key_number(1);
            REQUIRE(next_key_old.key_number() == 1);
            REQUIRE(this->mifare->authenticate(next_key_old));
            REQUIRE(this->mifare->authenticate(app.primary_key));
            const auto next_key_new = app.secondary_key.with_key_number(1);
            REQUIRE(next_key_new.key_number() == 1);
            REQUIRE(this->mifare->change_key(next_key_old, next_key_new));
            REQUIRE(this->mifare->authenticate(next_key_new));
            REQUIRE(this->mifare->authenticate(app.primary_key));
            REQUIRE(this->mifare->change_key(next_key_new, next_key_old));
        }
    }

}// namespace ut::desfire
