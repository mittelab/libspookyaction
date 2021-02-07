//
// Created by spak on 2/7/21.
//


#include <unity.h>
#include "utils.hpp"

namespace ut {

    static constexpr std::uint8_t secondary_keys_version = 0x10;
    static constexpr std::array<std::uint8_t, 8> secondary_des_key = {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe};
    static constexpr std::array<std::uint8_t, 16> secondary_des3_2k_key = {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e};
    static constexpr std::array<std::uint8_t, 24> secondary_des3_3k_key = {0x0, 0x2, 0x4, 0x6, 0x8, 0xa, 0xc, 0xe, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e, 0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e};
    static constexpr std::array<std::uint8_t, 16> secondary_aes_key = {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};

    unsigned nested_log::_level = 0;

    const char *nested_log::indent() {
        static std::string _buffer{};
        _buffer.resize(2 * _level, ' ');
        return _buffer.c_str();
    }

    std::pair<mlab::bin_data, bool> assert_comm_controller::communicate(const mlab::bin_data &data) {
        auto txrx_pair = std::move(txrx_fifo.front());
        txrx_fifo.pop_front();
        TEST_ASSERT_EQUAL_HEX8_ARRAY(txrx_pair.first.data(), data.data(), std::min(txrx_pair.first.size(), data.size()));
        TEST_ASSERT_EQUAL(txrx_pair.first.size(), data.size());
        return {std::move(txrx_pair.second), true};
    }

    void assert_comm_controller::append(std::initializer_list<std::uint8_t> tx,
                                        std::initializer_list<std::uint8_t> rx) {
        txrx_fifo.push_back(std::make_pair(mlab::bin_data::chain(tx), mlab::bin_data::chain(rx)));
    }

    void test_app::ensure_selected_and_primary(desfire::tag &tag) const {
        TEST_ASSERT(tag.select_application(aid));
        if (not tag.authenticate(primary_key)) {
            TEST_ASSERT(tag.authenticate(secondary_key));
            ESP_LOGI("UT", "Resetting key of app %02x %02x %02x.", aid[0], aid[1], aid[2]);
            TEST_ASSERT(tag.change_key(primary_key));
            TEST_ASSERT(tag.authenticate(primary_key));
        }
    }

    void test_app::ensure_created(desfire::tag &tag, desfire::any_key const &root_key) const {
        TEST_ASSERT(tag.select_application(desfire::root_app));
        TEST_ASSERT(tag.authenticate(root_key));
        const auto r_get_aids = tag.get_application_ids();
        TEST_ASSERT(r_get_aids);
        if (std::find(std::begin(*r_get_aids), std::end(*r_get_aids), aid) == std::end(*r_get_aids)) {
            TEST_ASSERT(tag.create_application(aid, desfire::app_settings{type}));
        }
    }

    void test_file::delete_preexisting(desfire::tag &tag) const {
        const auto r_get_fids = tag.get_file_ids();
        if (std::find(std::begin(*r_get_fids), std::end(*r_get_fids), fid) == std::end(*r_get_fids)) {
            TEST_ASSERT(tag.abort_transaction());
            TEST_ASSERT(tag.delete_file(fid));
        }
    }

    void enable_detailed_log() {
        esp_log_level_set(DESFIRE_TAG, ESP_LOG_DEBUG);
        esp_log_level_set(DESFIRE_TAG " >>", ESP_LOG_DEBUG);
        esp_log_level_set(DESFIRE_TAG " <<", ESP_LOG_DEBUG);
        esp_log_level_set(DESFIRE_TAG " RAW >>", ESP_LOG_DEBUG);
        esp_log_level_set(DESFIRE_TAG " RAW <<", ESP_LOG_DEBUG);
        esp_log_level_set(DESFIRE_TAG " TX MAC", ESP_LOG_DEBUG);
        esp_log_level_set(DESFIRE_TAG " RX MAC", ESP_LOG_DEBUG);
        esp_log_level_set(DESFIRE_TAG " != MAC", ESP_LOG_DEBUG);
        esp_log_level_set(DESFIRE_TAG " CRYPTO", ESP_LOG_DEBUG);
        esp_log_level_set(DESFIRE_TAG " DATA", ESP_LOG_DEBUG);
        esp_log_level_set(DESFIRE_TAG " BLOB", ESP_LOG_DEBUG);
        esp_log_level_set(DESFIRE_TAG "   IV", ESP_LOG_DEBUG);
    }


    ut::test_app const &get_test_app(desfire::cipher_type t) {
        static const ut::test_app dummy{};
        static const ut::test_app app_des{
                {0x00, 0xde, 0x08},
                desfire::key<desfire::cipher_type::des>{0, secondary_des_key, secondary_keys_version}
        };

        static const ut::test_app app_des3_2k{
                {0x00, 0xde, 0x16},
                desfire::key<desfire::cipher_type::des3_2k>{0, secondary_des3_2k_key, secondary_keys_version}
        };

        static const ut::test_app app_des3_3k{
                {0x00, 0xde, 0x24},
                desfire::key<desfire::cipher_type::des3_3k>{0, secondary_des3_3k_key, secondary_keys_version}
        };

        static const ut::test_app app_aes128{
                {0x00, 0xae, 0x16},
                desfire::key<desfire::cipher_type::aes128>{0, secondary_aes_key, secondary_keys_version}
        };
        switch (t) {
            case desfire::cipher_type::des:
                return app_des;
            case desfire::cipher_type::des3_2k:
                return app_des3_2k;
            case desfire::cipher_type::des3_3k:
                return app_des3_3k;
            case desfire::cipher_type::aes128:
                return app_aes128;
            case desfire::cipher_type::none:
                TEST_FAIL_MESSAGE("No app with cipher none.");
                return dummy;
            default:
                TEST_FAIL_MESSAGE("Unknown cipher!");
                return dummy;
        }
    }

    ut::test_file const &get_test_file(desfire::file_type t) {
        static const ut::test_file dummy{};

        static const desfire::generic_file_settings gfs{desfire::comm_mode::plain, desfire::access_rights{0}};
        static const desfire::data_file_settings dfs{.size = 0x100};
        static const desfire::record_file_settings rfs{.record_size = 8, .max_record_count = 2, .record_count = 0};
        static const desfire::value_file_settings vfs{.lower_limit = -10, .upper_limit = 10, .value = 0, .limited_credit_enabled = true};

        static const ut::test_file file_standard{
                0x00,
                desfire::file_settings<desfire::file_type::standard>{gfs, dfs}
        };

        static const ut::test_file file_backup{
                0x00,
                desfire::file_settings<desfire::file_type::backup>{gfs, dfs}
        };

        static const ut::test_file file_value{
                0x00,
                desfire::file_settings<desfire::file_type::value>{gfs, vfs}
        };

        static const ut::test_file file_linear_record{
                0x00,
                desfire::file_settings<desfire::file_type::linear_record>{gfs, rfs}
        };

        static const ut::test_file file_cyclic_record{
                0x00,
                desfire::file_settings<desfire::file_type::cyclic_record>{gfs, rfs}
        };
        switch (t) {
            case desfire::file_type::standard:
                return file_standard;
            case desfire::file_type::backup:
                return file_backup;
            case desfire::file_type::value:
                return file_value;
            case desfire::file_type::linear_record:
                return file_linear_record;
            case desfire::file_type::cyclic_record:
                return file_cyclic_record;
            default:
                TEST_FAIL_MESSAGE("Unknown file type!");
                return dummy;
        }
    }

    ut::test_file get_test_file(desfire::file_type t, desfire::comm_mode mode) {
        ut::test_file retval;
        ut::test_file const &base_file = get_test_file(t);
        // This is basically an implementation for a copy constructor
        // Match type by selecting the right template
        switch (t) {
            case desfire::file_type::standard:
                retval.settings = desfire::file_settings<desfire::file_type::standard>{};
                retval.settings.data_settings() = base_file.settings.data_settings();
                break;
            case desfire::file_type::backup:
                retval.settings = desfire::file_settings<desfire::file_type::backup>{};
                retval.settings.data_settings() = base_file.settings.data_settings();
                break;
            case desfire::file_type::value:
                retval.settings = desfire::file_settings<desfire::file_type::value>{};
                retval.settings.value_settings() = base_file.settings.value_settings();
                break;
            case desfire::file_type::linear_record:
                retval.settings = desfire::file_settings<desfire::file_type::linear_record>{};
                retval.settings.record_settings() = base_file.settings.record_settings();
                break;
            case desfire::file_type::cyclic_record:
                retval.settings = desfire::file_settings<desfire::file_type::cyclic_record>{};
                retval.settings.record_settings() = base_file.settings.record_settings();
                break;
            default: break;
        }
        // These are in common
        retval.settings.generic_settings() = base_file.settings.generic_settings();
        // Update the comm mode
        retval.settings.generic_settings().mode = mode;
        retval.type = t;
        retval.fid = base_file.fid;
        return retval;
    }
}