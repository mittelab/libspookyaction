//
// Created by spak on 3/23/21.
//

#include "test_desfire_files.hpp"
#include <numeric>
#include <unity.h>

namespace ut::desfire_files {
    namespace {
        constexpr const char *missing_instance_msg = "File test instance was not set up.";
    }

    test_data::test_data(std::shared_ptr<ut::desfire_main::test_instance> main_test_instance)
        : _hold_test_instance{std::move(main_test_instance)}, _file{}, _test_load{} {
        _test_load.resize(0x100);
        std::iota(std::begin(_test_load), std::end(_test_load), 0x00);
    }

    tag &test_data::tag() {
        return _hold_test_instance->tag();
    }

    demo_file &test_data::file() {
        return _file;
    }

    bin_data &test_data::test_load() {
        return _test_load;
    }


    void demo_file::delete_if_preexisting(tag &tag) const {
        const auto r_get_fids = tag.get_file_ids();
        TEST_ASSERT(r_get_fids);
        if (std::find(std::begin(*r_get_fids), std::end(*r_get_fids), fid()) != std::end(*r_get_fids)) {
            TEST_ASSERT(tag.abort_transaction());
            TEST_ASSERT(tag.delete_file(fid()));
        }
    }

    const char *demo_file::security_description() const {
        switch (security) {
            case file_security::none:
                return "none";
            case file_security::encrypted:
                return "encrypted";
            case file_security::authenticated:
                return "maced";
        }
        return nullptr;
    }

    const char *demo_file::cipher_description() const {
        switch (cipher) {
            case cipher_type::des:
                return "des";
            case cipher_type::des3_2k:
                return "des3_2k";
            case cipher_type::des3_3k:
                return "des3_3k";
            case cipher_type::aes128:
                return "aes128";
            case bits::cipher_type::none:
                break;
        }
        return nullptr;
    }

    const char *demo_file::type_description() const {
        switch (type) {
            case file_type::standard:
                return "standard";
            case file_type::backup:
                return "backup";
            case file_type::value:
                return "value";
            case file_type::linear_record:
                return "linear_record";
            case file_type::cyclic_record:
                return "cyclic_record";
        }
        return nullptr;
    }

    std::string demo_file::get_description() const {
        std::string buffer;
        buffer.reserve(128);
        // Here the buffer get cleared
        buffer.append("ut::desfire_files::test_file {.cipher=");
        buffer.append(cipher_description());
        buffer.append(", .type=");
        buffer.append(type_description());
        buffer.append(", .security=");
        buffer.append(security_description());
        buffer.append(free_access ? ", .free=true}" : ", .free=false}");
        return buffer;
    }

    file_id demo_file::fid() {
        return 0x00;
    }

    any_file_settings demo_file::get_settings() const {
        static constexpr data_file_settings dfs{.size = 0x100};
        static constexpr record_file_settings rfs{.record_size = 8, .max_record_count = 2, .record_count = 0};
        static constexpr value_file_settings vfs{.lower_limit = -10, .upper_limit = 10, .value = 0, .limited_credit_enabled = true};
        // Select either all keys, or one key (the one we are using
        const generic_file_settings gfs{security, free_access ? access_rights{all_keys} : access_rights{0}};

        switch (type) {
            case file_type::standard:
                return file_settings<file_type::standard>{gfs, dfs};
            case file_type::backup:
                return file_settings<file_type::backup>{gfs, dfs};
            case file_type::value:
                return file_settings<file_type::value>{gfs, vfs};
            case file_type::linear_record:
                return file_settings<file_type::linear_record>{gfs, rfs};
            case file_type::cyclic_record:
                return file_settings<file_type::cyclic_record>{gfs, rfs};
            default:
                ESP_LOGE("UT", "Unknown file type %s.", to_string(type));
                return {};
        }
    }

    void demo_file::test(tag &mifare, bin_data const &test_load) {
        const any_key root_key{key<cipher_type::des>{}};

        // Make sure there is enough space to run. 1376B is a decent estimate for how much space is needed
        TEST_ASSERT(mifare.select_application(root_app))
        TEST_ASSERT(mifare.authenticate(root_key))
        const auto r_free_mem = mifare.get_free_mem();
        TEST_ASSERT(r_free_mem)
        if (*r_free_mem < 1376) {
            ESP_LOGI("UT", "Formatting to recover space (only %d B free).", *r_free_mem);
            TEST_ASSERT(mifare.format_picc())
        }
        const ut::desfire_main::demo_app app{cipher};
        app.ensure_created(mifare, root_key);
        app.ensure_selected_and_primary(mifare);
        TEST_ASSERT_EQUAL_HEX8_ARRAY(app.aid.data(), mifare.active_app().data(), 3);
        TEST_ASSERT_EQUAL(app.primary_key.key_number(), mifare.active_key_no());
        delete_if_preexisting(mifare);
        TEST_ASSERT(mifare.create_file(fid(), get_settings()))

        switch (type) {
            case file_type::standard:
                test_standard_data_file(mifare, test_load);
                break;
            case file_type::backup:
                test_backup_data_file(mifare, test_load);
                break;
            case file_type::value:
                test_value_file(mifare);
                break;
            case file_type::linear_record:
                [[fallthrough]];
            case file_type::cyclic_record:
                test_record_file(mifare);
                break;
        }
        TEST_ASSERT(mifare.change_file_settings(fid(), get_settings().generic_settings(), trust_card));
        TEST_ASSERT(mifare.delete_file(fid()))
    }

    void demo_file::test_standard_data_file(tag &mifare, bin_data const &load) const {
        TEST_ASSERT(mifare.write_data(fid(), 0, load, trust_card))
        const auto r_read = mifare.read_data(fid(), 0, load.size(), trust_card);
        TEST_ASSERT(r_read)
        TEST_ASSERT_EQUAL(load.size(), r_read->size());
        TEST_ASSERT_EQUAL_HEX8_ARRAY(load.data(), r_read->data(), load.size());
    }

    void demo_file::test_backup_data_file(tag &mifare, bin_data const &load) const {
        TEST_ASSERT(mifare.write_data(fid(), 0, load, trust_card))
        const auto r_read_before_commit = mifare.read_data(fid(), 0, load.size(), trust_card);
        TEST_ASSERT(r_read_before_commit)
        TEST_ASSERT_EACH_EQUAL_HEX8(0x00, r_read_before_commit->data(), r_read_before_commit->size());
        TEST_ASSERT(mifare.commit_transaction())
        const auto r_read = mifare.read_data(fid(), 0, load.size(), trust_card);
        TEST_ASSERT(r_read)
        TEST_ASSERT_EQUAL(load.size(), r_read->size());
        TEST_ASSERT_EQUAL_HEX8_ARRAY(load.data(), r_read->data(), load.size());
    }

    void demo_file::test_value_file(tag &mifare) const {
        const auto test_get_value = [&](std::int32_t expected) {
            const auto res_read = mifare.get_value(fid(), trust_card);
            TEST_ASSERT(res_read)
            TEST_ASSERT_EQUAL(expected, *res_read);
        };

        test_get_value(0);
        TEST_ASSERT(mifare.credit(fid(), 2, trust_card))
        test_get_value(0);// Did not commit yet
        TEST_ASSERT(mifare.commit_transaction())
        test_get_value(2);
        TEST_ASSERT(mifare.debit(fid(), 5, trust_card))
        TEST_ASSERT(mifare.commit_transaction())
        test_get_value(-3);
    }

    void demo_file::test_record_file(tag &mifare) const {
        using record_t = std::array<std::uint8_t, 8>;

        const mlab::bin_data nibble = {0x00, 0x01, 0x02, 0x03};

        const auto test_get_record_count = [&](std::uint32_t expected) {
            const auto res_settings = mifare.get_file_settings(fid());
            TEST_ASSERT(res_settings)
            TEST_ASSERT_EQUAL(expected, res_settings->record_settings().record_count);
        };

        test_get_record_count(0);
        TEST_ASSERT(mifare.write_record(fid(), 4, nibble, trust_card))
        TEST_ASSERT(mifare.commit_transaction())
        test_get_record_count(1);
        const auto res_records = mifare.read_parse_records<record_t>(fid(), trust_card, 0, bits::all_records);
        TEST_ASSERT(res_records)
        TEST_ASSERT_EQUAL(res_records->size(), 1);
        const record_t expected = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03};
        TEST_ASSERT_EQUAL_HEX8_ARRAY(expected.data(), res_records->front().data(), 8);
        TEST_ASSERT(mifare.clear_record_file(fid()))
        TEST_ASSERT(mifare.commit_transaction())
    }

    void test_file() {
        auto instance = default_registrar().get<test_instance>();
        if (instance == nullptr) {
            TEST_FAIL_MESSAGE(missing_instance_msg);
            return;
        }
        instance->file().test(instance->tag(), instance->test_load());
    }

}// namespace ut::desfire_files