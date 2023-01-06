//
// Created by spak on 3/23/21.
//

#ifndef SPOOKY_ACTION_TEST_DESFIRE_FILES_HPP
#define SPOOKY_ACTION_TEST_DESFIRE_FILES_HPP

#include "registrar.hpp"
#include "test_desfire_main.hpp"


namespace ut {
    namespace desfire_files {
        using namespace ::desfire;

        static constexpr test_tag_t test_tag = 0xde5f11e;

        struct demo_file {
            cipher_type cipher = cipher_type::des;
            file_type type = file_type::standard;
            file_security security = file_security::none;

            [[nodiscard]] static file_id fid();

            [[nodiscard]] any_file_settings get_settings() const;

            void delete_if_preexisting(tag &tag) const;

            void test(tag &tag, bin_data const &test_load);

            [[nodiscard]] const char *security_description() const;

            [[nodiscard]] const char *cipher_description() const;

            [[nodiscard]] const char *type_description() const;

            [[nodiscard]] std::string get_description() const;

        private:
            void test_standard_data_file(tag &mifare, bin_data const &load) const;
            void test_backup_data_file(tag &mifare, bin_data const &load) const;
            void test_value_file(tag &mifare) const;
            void test_record_file(tag &mifare) const;
        };

        class test_data {
            std::shared_ptr<ut::desfire_main::test_instance> _hold_test_instance;
            demo_file _file;
            bin_data _test_load;

        public:
            explicit test_data(std::shared_ptr<ut::desfire_main::test_instance> main_test_instance);

            [[nodiscard]] ::desfire::tag &tag();
            [[nodiscard]] demo_file &file();
            [[nodiscard]] bin_data &test_load();
        };

    }// namespace desfire_files

    template <>
    struct test_instance<desfire_files::test_tag> : public desfire_files::test_data {
        using desfire_files::test_data::test_data;
    };

    namespace desfire_files {
        using test_instance = test_instance<test_tag>;

        void test_file();
    }// namespace desfire_files
}// namespace ut

#endif//SPOOKY_ACTION_TEST_DESFIRE_FILES_HPP
