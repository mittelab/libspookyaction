//
// Created by spak on 1/7/23.
//

#ifndef SPOOKY_ACTION_TEST_DESFIRE_FS_HPP
#define SPOOKY_ACTION_TEST_DESFIRE_FS_HPP

#include "registrar.hpp"
#include "test_desfire_main.hpp"

namespace ut {
    namespace fs {
        using namespace ::desfire;

        static constexpr test_tag_t test_tag = 0xf5;

        class test_data {
            std::shared_ptr<ut::desfire_main::test_instance> _hold_test_instance;

        public:
            explicit test_data(std::shared_ptr<ut::desfire_main::test_instance> main_test_instance);

            [[nodiscard]] ::desfire::tag &tag();
        };

    }// namespace fs

    template <>
    struct test_instance<fs::test_tag> : public fs::test_data {
        using fs::test_data::test_data;
    };

    namespace fs {
        using test_instance = test_instance<fs::test_tag>;

        void test_app();
        void test_ro_app();
        void test_file();
        void test_ro_data_file();
        void test_ro_value_file();
    }// namespace fs
}// namespace ut

#endif//SPOOKY_ACTION_TEST_DESFIRE_FS_HPP