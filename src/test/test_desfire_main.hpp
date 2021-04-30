//
// Created by spak on 3/18/21.
//

#ifndef KEYCARD_ACCESS_TEST_DESFIRE_MAIN_HPP
#define KEYCARD_ACCESS_TEST_DESFIRE_MAIN_HPP

#include "registrar.hpp"
#include "test_pn532.hpp"
#include <desfire/tag.hpp>
#include <memory>
#include <pn532/desfire_pcd.hpp>

namespace ut {
    namespace desfire_main {
        using namespace ::desfire;

        static constexpr test_tag_t test_tag = 0xde5f19e;

        struct demo_app {
            app_id aid;
            cipher_type cipher;
            any_key primary_key;
            any_key secondary_key;

            explicit demo_app(cipher_type c);

            void ensure_selected_and_primary(tag &tag) const;
            void ensure_created(tag &tag, any_key const &root_key) const;
        };

        class test_data {
            std::unique_ptr<pn532::desfire_pcd> _pcd = nullptr;
            std::shared_ptr<ut::pn532::test_instance> _hold_test_instance;
            ::desfire::tag _tag;

        public:
            test_data(std::shared_ptr<ut::pn532::test_instance> pn532_test_instance, std::uint8_t card_logical_index);
            explicit test_data(std::unique_ptr<pn532::desfire_pcd> controller);

            [[nodiscard]] pn532::desfire_pcd &controller();
            [[nodiscard]] ::desfire::tag &tag();
        };

    }// namespace desfire_main

    template <>
    struct test_instance<desfire_main::test_tag> : public desfire_main::test_data {
        using desfire_main::test_data::test_data;
    };

    namespace desfire_main {
        using test_instance = test_instance<test_tag>;

        std::shared_ptr<test_instance> try_connect_card(std::shared_ptr<ut::pn532::test_instance> pn532_test_instance);
        std::shared_ptr<test_instance> try_connect_card(pn532::controller &tag_reader);

        void test_mifare_base();
        void test_mifare_uid();
        void test_mifare_create_apps();
        void test_mifare_change_app_key();
        void test_mifare_root_operations();
    }// namespace desfire_main
}// namespace ut

#endif//KEYCARD_ACCESS_TEST_DESFIRE_MAIN_HPP
