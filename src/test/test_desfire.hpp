//
// Created by spak on 3/18/21.
//

#ifndef KEYCARD_ACCESS_TEST_DESFIRE_HPP
#define KEYCARD_ACCESS_TEST_DESFIRE_HPP

#include "registrar.hpp"
#include "test_pn532.hpp"
#include <desfire/tag.hpp>
#include <memory>
#include <pn532/desfire_pcd.hpp>

namespace ut {
    namespace desfire {
        using namespace ::desfire;

        static constexpr test_tag_t test_tag = 0xde5f19e;

        class test_data {
            std::unique_ptr<pn532::desfire_pcd> _controller = nullptr;
            [[maybe_unused]] std::shared_ptr<ut::pn532::test_instance> _hold_test_instance;
            ::desfire::tag _tag;

        public:
            test_data(std::shared_ptr<ut::pn532::test_instance> pn532_test_instance, std::uint8_t card_logical_index);
            explicit test_data(std::unique_ptr<pn532::desfire_pcd> controller);

            [[nodiscard]] pn532::desfire_pcd &controller();
            [[nodiscard]] ::desfire::tag &tag();
        };
    }// namespace desfire

    template <>
    struct test_instance<desfire::test_tag> : public desfire::test_data {
        using desfire::test_data::test_data;
    };

    namespace desfire {
        using test_instance = test_instance<test_tag>;

        std::shared_ptr<test_instance> try_connect_card(std::shared_ptr<ut::pn532::test_instance> pn532_test_instance);
        std::shared_ptr<test_instance> try_connect_card(pn532::nfc &tag_reader);

        void test_mifare_base();
        void test_mifare_uid();
        void test_mifare_create_apps();
        void test_mifare_change_app_key();
        void test_mifare_root_operations();
    }// namespace desfire
}// namespace ut

#endif//KEYCARD_ACCESS_TEST_DESFIRE_HPP
