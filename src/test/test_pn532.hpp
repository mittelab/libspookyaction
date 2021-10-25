//
// Created by spak on 3/17/21.
//

#ifndef KEYCARD_ACCESS_TEST_PN532_HPP
#define KEYCARD_ACCESS_TEST_PN532_HPP

#include "pn532_pinout.hpp"
#include "registrar.hpp"
#include <memory>
#include <pn532/controller.hpp>

namespace ut {

    namespace pn532 {
        using namespace ::pn532;

        static constexpr test_tag_t test_tag = 0x532;

        class test_data {
            std::unique_ptr<pn532::channel> _channel = nullptr;
            pn532::controller _tag_reader;
            bool _channel_did_wake;

        public:
            explicit test_data(std::unique_ptr<pn532::channel> channel);

            [[nodiscard]] inline bool channel_did_wake() const;

            inline void mark_channel_did_wake();

            [[nodiscard]] pn532::channel &channel();
            [[nodiscard]] pn532::controller &tag_reader();
        };


    }// namespace pn532

    template <>
    struct test_instance<pn532::test_tag> : public pn532::test_data {
        using pn532::test_data::test_data;
    };

    namespace pn532 {
        using test_instance = test_instance<test_tag>;

        std::shared_ptr<test_instance> try_activate_channel(channel_type type);

        [[nodiscard]] const char *to_string(channel_type type);

        void test_wake_channel();
        void test_get_fw();
        void test_diagnostics();
        void test_scan_mifare();
        void test_scan_all();
        void test_pn532_cycle_rf();
        void test_data_exchange();

    }// namespace pn532
}// namespace ut

namespace ut::pn532 {

    bool test_data::channel_did_wake() const {
        return _channel_did_wake;
    }

    void test_data::mark_channel_did_wake() {
        _channel_did_wake = true;
    }
}// namespace ut::pn532

#endif//KEYCARD_ACCESS_TEST_PN532_HPP
