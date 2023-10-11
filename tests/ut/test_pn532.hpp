//
// Created by spak on 3/17/21.
//

#ifndef SPOOKY_ACTION_TEST_PN532_HPP
#define SPOOKY_ACTION_TEST_PN532_HPP

#include "pn532_pinout.hpp"
#include "registrar.hpp"
#include <catch.hpp>
#include <memory>
#include <pn532/controller.hpp>
#include <thread>

namespace ut::pn532 {
    using namespace ::pn532;

    [[nodiscard]] std::unique_ptr<channel> try_activate_channel(channel_type type);

    template <channel_type CT>
    struct channel_fixture {
        std::unique_ptr<channel> chn = try_activate_channel(CT);
        std::unique_ptr<controller> ctrl = chn ? std::make_unique<controller>(*chn) : nullptr;

        /**
         * @note We must power down the PN532 if we want to launch sam_configuration at every test case.
         * When powering down, also ensure to wait some time otherwise it might miss the next wake call.
         */
        ~channel_fixture() {
            if (ctrl) {
                ctrl->power_down({wakeup_source::hsu, wakeup_source::spi, wakeup_source::i2c});
                std::this_thread::sleep_for(50ms);
            }
        }

        [[nodiscard]] virtual inline explicit operator bool() const { return chn and ctrl; }
    };


}// namespace ut::pn532


#endif//SPOOKY_ACTION_TEST_PN532_HPP
