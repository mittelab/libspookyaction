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

namespace ut::pn532 {
    using namespace ::pn532;

    [[nodiscard]] std::unique_ptr<channel> try_activate_channel(channel_type type);

    template <channel_type CT>
    struct channel_fixture {
        std::unique_ptr<channel> chn = try_activate_channel(CT);
        std::unique_ptr<controller> ctrl = chn ? std::make_unique<controller>(*chn) : nullptr;

        [[nodiscard]] virtual inline explicit operator bool() const { return chn and ctrl; }
    };


}// namespace ut::pn532


#endif//SPOOKY_ACTION_TEST_PN532_HPP
