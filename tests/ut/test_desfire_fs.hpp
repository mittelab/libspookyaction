//
// Created by spak on 1/7/23.
//

#ifndef SPOOKY_ACTION_TEST_DESFIRE_FS_HPP
#define SPOOKY_ACTION_TEST_DESFIRE_FS_HPP

#include "test_desfire_main.hpp"

namespace ut::fs {
    using namespace ::desfire;

    struct app_fixture_setup : ut::desfire::card_fixture_setup {
        any_key root_key;
        app_id aid;
        any_key master_key;

        explicit app_fixture_setup(desfire::tag &mifare_,
                                   any_key root_key_ = key<cipher_type::des>{},
                                   app_id aid_ = {0x11, 0x22, 0x33},
                                   cipher_type cipher = cipher_type::aes128);

        ~app_fixture_setup();
    };

}// namespace ut::fs


#endif//SPOOKY_ACTION_TEST_DESFIRE_FS_HPP
