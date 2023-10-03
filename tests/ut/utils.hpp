//
// Created by spak on 2/7/21.
//

#ifndef SPOOKY_ACTION_UTILS_HPP
#define SPOOKY_ACTION_UTILS_HPP

#include <esp_log.h>
#include <initializer_list>
#include <unity.h>
#include <utility>
#include <vector>

#define UNITY_PATCH_TEST_FILE \
    auto _patch_test_file = unity_patch_test_file { __FILE__ }

namespace ut {

    struct unity_patch_test_file {
        const char *prev_test_file;
        explicit unity_patch_test_file(const char *new_file);
        ~unity_patch_test_file();
    };

    struct log_options {
        bool generic;
        bool plain_data;
        bool mac_cmac;
        bool raw_data;
        bool crypto_operations;
        bool reveal_keys;
    };

    [[maybe_unused]] static constexpr log_options log_everything{true, true, true, true, true, true};
    [[maybe_unused]] static constexpr log_options log_debug{true, true, true, true, false, false};
    [[maybe_unused]] static constexpr log_options log_crypto{false, false, false, false, true, false};
    [[maybe_unused]] static constexpr log_options log_nothing{false, false, false, false, false, false};

    [[maybe_unused]] void enable_debug_log(log_options options);


}// namespace ut

#endif//SPOOKY_ACTION_UTILS_HPP
