//
// Created by spak on 2/7/21.
//

#ifndef SPOOKY_ACTION_UTILS_HPP
#define SPOOKY_ACTION_UTILS_HPP

#include <esp_log.h>
#include <initializer_list>
#include <utility>
#include <vector>
#include <unity.h>

#define UNITY_PATCH_TEST_FILE auto _patch_test_file = unity_patch_test_file{__FILE__}

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


    struct suppress_log {
        std::vector<std::pair<const char *, esp_log_level_t>> tag_log_lev;

        explicit suppress_log(std::initializer_list<const char *> tags);
        void suppress();
        void restore();
        ~suppress_log();
    };


}// namespace ut

#endif//SPOOKY_ACTION_UTILS_HPP
