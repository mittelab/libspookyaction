//
// Created by spak on 2/7/21.
//

#ifndef SPOOKY_ACTION_UTILS_HPP
#define SPOOKY_ACTION_UTILS_HPP

#include <esp_log.h>

namespace ut {

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
        const char *const tag;
        esp_log_level_t const previous_log_level;

        explicit suppress_log(const char *tag_);
        void suppress();
        void restore();
        ~suppress_log();
    };


}// namespace ut

#endif//SPOOKY_ACTION_UTILS_HPP
