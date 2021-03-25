//
// Created by spak on 2/7/21.
//

#ifndef KEYCARD_ACCESS_UTILS_HPP
#define KEYCARD_ACCESS_UTILS_HPP

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

    [[maybe_unused]] void enable_debug_log(log_options options);

}// namespace ut

#endif//KEYCARD_ACCESS_UTILS_HPP
