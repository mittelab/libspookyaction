//
// Created by spak on 2/7/21.
//

#ifndef KEYCARD_ACCESS_UTILS_HPP
#define KEYCARD_ACCESS_UTILS_HPP

#include <desfire/tag.hpp>
#include <list>

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

    struct test_app {
        ::desfire::app_id aid = {{0xff, 0xff, 0xff}};
        ::desfire::cipher_type type = ::desfire::cipher_type::none;
        ::desfire::any_key primary_key;
        ::desfire::any_key secondary_key;

        test_app() = default;

        template <::desfire::cipher_type Type>
        test_app(::desfire::app_id aid_, ::desfire::key<Type> sec_key) : aid{aid_},
                                                                         type{Type},
                                                                         primary_key{::desfire::key<Type>{}},
                                                                         secondary_key{std::move(sec_key)} {}

        void ensure_selected_and_primary(::desfire::tag &tag) const;
        void ensure_created(::desfire::tag &tag, ::desfire::any_key const &root_key) const;
    };

    struct test_file {
        ::desfire::file_id fid = 0x00;
        ::desfire::file_type type = ::desfire::file_type::standard;
        ::desfire::any_file_settings settings;

        test_file() = default;

        template <::desfire::file_type Type>
        test_file(::desfire::file_id fid_, ::desfire::file_settings<Type> settings_) : fid{fid_},
                                                                                       type{Type},
                                                                                       settings{std::move(settings_)} {}

        void delete_preexisting(::desfire::tag &tag) const;
    };

    [[nodiscard]] ut::test_app const &get_test_app(::desfire::cipher_type t);
    [[nodiscard]] ut::test_file const &get_test_file(::desfire::file_type t);
    [[nodiscard]] ut::test_file get_test_file(::desfire::file_type t, ::desfire::file_security security);

}// namespace ut

namespace ut {


}// namespace ut

#endif//KEYCARD_ACCESS_UTILS_HPP
