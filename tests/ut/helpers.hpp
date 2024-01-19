//
// Created by spak on 26/10/23.
//

#ifndef TESTS_HELPERS_HPP
#define TESTS_HELPERS_HPP

#include <desfire/tag.hpp>
#include <memory>

namespace ut {

    struct demo_app {
        desfire::cipher_type cipher;
        desfire::app_id aid;
        desfire::any_key master_key;
        desfire::any_key secondary_key;

        explicit demo_app(desfire::cipher_type cipher_);
    };

    /**
     * Use within test cases. Recovers root password if it can and then formats upon destruction.
     * In case of failure, aborts the test case.
     */
    struct ensure_card_formatted {
        std::shared_ptr<desfire::tag> card;

        [[nodiscard]] static desfire::any_key const &default_root_key();
        [[nodiscard]] static std::vector<desfire::any_key> const &root_key_candidates();

        bool format();

        explicit ensure_card_formatted(std::shared_ptr<desfire::tag> card_);
        ~ensure_card_formatted();
    };

    /**
     * Use within test cases. Ensure a @ref demo_app of the given @p cipher type exists on the card,
     * and destroys it upon destruction.
     * In case of failure, aborts the test case.
     */
    struct ensure_demo_app {
        std::shared_ptr<desfire::tag> card;
        desfire::any_key root_key;
        demo_app app;

        explicit ensure_demo_app(std::shared_ptr<desfire::tag> card_, demo_app app_, desfire::any_key root_key_ = desfire::key<desfire::cipher_type::des>{});
        ~ensure_demo_app();

    private:
        bool delete_if_exists();
    };


}// namespace ut

#endif//TESTS_HELPERS_HPP
