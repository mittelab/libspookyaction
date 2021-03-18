//
// Created by spak on 3/18/21.
//

#ifndef KEYCARD_ACCESS_TEST_DESFIRE_HPP
#define KEYCARD_ACCESS_TEST_DESFIRE_HPP

#include "utils.hpp"
#include <memory>
#include <pn532/desfire_pcd.hpp>

namespace test::desfire {

    class instance {
        std::unique_ptr<::pn532::desfire_pcd> _controller = nullptr;
        mutable ::desfire::tag _tag;

    public:
        explicit instance(std::unique_ptr<::pn532::desfire_pcd> controller);
        ~instance();

        instance(instance &&) noexcept = default;
        instance &operator=(instance &&) noexcept = default;

        /**
         * @ref operator* is intended for usage with structure binding, but sometimes one needs a ref.
         * @return
         */
        [[nodiscard]] ::desfire::tag &tag() const;

        /**
         * @code
         * auto &[pcd, tag] = *instance;
         * @endcode
         */
        [[nodiscard]] std::pair<::pn532::desfire_pcd &, ::desfire::tag &> const operator*() const;
    };

    /**
     * @addtogroup TestPrepare
     * These methods will return a callable method that can be used with Unity's RUN_TEST.
     * @note Only one of these methods can be called at a time! The @ref instance parameter will be kept
     *  alive in memory until the test is run or @ref cleanup is called.
     * @{
     */
    ut::test_fn get_test_mifare_base(std::shared_ptr<instance> instance);
    ut::test_fn get_test_mifare_uid(std::shared_ptr<instance> instance);
    ut::test_fn get_test_mifare_create_apps(std::shared_ptr<instance> instance);
    ut::test_fn get_test_mifare_change_app_key(std::shared_ptr<instance> instance);
    ut::test_fn get_test_mifare_root_operations(std::shared_ptr<instance> instance);
    /**
     * @}
     */

    std::shared_ptr<instance> build_instance(::pn532::nfc &tag_reader);

    /**
     * Ensures that dangling instances are successfully discarded.
     */
    void cleanup();

    struct auto_cleanup {
        inline ~auto_cleanup() {
            cleanup();
        }
    };

}// namespace test::desfire

#endif//KEYCARD_ACCESS_TEST_DESFIRE_HPP
