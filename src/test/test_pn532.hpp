//
// Created by spak on 3/17/21.
//

#ifndef KEYCARD_ACCESS_TEST_PN532_HPP
#define KEYCARD_ACCESS_TEST_PN532_HPP

#include "utils.hpp"
#include <memory>
#include <pn532/nfc.hpp>


namespace test::pn532 {

    class instance {
        std::unique_ptr<::pn532::channel> _channel = nullptr;
        mutable ::pn532::nfc _tag_reader;

    public:
        explicit instance(std::unique_ptr<::pn532::channel> channel);

        instance(instance &&) noexcept = default;
        instance &operator=(instance &&) noexcept = default;

        /**
         * @ref operator* is intended for usage with structure binding, but sometimes one needs a ref.
         * @return
         */
        [[nodiscard]] ::pn532::nfc &tag_reader() const;

        /**
         * @code
         * auto &[channel, tag_reader] = *instance;
         * @endcode
         */
        [[nodiscard]] std::pair<::pn532::channel &, ::pn532::nfc &> const operator*() const;
    };

    enum struct channel_type {
        hsu,
        i2c,
        i2c_irq,
        spi
    };

    /**
     * @addtogroup TestPrepare
     * These methods will return a callable method that can be used with Unity's RUN_TEST.
     * @note Only one of these methods can be called at a time! The @ref instance parameter will be kept
     *  alive in memory until the test is run or @ref cleanup is called.
     * @{
     */
    ut::test_fn get_test_wake_channel(std::shared_ptr<instance> instance, bool *store_success);
    ut::test_fn get_test_get_fw(std::shared_ptr<instance> instance);
    ut::test_fn get_test_diagnostics(std::shared_ptr<instance> instance);
    ut::test_fn get_test_scan_mifare(std::shared_ptr<instance> instance);
    ut::test_fn get_test_scan_all(std::shared_ptr<instance> instance);
    ut::test_fn get_test_pn532_cycle_rf(std::shared_ptr<instance> instance);
    ut::test_fn get_test_data_exchange(std::shared_ptr<instance> instance);
    /**
     * @}
     */


    /**
     * On the CI/CD machine, will select the correct mode on the PN532 and power cycle.
     */
    std::shared_ptr<instance> activate_channel(channel_type type);

    /**
     * Ensures that dangling instances are successfully discarded.
     */
    void cleanup();

    struct auto_cleanup {
        inline ~auto_cleanup() {
            cleanup();
        }
    };


    [[nodiscard]] const char *to_string(channel_type type);

}// namespace test::pn532

#endif//KEYCARD_ACCESS_TEST_PN532_HPP
