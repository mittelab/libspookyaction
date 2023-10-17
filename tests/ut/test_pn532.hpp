//
// Created by spak on 3/17/21.
//

#ifndef SPOOKY_ACTION_TEST_PN532_HPP
#define SPOOKY_ACTION_TEST_PN532_HPP

#include <catch.hpp>
#include <memory>
#include <pn532/controller.hpp>
#include <thread>

namespace ut::pn532 {
    using namespace ::pn532;
    enum struct channel_type {
        none,
        hsu,
        i2c,
        i2c_irq,
        spi,
        spi_irq
    };

    [[nodiscard]] const char *to_string(channel_type type);

    class status {
        std::unique_ptr<channel> _channel;
        std::shared_ptr<controller> _controller;
        channel_type _active_channel;

        /**
         * Puts the PN532 in power down mode, if active, and removes the power, if possible.
         */
        void power_down();

        /**
         * Re-enables power on the PN532.
         */
        void power_up();

        /**
         * Power up, calls @ref channel::wake and @ref controller::sam_configuration.
         * Makes 3 attempts. Assumes at the beginning is powered down, and in case of failure, it will power down again.
         * @return True if and only if all three succeed.
         */
        [[nodiscard]] bool try_wake_and_sam_configure();

        status();
        ~status();

        [[nodiscard]] bool activate_internal(channel_type ct);
    public:
        [[nodiscard]] channel_type active_channel() const;

        [[nodiscard]] std::shared_ptr<controller> ctrl() const;

        [[nodiscard]] bool supports(channel_type ct) const;

        /**
         * Nilpotent.
         */
        [[nodiscard]] bool activate(channel_type ct);

        /**
         * Nilpotent.
         */
        void deactivate();

        [[nodiscard]] static status &instance();
    };

    [[nodiscard]] std::unique_ptr<channel> try_activate_channel(channel_type type);
    [[nodiscard]] bool try_activate_controller(channel &chn, controller &ctrl);

    template <channel_type CT>
    struct channel_fixture {
        std::unique_ptr<channel> chn = try_activate_channel(CT);
        std::unique_ptr<controller> ctrl = chn ? std::make_unique<controller>(*chn) : nullptr;

        [[nodiscard]] virtual inline explicit operator bool() const { return chn and ctrl; }
    };


}// namespace ut::pn532


#endif//SPOOKY_ACTION_TEST_PN532_HPP
