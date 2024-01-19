//
// Created by spak on 26/10/23.
//

#ifndef TESTS_FACILITY_HPP
#define TESTS_FACILITY_HPP

#include <desfire/tag.hpp>
#include <memory>
#include <pn532/channel.hpp>
#include <pn532/controller.hpp>

namespace ut {
    enum struct channel_type {
        none,
        hsu,
        i2c,
        i2c_irq,
        spi,
        spi_irq
    };

    [[nodiscard]] const char *to_string(channel_type type);

    class facility {
        std::unique_ptr<pn532::channel> _channel;
        std::shared_ptr<pn532::controller> _controller;
        std::shared_ptr<desfire::tag> _tag;
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

        facility();
        ~facility();

        [[nodiscard]] bool activate_internal(channel_type ct);

    public:
        [[nodiscard]] channel_type active_channel() const;

        [[nodiscard]] bool supports(channel_type ct) const;

        /**
         * @return The logical index of the card target, or 0xff for any kind of other failure.
         */
        [[nodiscard]] std::shared_ptr<desfire::tag> get_card();

        /**
         * Nilpotent.
         */
        [[nodiscard]] std::shared_ptr<pn532::controller> activate_channel(channel_type ct);

        /**
         * Nilpotent.
         */
        void deactivate();

        [[nodiscard]] static facility &instance();
    };

}// namespace ut

#endif//TESTS_FACILITY_HPP
