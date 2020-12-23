//
// Created by Pietro Saccardi on 22/12/2020.
//

#ifndef APERTURAPORTA_DATA_HPP
#define APERTURAPORTA_DATA_HPP

#include <limits>
#include "bits.hpp"
#include "bin_data.hpp"
#include "result.hpp"

namespace pn532 {

    using controller_error = bits::error;
    using command_code = bits::command;

    using bits::speed;
    using bits::modulation;
    using bits::baudrate_modulation;
    using bits::sfr_register;
    using bits::baud_rate;
    using bits::sam_mode;
    using bits::rf_timeout;
    using bits::polling_method;

    using bits::ciu_reg_212_424kbps;
    using bits::ciu_reg_106kbps_typea;
    using bits::ciu_reg_typeb;
    using bits::ciu_reg_iso_iec_14443_4_at_baudrate;
    using bits::ciu_reg_iso_iec_14443_4;


    using target_kbps106_typea = bits::target<baudrate_modulation::kbps106_iso_iec_14443_typea>;
    using target_kbps212_felica = bits::target<baudrate_modulation::kbps212_felica_polling>;
    using target_kbps424_felica = bits::target<baudrate_modulation::kbps424_felica_polling>;
    using target_kbps106_typeb = bits::target<baudrate_modulation::kbps106_iso_iec_14443_3_typeb>;
    using target_kbps106_jewel_tag = bits::target<baudrate_modulation::kbps106_innovision_jewel_tag>;

    class any_target {
        std::uint8_t _logical_index;
        baudrate_modulation _type;
        bin_data _payload;
    public:
        inline any_target(std::uint8_t logical_index, baudrate_modulation type, bin_data payload);

        enum error {
            incorrect_cast,
            malformed
        };

        inline std::uint8_t logical_index() const;
        inline baudrate_modulation type() const;

        template <baudrate_modulation Type>
        result<error, bits::target<Type>> get_info() const;
    };

    enum struct gpio_loc {
        p3, p7, i0i1
    };

    struct firmware_version {
        std::uint8_t ic;
        std::uint8_t version;
        std::uint8_t revision;
        bool iso_18092;
        bool iso_iec_14443_typea;
        bool iso_iec_14443_typeb;
    };

    struct target_status {
        std::uint8_t logical_index;
        speed bitrate_rx;
        speed bitrate_tx;
        modulation modulation_type;
    };

    struct status {
        bool nad_present;
        bool expect_more_info;
        controller_error error;
    };

    struct general_status {
        controller_error last_error;
        bool rf_field_present;
        std::vector<target_status> targets;
        std::uint8_t sam_status;
    };

    template <std::size_t Length>
    struct uid_cascade : public std::array<std::uint8_t , Length> {
        using std::array<std::uint8_t, Length>::array;
    };

    using uid_cascade_l1 = uid_cascade<4>;
    using uid_cascade_l2 = uid_cascade<7>;
    using uid_cascade_l3 = uid_cascade<10>;

    struct reg_addr : public std::array<std::uint8_t, 2> {
        inline reg_addr(sfr_register sfr_reg);

        inline reg_addr(std::uint16_t xram_mmap_reg);
    };

    class gpio_status {
    private:
        std::uint8_t _p3_mask = 0x00;
        std::uint8_t _p7_mask = 0x00;
        std::uint8_t _i0i1_mask = 0x00;
    public:
        gpio_status() = default;

        inline gpio_status(std::uint8_t p3_mask, std::uint8_t p7_mask, std::uint8_t i0i1_mask);

        inline std::uint8_t mask(gpio_loc loc) const;

        inline void set_mask(gpio_loc loc, std::uint8_t mask);

        inline bool operator[](std::pair<gpio_loc, std::uint8_t> const &gpio_idx) const;

        inline bit_ref operator[](std::pair<gpio_loc, std::uint8_t> const &gpio_idx);
    };

    bin_data &operator<<(bin_data &bd, ciu_reg_212_424kbps const &reg);
    bin_data &operator<<(bin_data &bd, ciu_reg_106kbps_typea const &reg);
    bin_data &operator<<(bin_data &bd, ciu_reg_typeb const &reg);
    bin_data &operator<<(bin_data &bd, ciu_reg_iso_iec_14443_4_at_baudrate const &reg);
    bin_data &operator<<(bin_data &bd, ciu_reg_iso_iec_14443_4 const &reg);
    bin_data &operator<<(bin_data &bd, uid_cascade_l1 const &uid);
    bin_data &operator<<(bin_data &bd, uid_cascade_l2 const &uid);
    bin_data &operator<<(bin_data &bd, uid_cascade_l3 const &uid);

    bin_stream &operator>>(bin_stream &s, target_status &ts);
    bin_stream &operator>>(bin_stream &s, target_kbps106_typea &target);
    bin_stream &operator>>(bin_stream &s, target_kbps212_felica &target);
    bin_stream &operator>>(bin_stream &s, target_kbps424_felica &target);
    bin_stream &operator>>(bin_stream &s, target_kbps106_typeb &target);
    bin_stream &operator>>(bin_stream &s, target_kbps106_jewel_tag &target);

}

namespace pn532 {

    any_target::any_target(std::uint8_t logical_index, baudrate_modulation type, bin_data payload) :
        _logical_index{logical_index}, _type{type}, _payload{std::move(payload)} {}


    template <baudrate_modulation Type>
    result<any_target::error, bits::target<Type>> any_target::get_info() const {
        if (type() != Type) {
            return error::incorrect_cast;
        }
        std::pair<bits::target<Type>, bool> target_success = {{}, false};
        _payload >> target_success;
        if (not target_success.second) {
            return error::incorrect_cast;
        }
        return std::move(target_success.first);
    }

    std::uint8_t any_target::logical_index() const {
        return _logical_index;
    }
    baudrate_modulation any_target::type() const {
        return _type;
    }

    bool gpio_status::operator[](std::pair<gpio_loc, std::uint8_t> const &gpio_idx) const {
        switch (gpio_idx.first) {
            case gpio_loc::p3:   return 0 != (_p3_mask   & (1 << gpio_idx.second));
            case gpio_loc::p7:   return 0 != (_p7_mask   & (1 << gpio_idx.second));
            case gpio_loc::i0i1: return 0 != (_i0i1_mask & (1 << gpio_idx.second));
            default: return false;
        }
    }

    bit_ref gpio_status::operator[](std::pair<gpio_loc, std::uint8_t> const &gpio_idx) {
        static std::uint8_t _garbage = 0x00;
        switch (gpio_idx.first) {
            case gpio_loc::p3:   return bit_ref{_p3_mask, gpio_idx.second, bits::gpio_p3_pin_mask};
            case gpio_loc::p7:   return bit_ref{_p7_mask, gpio_idx.second, bits::gpio_p7_pin_mask};
            case gpio_loc::i0i1: return bit_ref{_i0i1_mask, gpio_idx.second, bits::gpio_i0i1_pin_mask};
            default: return bit_ref{_garbage, gpio_idx.second, 0xff};
        }
    }

    gpio_status::gpio_status(std::uint8_t p3_mask, std::uint8_t p7_mask, std::uint8_t i0i1_mask) :
            _p3_mask{p3_mask}, _p7_mask{p7_mask}, _i0i1_mask{i0i1_mask} {}

    inline std::uint8_t gpio_status::mask(gpio_loc loc) const {
        switch (loc) {
            case gpio_loc::p3:   return _p3_mask;
            case gpio_loc::p7:   return _p7_mask;
            case gpio_loc::i0i1: return _i0i1_mask;
            default: return 0x00;
        }
    }

    void gpio_status::set_mask(gpio_loc loc, std::uint8_t mask) {
        switch (loc) {
            case gpio_loc::p3:   _p3_mask   = mask & bits::gpio_p3_pin_mask; break;
            case gpio_loc::p7:   _p7_mask   = mask & bits::gpio_p7_pin_mask; break;
            case gpio_loc::i0i1: _i0i1_mask = mask & bits::gpio_i0i1_pin_mask; break;
            default: break;
        }
    }

    reg_addr::reg_addr(sfr_register sfr_reg) :
            std::array<std::uint8_t, 2>{{bits::sfr_registers_high, static_cast<std::uint8_t>(sfr_reg)}} {}

    reg_addr::reg_addr(std::uint16_t xram_mmap_reg) :
            std::array<std::uint8_t, 2>{{std::uint8_t(xram_mmap_reg >> 8),
                                                std::uint8_t(xram_mmap_reg & 0xff)}} {}

}

#endif //APERTURAPORTA_DATA_HPP
