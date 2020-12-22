//
// Created by Pietro Saccardi on 22/12/2020.
//

#ifndef APERTURAPORTA_DATA_HPP
#define APERTURAPORTA_DATA_HPP

#include <limits>
#include "bits.hpp"
#include "bin_data.hpp"

namespace pn532 {

    using speed = bits::speed;
    using modulation = bits::modulation;
    using error = bits::error;
    using sfr_registers = bits::sfr_registers;
    using command = bits::command;

    enum struct gpio_loc {
        p3, p7, i0i1
    };

    enum struct result {
        success,
        timeout,
        comm_checksum_fail,
        comm_error,
        comm_malformed,
        nack,
        failure
    };

    struct firmware_version {
        std::uint8_t ic = std::numeric_limits<std::uint8_t>::max();
        std::uint8_t version = std::numeric_limits<std::uint8_t>::max();
        std::uint8_t revision = std::numeric_limits<std::uint8_t>::max();
        bool iso_18092 = false;
        bool iso_iec_14443_typeb = false;
        bool iso_iec_14443_typea = false;
    };

    struct target_status {
        std::uint8_t logical_index;
        bits::speed bitrate_rx;
        bits::speed bitrate_tx;
        bits::modulation modulation_type;
    };

    struct general_status {
        bool nad_present;
        bool mi_set;
        bits::error last_error;
        bool rf_field_present;
        std::vector<target_status> targets;
        std::uint8_t sam_status;
    };

    struct reg_addr : public std::array<std::uint8_t, 2> {
        inline reg_addr(bits::sfr_registers sfr_register);

        inline reg_addr(std::uint16_t xram_mmap_register);
    };

    struct gpio_status {
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

}

namespace pn532 {

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

    reg_addr::reg_addr(bits::sfr_registers sfr_register) :
            std::array<std::uint8_t, 2>{{bits::sfr_registers_high, static_cast<std::uint8_t>(sfr_register)}} {}

    reg_addr::reg_addr(std::uint16_t xram_mmap_register) :
            std::array<std::uint8_t, 2>{{std::uint8_t(xram_mmap_register >> 8),
                                                std::uint8_t(xram_mmap_register & 0xff)}} {}

}

#endif //APERTURAPORTA_DATA_HPP
