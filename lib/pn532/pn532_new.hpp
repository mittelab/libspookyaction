//
// Created by Pietro Saccardi on 20/12/2020.
//

#ifndef APERTURAPORTA_PN532_HPP
#define APERTURAPORTA_PN532_HPP


#include <array>
#include <vector>
#include <cstddef>
#include <limits>
#include "instructions_new.hpp"
#include "channel.hpp"

namespace pn532 {

    namespace frames {
        struct header;
    }

    class bin_data;

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
        pieces::speed bitrate_rx;
        pieces::speed bitrate_tx;
        pieces::modulation modulation_type;
    };

    struct general_status {
        bool nad_present;
        bool mi_set;
        pieces::error last_error;
        bool rf_field_present;
        std::vector<target_status> targets;
        std::uint8_t sam_status;
    };

    struct reg_addr : public std::array<std::uint8_t, 2> {
        inline reg_addr(pieces::sfr_registers sfr_register);
        inline reg_addr(std::uint16_t xram_mmap_register);
    };

    enum struct gpio_loc {
        p3, p7, i0i1
    };

    struct bit_ref {
        std::uint8_t &byte;
        const std::uint8_t index;
        const std::uint8_t write_mask;

        inline bit_ref &operator=(bool v);
        inline operator bool() const;
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

    class nfc {
        channel *_channel;

        inline channel &chn() const;

        bool await_frame(ms timeout);
        std::pair<frames::header, bool> read_header(ms timeout);
        std::pair<bin_data, bool> read_body(frames::header const &hdr, ms timeout);

    public:
        inline explicit nfc(channel &chn);

        nfc(nfc const &) = delete;
        nfc(nfc &&) = default;

        nfc &operator=(nfc const &) = delete;
        nfc &operator=(nfc &&) = default;

        result raw_send_ack(bool ack = true, ms timeout = one_sec);
        result raw_send_command(pieces::command cmd, bin_data const &payload, ms timeout = one_sec);

        std::pair<bool, result> raw_await_ack(ms timeout = one_sec);
        std::tuple<pieces::command, bin_data, result> raw_await_response(ms timeout = one_sec);

        result command(pieces::command cmd, bin_data const &payload, ms timeout = one_sec);
        std::pair<bin_data, result> command_response(pieces::command cmd, bin_data const &payload, ms timeout = one_sec);

        result diagnose_rom(ms timeout = one_sec);
        result diagnose_ram(ms timeout = one_sec);
        result diagnose_attention_req_or_card_presence(ms timeout = one_sec);

        result diagnose_comm_line(ms timeout = one_sec);
        /**
         *
         * @param timeout
         * @return Number of fails (<128) at 212 kbps, number of fails (<128) as 424 kbps, command result.
         */
        std::tuple<unsigned, unsigned, result> diagnose_poll_target(ms timeout = one_sec);

        /**
         * @param tx_mode
         * @param rx_mode
         * @todo Figure out what these should be (page 70)
         */
        result diagnose_echo_back(ms reply_delay, std::uint8_t tx_mode, std::uint8_t rx_mode, ms timeout = one_sec);
        /**
         * @param threshold
         * @todo Figure out the bit packing for this (page 72)
         */
        result diagnose_self_antenna(std::uint8_t threshold, ms timeout = one_sec);

        std::pair<firmware_version, result> get_firmware_version(ms timeout = one_sec);

        std::pair<general_status, result> get_general_status(ms timeout = one_sec);

        std::pair<std::vector<uint8_t>, result> read_register(std::vector<reg_addr> const &addresses, ms timeout = one_sec);

        result write_register(std::vector<std::pair<reg_addr, std::uint8_t>> const &addr_value_pairs, ms timeout = one_sec);

        std::pair<gpio_status, result> read_gpio(ms timeout = one_sec);

        result write_gpio(gpio_status const &status, bool write_p3 = true, bool write_p7 = true, ms timeout = one_sec);

        result set_gpio_pin(gpio_loc loc, std::uint8_t pin_idx, bool value, ms timeout = one_sec);

        /*
- (SetSerialBaudRate)
- SAMConfiguration

- RFConfiguration
- InDataExchange
- InSelect
- InAutoPoll
         */
    };

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
            case gpio_loc::p3:   return bit_ref{_p3_mask,   gpio_idx.second, pieces::gpio_p3_pin_mask};
            case gpio_loc::p7:   return bit_ref{_p7_mask,   gpio_idx.second, pieces::gpio_p7_pin_mask};
            case gpio_loc::i0i1: return bit_ref{_i0i1_mask, gpio_idx.second, pieces::gpio_i0i1_pin_mask};
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
            case gpio_loc::p3:   _p3_mask   = mask & pieces::gpio_p3_pin_mask; break;
            case gpio_loc::p7:   _p7_mask   = mask & pieces::gpio_p7_pin_mask; break;
            case gpio_loc::i0i1: _i0i1_mask = mask & pieces::gpio_i0i1_pin_mask; break;
            default: break;
        }
    }

    bit_ref &bit_ref::operator=(bool v) {
        if (0 != (write_mask & (1 << index))) {
            if (v) {
                byte |= 1 << index;
            } else {
                byte &= ~(1 << index);
            }
        }
        return *this;
    }

    bit_ref::operator bool() const {
        return 0 != (byte & (1 << index));
    }

    nfc::nfc(channel &chn) : _channel{&chn} {}
    channel &nfc::chn() const { return *_channel; }

    reg_addr::reg_addr(pieces::sfr_registers sfr_register) :
        std::array<std::uint8_t, 2>{{pieces::sfr_registers_high, static_cast<std::uint8_t>(sfr_register)}} {}

    reg_addr::reg_addr(std::uint16_t xram_mmap_register) :
        std::array<std::uint8_t, 2>{{std::uint8_t(xram_mmap_register >> 8),
                                     std::uint8_t(xram_mmap_register & 0xff)}} {}


}


#endif //APERTURAPORTA_PN532_HPP
