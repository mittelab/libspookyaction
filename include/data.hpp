//
// Created by Pietro Saccardi on 22/12/2020.
//

#ifndef APERTURAPORTA_DATA_HPP
#define APERTURAPORTA_DATA_HPP

#include <limits>
#include "bits.hpp"
#include "bin_data.hpp"
#include "result.hpp"
#include "msg.hpp"
#include "any.hpp"

namespace pn532 {

    using controller_error = bits::error;
    using command_code = bits::command;

    using bits::baudrate;
    using bits::modulation;
    using bits::baudrate_modulation;
    using bits::sfr_register;
    using bits::serial_baudrate;
    using bits::sam_mode;
    using bits::rf_timeout;
    using bits::polling_method;
    using bits::atr_res_info;
    using bits::tx_mode;
    using bits::nfcip1_picc_status;

    using bits::ciu_reg_212_424kbps;
    using bits::ciu_reg_106kbps_typea;
    using bits::ciu_reg_typeb;
    using bits::ciu_reg_iso_iec_14443_4_at_baudrate;
    using bits::ciu_reg_iso_iec_14443_4;
    using bits::low_current_thr;
    using bits::high_current_thr;
    using bits::target_type;
    using bits::poll_period;
    using bits::wakeup_source;

    using target_kbps106_typea = bits::target<baudrate_modulation::kbps106_iso_iec_14443_typea>;
    using target_kbps212_felica = bits::target<baudrate_modulation::kbps212_felica_polling>;
    using target_kbps424_felica = bits::target<baudrate_modulation::kbps424_felica_polling>;
    using target_kbps106_typeb = bits::target<baudrate_modulation::kbps106_iso_iec_14443_3_typeb>;
    using target_kbps106_jewel_tag = bits::target<baudrate_modulation::kbps106_innovision_jewel_tag>;

    template <target_type Type>
    struct poll_entry : public bits::target<bits::baudrate_modulation_of_target<Type>::value> {
    };

    struct infty_t {
    };

    static constexpr infty_t infty = infty_t{};

    template <class Integral, class = typename std::enable_if<std::is_integral<Integral>::value>::type>
    struct with_inf {
        Integral v = Integral{};

        with_inf() = default;

        inline with_inf(infty_t) : v{std::numeric_limits<Integral>::max()} {}

        inline with_inf(Integral n) : v{n} {}

        inline operator Integral() const { return v; }

        inline with_inf &operator=(infty_t) { v = std::numeric_limits<Integral>::max(); }

        inline bool operator==(infty_t) const { return v == std::numeric_limits<Integral>::max(); }

        inline bool operator!=(infty_t) const { return v != std::numeric_limits<Integral>::max(); }
    };

    using infbyte = with_inf<std::uint8_t>;

    struct poll_entry_with_atr {
        atr_res_info atr_info;
    };

    template <baudrate_modulation BrMd>
    struct poll_entry_dep_passive : public bits::target<BrMd>, public poll_entry_with_atr {
    };

    template <>
    struct poll_entry<target_type::dep_passive_106kbps> :
            public poll_entry_dep_passive<
                    bits::baudrate_modulation_of_target<target_type::dep_passive_106kbps>::value> {
    };

    template <>
    struct poll_entry<target_type::dep_passive_212kbps> :
            public poll_entry_dep_passive<
                    bits::baudrate_modulation_of_target<target_type::dep_passive_212kbps>::value> {
    };

    template <>
    struct poll_entry<target_type::dep_passive_424kbps> :
            public poll_entry_dep_passive<
                    bits::baudrate_modulation_of_target<target_type::dep_passive_424kbps>::value> {
    };

    template <>
    struct poll_entry<target_type::dep_active_106kbps> : public poll_entry_with_atr {
    };

    template <>
    struct poll_entry<target_type::dep_active_212kbps> : public poll_entry_with_atr {
    };

    template <>
    struct poll_entry<target_type::dep_active_424kbps> : public poll_entry_with_atr {
    };


    class any_target {
        target_type _type;
        any _poll_entry;
    public:
        struct incorrect_cast_t {
        };
        static constexpr incorrect_cast_t incorrect_cast{};

        inline any_target();

        template <target_type Type>
        inline explicit any_target(poll_entry<Type> entry);

        inline target_type type() const;

        template <target_type Type>
        poll_entry<Type> const &get_entry() const;

        template <target_type Type>
        any_target &operator=(poll_entry<Type> entry);
    };

    namespace ctti {
        template <target_type Type>
        struct type_info<poll_entry<Type>> : public std::integral_constant<id_type, static_cast<id_type>(Type)> {
        };
    }

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
        baudrate baudrate_rx;
        baudrate baudrate_tx;
        modulation modulation_type;
    };

    struct rf_status {
        bool nad_present;
        bool expect_more_info;
        controller_error error;

        inline explicit operator bool() const { return error == controller_error::none; }
    };

    struct parameters {
        bool use_nad_data;
        bool use_did_data;
        bool auto_generate_atr_res;
        bool auto_generate_rats;
        bool enable_iso_14443_4_picc_emulation;
        bool remove_pre_post_amble;
    };

    struct sam_status {
        bool neg_pulse_on_clad_line;
        bool detected_rf_field_off;
        bool timeout_after_sig_act_irq;
        bool clad_line_high;
    };

    struct general_status {
        controller_error last_error;
        bool rf_field_present;
        std::vector<target_status> targets;
        sam_status sam;
    };

    struct status_as_target {
        nfcip1_picc_status status;
        baudrate initiator_speed;
        baudrate target_speed;
    };

    struct reg_antenna_detector {
        bool detected_low_pwr;
        bool detected_high_pwr;
        low_current_thr low_current_threshold;
        high_current_thr high_current_threshold;
        bool enable_detection;
    };

    struct jump_dep_psl {
        rf_status status{};
        std::uint8_t target_logical_index{};
        atr_res_info atr_info;
    };

    template <std::size_t Length>
    struct uid_cascade : public std::array<std::uint8_t, Length> {
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

    bin_data &operator<<(bin_data &bd, uid_cascade_l2 const &uid);

    bin_data &operator<<(bin_data &bd, uid_cascade_l3 const &uid);

    bin_data &operator<<(bin_data &bd, reg_antenna_detector const &r);

    bin_data &operator<<(bin_data &s, parameters const &p);

    bin_data &operator<<(bin_data &s, std::vector<wakeup_source> const &vws);

    template <baudrate_modulation BrMd>
    bin_stream &operator>>(bin_stream &s, std::vector<bits::target<BrMd>> &targets);

    template <target_type Type>
    bin_stream &operator>>(bin_stream &s, poll_entry<Type> &entry);

    bin_stream &operator>>(bin_stream &s, any_target &t);

    bin_stream &operator>>(bin_stream &s, std::vector<any_target> &targets);

    bin_stream &operator>>(bin_stream &s, std::pair<rf_status, bin_data> &status_data_pair);

    bin_stream &operator>>(bin_stream &s, rf_status &status);

    bin_stream &operator>>(bin_stream &s, gpio_status &gpio);

    bin_stream &operator>>(bin_stream &s, firmware_version &fw);

    bin_stream &operator>>(bin_stream &s, general_status &gs);

    bin_stream &operator>>(bin_stream &s, target_status &ts);

    bin_stream &operator>>(bin_stream &s, target_kbps106_typea &target);

    bin_stream &operator>>(bin_stream &s, target_kbps212_felica &target);

    bin_stream &operator>>(bin_stream &s, target_kbps424_felica &target);

    bin_stream &operator>>(bin_stream &s, target_kbps106_typeb &target);

    bin_stream &operator>>(bin_stream &s, target_kbps106_jewel_tag &target);

    bin_stream &operator>>(bin_stream &s, atr_res_info &atr_res);

    bin_stream &operator>>(bin_stream &s, std::pair<rf_status, atr_res_info> &status_atr_res);

    bin_stream &operator>>(bin_stream &s, reg_antenna_detector &r);

    bin_stream &operator>>(bin_stream &s, jump_dep_psl &r);

    bin_stream &operator>>(bin_stream &s, sam_status &sams);

    bin_stream &operator>>(bin_stream &s, status_as_target &st);

}

namespace pn532 {

    any_target::any_target() : _type{}, _poll_entry{} {}


    template <target_type Type>
    any_target::any_target(poll_entry<Type> entry) :
            _type{Type}, _poll_entry{std::move(entry)} {}

    template <target_type Type>
    any_target &any_target::operator=(poll_entry<Type> entry) {
        _type = Type;
        _poll_entry = std::move(entry);
        return *this;
    }

    target_type any_target::type() const {
        if (_poll_entry.empty()) {
            LOGE("Requested target type of an empty any_target.");
            return {};
        }
        return _type;
    }


    template <target_type Type>
    poll_entry<Type> const &any_target::get_entry() const {
        return _poll_entry.template get<poll_entry<Type>>();
    }

    bool gpio_status::operator[](std::pair<gpio_loc, std::uint8_t> const &gpio_idx) const {
        switch (gpio_idx.first) {
            case gpio_loc::p3:
                return 0 != (_p3_mask & (1 << gpio_idx.second));
            case gpio_loc::p7:
                return 0 != (_p7_mask & (1 << gpio_idx.second));
            case gpio_loc::i0i1:
                return 0 != (_i0i1_mask & (1 << gpio_idx.second));
            default:
                return false;
        }
    }

    bit_ref gpio_status::operator[](std::pair<gpio_loc, std::uint8_t> const &gpio_idx) {
        static std::uint8_t _garbage = 0x00;
        switch (gpio_idx.first) {
            case gpio_loc::p3:
                return bit_ref{_p3_mask, gpio_idx.second, bits::gpio_p3_pin_mask};
            case gpio_loc::p7:
                return bit_ref{_p7_mask, gpio_idx.second, bits::gpio_p7_pin_mask};
            case gpio_loc::i0i1:
                return bit_ref{_i0i1_mask, gpio_idx.second, bits::gpio_i0i1_pin_mask};
            default:
                return bit_ref{_garbage, gpio_idx.second, 0xff};
        }
    }

    gpio_status::gpio_status(std::uint8_t p3_mask, std::uint8_t p7_mask, std::uint8_t i0i1_mask) :
            _p3_mask{p3_mask}, _p7_mask{p7_mask}, _i0i1_mask{i0i1_mask} {}

    inline std::uint8_t gpio_status::mask(gpio_loc loc) const {
        switch (loc) {
            case gpio_loc::p3:
                return _p3_mask;
            case gpio_loc::p7:
                return _p7_mask;
            case gpio_loc::i0i1:
                return _i0i1_mask;
            default:
                return 0x00;
        }
    }

    void gpio_status::set_mask(gpio_loc loc, std::uint8_t mask) {
        switch (loc) {
            case gpio_loc::p3:
                _p3_mask = mask & bits::gpio_p3_pin_mask;
                break;
            case gpio_loc::p7:
                _p7_mask = mask & bits::gpio_p7_pin_mask;
                break;
            case gpio_loc::i0i1:
                _i0i1_mask = mask & bits::gpio_i0i1_pin_mask;
                break;
            default:
                break;
        }
    }

    reg_addr::reg_addr(sfr_register sfr_reg) :
            std::array<std::uint8_t, 2>{{bits::sfr_registers_high, static_cast<std::uint8_t>(sfr_reg)}} {}

    reg_addr::reg_addr(std::uint16_t xram_mmap_reg) :
            std::array<std::uint8_t, 2>{{std::uint8_t(xram_mmap_reg >> 8),
                                                std::uint8_t(xram_mmap_reg & 0xff)}} {}


    template <baudrate_modulation BrMd>
    bin_stream &operator>>(bin_stream &s, std::vector<bits::target<BrMd>> &targets) {
        if (s.remaining() < 1) {
            LOGE("Parsing vector<target<%s>>: not enough data.", to_string(BrMd));
            s.set_bad();
            return s;
        }
        const auto num_targets = s.pop();
        if (num_targets > bits::max_num_targets) {
            LOGW("Parsing vector<target<%s>>: found %u targets, which is more than the number of supported targets %u.",
                 to_string(BrMd), num_targets, bits::max_num_targets);
        }
        targets.resize(num_targets);
        for (auto &target : targets) {
            if (not s.good()) {
                break;
            }
            s >> target;
        }
        return s;
    }

    namespace impl {
        template <bool, bool>
        struct poll_entry_extractor {
        };

        template <>
        struct poll_entry_extractor<false, true> {
            template <target_type Type>
            bin_stream &operator()(bin_stream &s, poll_entry<Type> &entry) const {
                static_assert(std::is_base_of<poll_entry_with_atr, poll_entry<Type>>::value,
                              "This variant is intended for DEP compatible, active targets.");
                return s >> static_cast<poll_entry_with_atr &>(entry).atr_info;
            }
        };

        template <>
        struct poll_entry_extractor<true, false> {
            template <target_type Type>
            bin_stream &operator()(bin_stream &s, poll_entry<Type> &entry) const {
                static constexpr baudrate_modulation BrMod = bits::baudrate_modulation_of_target<Type>::value;
                static_assert(std::is_base_of<bits::target<BrMod>, poll_entry<Type>>::value,
                              "This variant is not intended for DEP compatible, active targets.");
                return s >> static_cast<bits::target<BrMod> &>(entry);
            }
        };

        template <>
        struct poll_entry_extractor<true, true> {
            template <target_type Type>
            bin_stream &operator()(bin_stream &s, poll_entry<Type> &entry) const {
                // A bit of both [cit.], in the right order
                poll_entry_extractor<true, false>{}(s, entry);
                return poll_entry_extractor<false, true>{}(s, entry);
            }
        };
    }

    template <target_type Type>
    bin_stream &operator>>(bin_stream &s, poll_entry<Type> &entry) {
        static constexpr baudrate_modulation BrMod = bits::baudrate_modulation_of_target<Type>::value;
        static constexpr bool HasTarget = std::is_base_of<bits::target<BrMod>, poll_entry<Type>>::value;
        static constexpr bool HasAtr = std::is_base_of<poll_entry_with_atr, poll_entry<Type>>::value;
        return impl::poll_entry_extractor<HasTarget, HasAtr>{}(s, entry);
    }

}

#endif //APERTURAPORTA_DATA_HPP
