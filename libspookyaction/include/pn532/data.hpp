//
// Created by Pietro Saccardi on 22/12/2020.
//

#ifndef PN532_DATA_HPP
#define PN532_DATA_HPP

#include <limits>
#include <mlab/bin_data.hpp>
#include <mlab/result.hpp>
#include <pn532/bits.hpp>
#include <pn532/log.h>
#include <pn532/msg.hpp>

namespace pn532 {
    using controller_error = bits::error;
    using command_code = bits::command;

    using bits::atr_res_info;
    using bits::baudrate;
    using bits::baudrate_modulation;
    using bits::modulation;
    using bits::nfcip1_picc_status;
    using bits::polling_method;
    using bits::rf_timeout;
    using bits::sam_mode;
    using bits::serial_baudrate;
    using bits::sfr_register;
    using bits::tx_mode;

    using bits::ciu_reg_106kbps_typea;
    using bits::ciu_reg_212_424kbps;
    using bits::ciu_reg_iso_iec_14443_4;
    using bits::ciu_reg_iso_iec_14443_4_at_baudrate;
    using bits::ciu_reg_typeb;
    using bits::framing;
    using bits::high_current_thr;
    using bits::low_current_thr;
    using bits::poll_period;
    using bits::target_type;
    using bits::wakeup_source;

    using target_kbps106_typea = bits::target<baudrate_modulation::kbps106_iso_iec_14443_typea>;
    using target_kbps212_felica = bits::target<baudrate_modulation::kbps212_felica_polling>;
    using target_kbps424_felica = bits::target<baudrate_modulation::kbps424_felica_polling>;
    using target_kbps106_typeb = bits::target<baudrate_modulation::kbps106_iso_iec_14443_3_typeb>;
    using target_kbps106_jewel_tag = bits::target<baudrate_modulation::kbps106_innovision_jewel_tag>;

    template <target_type Type>
    struct poll_entry : public bits::target<bits::baudrate_modulation_of_target<Type>> {
    };

    /**
     * @brief Monostate structure that signals infinity. Use @ref infty.
     */
    struct infty_t {
    };

    /**
     * @brief A marker for the infinity value added by @ref with_inf to an integral type.
     * @see with_inf
     */
    static constexpr infty_t infty = infty_t{};

    /**
     * @brief "Concept-like" wrapper that adds a signalling "infinity" value to an integral type.
     *
     * In the PN532, sometimes the natural maximum (`std::numeric_limits<Integral>::max()`) of an integral type is used
     * to signal infinity, e.g. repeat an operation indefinitely. This template explicitly marks this property by adding some
     * syntactic sugar to the type. This type behaves exactly like the underlying integral type, but moreover can be assigned
     * and compared with @ref infty.
     * @code
     *  with_inf<int> i = infty;
     *  if (i == infty) {
     *      std::cout << "∞" << std::endl;
     *  } else {
     *      std::cout << i << std::endl;
     *  }
     * @endcode
     * @tparam Integral Any integral type
     */
    template <class Integral>
    struct with_inf {
        static_assert(std::is_integral_v<Integral>);
        Integral v = Integral{};

        with_inf() = default;

        inline with_inf(infty_t) : v{std::numeric_limits<Integral>::max()} {}

        inline with_inf(Integral n) : v{n} {}

        inline operator Integral() const { return v; }

        inline with_inf &operator=(infty_t) {
            v = std::numeric_limits<Integral>::max();
            return *this;
        }

        inline bool operator==(infty_t) const { return v == std::numeric_limits<Integral>::max(); }

        inline bool operator!=(infty_t) const { return v != std::numeric_limits<Integral>::max(); }
    };

    /**
     * @brief Shorthand wrapper for a byte with infinity expressed as 0xff.
     */
    using infbyte = with_inf<std::uint8_t>;

    struct poll_entry_with_atr {
        atr_res_info atr_info;
    };

    template <baudrate_modulation BrMd>
    struct poll_entry_dep_passive : public bits::target<BrMd>, public poll_entry_with_atr {
    };

    template <>
    struct poll_entry<target_type::dep_passive_106kbps> : public poll_entry_dep_passive<
                                                                  bits::baudrate_modulation_of_target<target_type::dep_passive_106kbps>> {
    };

    template <>
    struct poll_entry<target_type::dep_passive_212kbps> : public poll_entry_dep_passive<
                                                                  bits::baudrate_modulation_of_target<target_type::dep_passive_212kbps>> {
    };

    template <>
    struct poll_entry<target_type::dep_passive_424kbps> : public poll_entry_dep_passive<
                                                                  bits::baudrate_modulation_of_target<target_type::dep_passive_424kbps>> {
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


    using any_target = mlab::any_of<target_type, poll_entry>;

    enum struct gpio_loc {
        p3,
        p7,
        i0i1
    };

    /**
     * @brief Data returned after "GetFirmwareVersion" (@ref controller::get_firmware_version) (UM0701-02 §7.2.2)
     */
    struct firmware_version {
        std::uint8_t ic;         //!< The ic version, for PN532 is always 0x32
        std::uint8_t version;    //!< IC firmware version
        std::uint8_t revision;   //!< IC firmware revision
        bool iso_18092;          //!< The chip supports ISO18092 tags
        bool iso_iec_14443_typea;//!< The chip supports ISO 14443 TypeA tags
        bool iso_iec_14443_typeb;//!< The chip supports ISO 14443 TypeB tags
    };

    /**
     * @brief Data returned after "GetGeneralStatus" (@ref controller::get_general_status) (one for each tag) (UM0701-02 §7.2.3)
     */
    struct target_status {
        std::uint8_t logical_index;//!< Tag index (given at initialization from the PN532)
        baudrate baudrate_rx;      //!< Bit rate in reception
        baudrate baudrate_tx;      //!< Bit rate in transmission
        modulation modulation_type;//!< Modulation type
    };

    /**
     * @brief Data returned after most of initiator calls on @ref controller (UM0701-02 §7.1)
     */
    struct rf_status {
        bool nad_present;      //!< True if NAD bit is present
        bool expect_more_info; //!< True if the tag expect another byte to be sent
        controller_error error;//!< PN532 error

        inline explicit operator bool() const { return error == controller_error::none; }
    };

    /**
     * @brief Data returned after "SetParameter" (@ref controller::set_parameters) (UM0701-02 §7.2.9)
     */
    struct parameters {
        bool use_nad_data;                     //!< Use NAD information (used in initiator mode)
        bool use_did_data;                     //!< Use DID information (used in initiator mode)
        bool auto_generate_atr_res;            //!< Automatic generation of ATR_RES (used in target mode)
        bool auto_generate_rats;               //!< Automatic generation of RATS (used in ISO 14443-4 PCD mode)
        bool enable_iso_14443_4_picc_emulation;//!< Emulate a ISO 14443-4 PICC (tag)
        bool remove_pre_post_amble;            //!< Disable pre/post-amble byte
    };

    /**
     * @brief Data returned after "GetGeneralStatus" (@ref controller::get_general_status) (UM0701-02 §7.2.3)
     */
    struct sam_status {
        bool neg_pulse_on_clad_line;
        bool detected_rf_field_off;
        bool timeout_after_sig_act_irq;
        bool clad_line_high;
    };

    /**
     * @brief Data returned after "GetGeneralStatus" (@ref controller::get_general_status) (UM0701-02 §7.2.3)
     */
    struct general_status {
        controller_error last_error;       //!< Last error of the controller
        bool rf_field_present;             //!< True if the RF field is switched on
        std::vector<target_status> targets;//!< List of target inizialized by the controller (max 2)
        sam_status sam;                    //!< SAM status information
    };

    /**
     * @brief Data returned after "TgGetTargetStatus" (@ref controller::target_get_target_status) (UM0701-02 §7.2.21)
     */
    struct status_as_target {
        nfcip1_picc_status status;
        baudrate initiator_speed;
        baudrate target_speed;
    };

    /**
     * Parameters for the command "Diagnose" (@ref controller::diagnose_self_antenna) (UM0701-02 §7.2.1)
     * The parameters are described in (PN532/C1 §8.6.9.2)
     */
    struct reg_antenna_detector {
        bool detected_low_pwr;                  //!< Too low power consuption detection flag (must be 0) (PN532/C1 §8.6.9.2)
        bool detected_high_pwr;                 //!< Too high power consuptiond detection flag (must be 0) (PN532/C1 §8.6.9.2)
        low_current_thr low_current_threshold;  //!< Lower current threshold for low power detection (PN532/C1 §8.6.9.2)
        high_current_thr high_current_threshold;//!< Higher current threshold for high current detection (PN532/C1 §8.6.9.2)
        bool enable_detection;                  //!< Start antenna selftest (must be 1) (PN532/C1 §8.6.9.2)
    };

    /**
     * @brief Data returned after "InJumpForDEP" (UM0701-02 §7.3.3)
     */
    struct jump_dep_psl {
        rf_status status{};                 //!< Error Byte (UM0701-02 §7.1)
        std::uint8_t target_logical_index{};//!< Logical number assigned to the tag
        atr_res_info atr_info;              //!< ATR_RES sent by the tag
    };

    /**
     * @brief Data returned after "TgInitAsTarget"  (UM0701-02 §7.3.14)
     */
    struct mode_as_target {
        baudrate speed;           //!< Trasmission baud rate.
        bool iso_iec_14443_4_picc;//!< Whether it's a ISO/IEC 1443-4 PICC
        bool dep;                 //!< Whether uses DEP
        framing framing_type;     //!< Type of framing
    };

    /**
     * @brief Parameters for the command "TgGetTargetStatus" (@ref controller::target_init_as_target) (UM0701-02 §7.3.21)
     */
    struct mifare_params {
        std::array<std::uint8_t, 2> sens_res;
        std::array<std::uint8_t, 3> nfcid_1t;
        std::uint8_t sel_res;
    };

    /**
     * @note Identical to @ref bits::target_info<baudrate_modulation::kbps212_felica_polling>.
     */
    struct felica_params {
        std::array<std::uint8_t, 8> nfcid_2t;
        std::array<std::uint8_t, 8> pad;
        std::array<std::uint8_t, 2> syst_code;
    };

    /**
     * @brief Data returned after "TgInitAsTarget" (@ref controller::target_init_as_target) (UM0701-02 §7.3.14)
     */
    struct init_as_target_res {
        mode_as_target mode;                        //!< A byte containing witch mode the PN532 has been activated
        std::vector<std::uint8_t> initiator_command;//!< A vector containing the first frame received by the PN532
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

        [[nodiscard]] inline std::uint8_t mask(gpio_loc loc) const;

        inline void set_mask(gpio_loc loc, std::uint8_t mask);

        [[nodiscard]] inline bool operator[](std::pair<gpio_loc, std::uint8_t> const &gpio_idx) const;

        inline mlab::bit_ref operator[](std::pair<gpio_loc, std::uint8_t> const &gpio_idx);
    };
}// namespace pn532

namespace mlab {
    // Locally import pn532 so that these declaration make sense
    namespace {
        using namespace pn532;
    }

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

    bin_data &operator<<(bin_data &s, mifare_params const &p);

    bin_data &operator<<(bin_data &s, felica_params const &p);

    template <baudrate_modulation BrMd>
    bin_stream &operator>>(bin_stream &s, std::vector<bits::target<BrMd>> &targets);

    /**
     * @note This is a custom operator because we do not have ATS bytes.
     */
    bin_stream &operator>>(bin_stream &s, poll_entry<target_type::dep_passive_106kbps> &entry);

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

    bin_stream &operator>>(bin_stream &s, mode_as_target &mt);

    bin_stream &operator>>(bin_stream &s, init_as_target_res &mt);

}// namespace mlab

namespace pn532 {

    bool gpio_status::operator[](std::pair<gpio_loc, std::uint8_t> const &gpio_idx) const {
        switch (gpio_idx.first) {
            case gpio_loc::p3:
                return 0 != (_p3_mask & (1 << gpio_idx.second));
            case gpio_loc::p7:
                return 0 != (_p7_mask & (1 << gpio_idx.second));
            case gpio_loc::i0i1:
                return 0 != (_i0i1_mask & (1 << gpio_idx.second));
        }
    }

    mlab::bit_ref gpio_status::operator[](std::pair<gpio_loc, std::uint8_t> const &gpio_idx) {
        static std::uint8_t _garbage = 0x00;
        switch (gpio_idx.first) {
            case gpio_loc::p3:
                return mlab::bit_ref{_p3_mask, gpio_idx.second, bits::gpio_p3_pin_mask};
            case gpio_loc::p7:
                return mlab::bit_ref{_p7_mask, gpio_idx.second, bits::gpio_p7_pin_mask};
            case gpio_loc::i0i1:
                return mlab::bit_ref{_i0i1_mask, gpio_idx.second, bits::gpio_i0i1_pin_mask};
        }
        return mlab::bit_ref{_garbage, gpio_idx.second, 0xff};
    }

    gpio_status::gpio_status(std::uint8_t p3_mask, std::uint8_t p7_mask, std::uint8_t i0i1_mask) : _p3_mask{p3_mask}, _p7_mask{p7_mask}, _i0i1_mask{i0i1_mask} {}

    inline std::uint8_t gpio_status::mask(gpio_loc loc) const {
        switch (loc) {
            case gpio_loc::p3:
                return _p3_mask;
            case gpio_loc::p7:
                return _p7_mask;
            case gpio_loc::i0i1:
                return _i0i1_mask;
        }
        return 0x00;
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
        }
    }

    reg_addr::reg_addr(sfr_register sfr_reg) : std::array<std::uint8_t, 2>{{bits::sfr_registers_high, static_cast<std::uint8_t>(sfr_reg)}} {}

    reg_addr::reg_addr(std::uint16_t xram_mmap_reg) : std::array<std::uint8_t, 2>{{std::uint8_t(xram_mmap_reg >> 8),
                                                                                   std::uint8_t(xram_mmap_reg & 0xff)}} {}

}// namespace pn532

namespace mlab {
    template <baudrate_modulation BrMd>
    bin_stream &operator>>(bin_stream &s, std::vector<bits::target<BrMd>> &targets) {
        if (s.remaining() < 1) {
            PN532_LOGE("Parsing vector<target<%s>>: not enough data.", to_string(BrMd));
            s.set_bad();
            return s;
        }
        const auto num_targets = s.pop();
        if (num_targets > bits::max_num_targets) {
            PN532_LOGW("Parsing vector<target<%s>>: found %u targets, which is more than the number of supported targets %u.",
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

    template <target_type Type>
    bin_stream &operator>>(bin_stream &s, poll_entry<Type> &entry) {
        static constexpr baudrate_modulation BrMod = bits::baudrate_modulation_of_target<Type>;
        if constexpr (std::is_base_of_v<bits::target<BrMod>, poll_entry<Type>>) {
            s >> static_cast<bits::target<BrMod> &>(entry);
        }
        if constexpr (std::is_base_of_v<poll_entry_with_atr, poll_entry<Type>>) {
            s >> static_cast<poll_entry_with_atr &>(entry).atr_info;
        }
        return s;
    }

}// namespace mlab

#endif//PN532_DATA_HPP
