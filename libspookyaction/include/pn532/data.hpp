//
// Created by Pietro Saccardi on 22/12/2020.
//

#ifndef PN532_DATA_HPP
#define PN532_DATA_HPP

#include <mlab/bin_data.hpp>
#include <mlab/result.hpp>
#include <pn532/bits.hpp>
#include <pn532/log.h>
#include <pn532/msg.hpp>

/**
 * @defgroup IOOperators I/O binary operators
 * Operators to serialize a given data structure to a `bin_data`, or to deserialize it from a `bin_stream`.
 * These implement the various binary data formats described in the manual references.
 */
namespace pn532 {
    using target_kbps106_typea = target<baudrate_modulation::kbps106_iso_iec_14443_typea>;
    using target_kbps212_felica = target<baudrate_modulation::kbps212_felica>;
    using target_kbps424_felica = target<baudrate_modulation::kbps424_felica>;
    using target_kbps106_typeb = target<baudrate_modulation::kbps106_iso_iec_14443_3_typeb>;
    using target_kbps106_jewel_tag = target<baudrate_modulation::kbps106_innovision_jewel_tag>;

    /**
     * @brief Monostate structure that signals infinity. Use as @ref pn532::infty.
     * This is intended together with @ref with_inf to mark integral types.
     */
    struct infty_t {
    };

    /**
     * Marker that stands for `std::numeric_limits<Integral>::max()` in @ref with_inf.
     */
    static constexpr infty_t infty{};

    /**
     * @brief Wrapper around an integral type that can take @ref pn532::infty and assign to the underlying integer type its maximum value.
     *
     * In the PN532, sometimes the natural maximum (`std::numeric_limits<Integral>::max()`) of an integral type is used
     * to signal infinity, e.g. repeat an operation indefinitely. This template explicitly marks this property by adding some
     * syntactic sugar to the type. This type behaves exactly like the underlying integral type, but moreover can be assigned
     * and compared with @ref pn532::infty.
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
        static_assert(std::is_integral_v<Integral> and not std::is_same_v<Integral, bool>);
        /// Integral member.
        Integral v = Integral{};

        /// Zero-initializes the underlying value @ref v.
        with_inf() = default;

        /// Initializes @ref v to `std::numeric_limits<Integral>::max()`.
        inline with_inf(infty_t) : v{std::numeric_limits<Integral>::max()} {}

        /// Implicitly wraps @p n.
        inline with_inf(Integral n) : v{n} {}

        /// Prevents accidental cast from bool.
        with_inf(bool) = delete;

        /// Implicitly converts back to integral.
        inline operator Integral() const { return v; }

        /// Assigns the maximum.
        inline with_inf &operator=(infty_t) {
            v = std::numeric_limits<Integral>::max();
            return *this;
        }

        /**
         * @name Comparison operators
         * Compares against @ref pn532::infty (i.e. `std::numeric_limits<Integral>::max()`).
         */
        ///@{
        inline bool operator==(infty_t) const { return v == std::numeric_limits<Integral>::max(); }
        inline bool operator!=(infty_t) const { return v != std::numeric_limits<Integral>::max(); }
        ///@}
    };

    /**
     * @brief Shorthand wrapper for a byte with infinity expressed as 0xff.
     */
    using infbyte = with_inf<std::uint8_t>;

    /**
     * @defgroup PollTargetSpecialization Poll target specializations and mixins
     */

    /**
     * @brief A scanned @ref target, as a result of a polling operation.
     * Note that the actual content of the struture depends on the @ref baudrate_modulation, rather than
     * the actual @ref target_type.
     * For most target types, this is just a @ref target class. However, DEP entries also carry
     * a ATR_RES member @ref atr_res_info; these are
     *  - @ref poll_target<target_type::dep_passive_106kbps>
     *  - @ref poll_target<target_type::dep_passive_212kbps>
     *  - @ref poll_target<target_type::dep_passive_424kbps>
     *
     * Active DEP entries instead, have no @ref target member and only have a @ref atr_res_info member. These are
     *  - @ref poll_target<target_type::dep_active_106kbps>
     *  - @ref poll_target<target_type::dep_active_212kbps>
     *  - @ref poll_target<target_type::dep_active_424kbps>
     *
     * @see
     *  - pn532::controller::initiator_auto_poll
     *  - baudrate_modulation_of
     *  - any_poll_target
     *  - target
     * @tparam Type The target type @ref target_type.
     *
     * @rst
     * Poll target specializations and mixins
     * --------------------------------------
     * .. doxygengroup:: PollTargetSpecialization
     *    :content-only:
     *    :project: libSpookyAction
     *    :members:
     *    :outline:
     * @endrst
     */
    template <target_type Type>
    struct poll_target : public target<baudrate_modulation_of(Type)> {
    };

    /**
     * @addtogroup PollTargetSpecialization
     * @{
     */

    /**
     * Mixin for all DEP variants of @ref poll_target which carries a @ref atr_res_info member.
     */
    struct poll_target_with_atr {
        /**
         * @brief ATR_RES info associated to the activation of a DEP target
         * @see
         *  - pn532::controller::initiator_auto_poll
         *  - poll_target<target_type::dep_passive_106kbps>
         *  - poll_target<target_type::dep_passive_212kbps>
         *  - poll_target<target_type::dep_passive_424kbps>
         *  - poll_target<target_type::dep_active_106kbps>
         *  - poll_target<target_type::dep_active_212kbps>
         *  - poll_target<target_type::dep_active_424kbps>
         *  - pn532::controller::initiator_activate_target
         *  - pn532::controller::initiator_auto_poll
         *  - pn532::controller::initiator_jump_for_dep_active
         *  - pn532::controller::initiator_jump_for_dep_passive_106kbps
         *  - pn532::controller::initiator_jump_for_dep_passive_212kbps
         *  - pn532::controller::initiator_jump_for_dep_passive_424kbps
         *  - pn532::controller::initiator_jump_for_psl
         */
        atr_res_info atr_info;
    };

    /**
     * Mixin for all passive DEP variants of @ref poll_target, which carries both a @ref poll_target_with_atr and a @ref target.
         * @see
         *  - pn532::controller::initiator_auto_poll
         *  - target
         *  - poll_target_with_atr
         *  - atr_res_info
         *  - poll_target<target_type::dep_passive_106kbps>
         *  - poll_target<target_type::dep_passive_212kbps>
         *  - poll_target<target_type::dep_passive_424kbps>
     * @tparam BrMd Baudrate and modulation of the target.
     */
    template <baudrate_modulation BrMd>
    struct poll_target_dep_passive : public target<BrMd>, public poll_target_with_atr {
    };

    /**
     * @brief 106 kbps DEP passive polling target.
     * @see
     *  - pn532::controller::initiator_auto_poll
     *  - target<baudrate_modulation::kbps106_iso_iec_14443_typea>
     */
    template <>
    struct poll_target<target_type::dep_passive_106kbps> : public poll_target_dep_passive<
                                                                   baudrate_modulation_of(target_type::dep_passive_106kbps)> {
    };

    /**
     * @brief 212 kbps DEP passive polling target.
     * @see
     *  - pn532::controller::initiator_auto_poll
     *  - target<baudrate_modulation::kbps212_felica>
     */
    template <>
    struct poll_target<target_type::dep_passive_212kbps> : public poll_target_dep_passive<
                                                                   baudrate_modulation_of(target_type::dep_passive_212kbps)> {
    };

    /**
     * @brief 424 kbps DEP passive polling target.
     * @see
     *  - pn532::controller::initiator_auto_poll
     *  - target<baudrate_modulation::kbps424_felica>
     */
    template <>
    struct poll_target<target_type::dep_passive_424kbps> : public poll_target_dep_passive<
                                                                   baudrate_modulation_of(target_type::dep_passive_424kbps)> {
    };

    /**
     * @brief 106 kbps DEP active polling target.
     * @see
     *  - pn532::controller::initiator_auto_poll
     *  - target<baudrate_modulation::kbps106_iso_iec_14443_typea>
     */
    template <>
    struct poll_target<target_type::dep_active_106kbps> : public poll_target_with_atr {
    };

    /**
     * @brief 212 kbps DEP active polling target.
     * @see
     *  - pn532::controller::initiator_auto_poll
     *  - target<baudrate_modulation::kbps212_felica>
     */
    template <>
    struct poll_target<target_type::dep_active_212kbps> : public poll_target_with_atr {
    };

    /**
     * @brief 424 kbps DEP active polling target.
     * @see
     *  - pn532::controller::initiator_auto_poll
     *  - target<baudrate_modulation::kbps424_felica>
     */
    template <>
    struct poll_target<target_type::dep_active_424kbps> : public poll_target_with_atr {
    };

    /**
     * @}
     */

    /**
     * @brief Variant class that encompasses any of the @ref poll_target classes
     * @see
     *  - poll_target
     *  - pn532::controller::initiator_auto_poll
     */
    class any_poll_target : public mlab::any_of<target_type, poll_target> {
    public:
        using mlab::any_of<target_type, poll_target>::any_of;
        explicit any_poll_target(enum_type) = delete;
    };

    /**
     * Represents one of the accessible GPIOs of the PN532  (UM0701-02 §7.2.6).
     * @note I0 and I1 can be used as general purpose I/O once the selection of the transmission protocol
     * has been performed.
     * @see
     *  - pn532::controller::read_gpio
     *  - pn532::controller::write_gpio
     *  - pn532::controller::set_gpio_pin
     */
    enum struct gpio_port {
        p3, ///< P3 port GPIO.
        p7, ///< P6 port GPIO
        i0i1////< I0 and I1 port GPIO (the ones used to select the communication channel).
    };

    /**
     * @brief Data returned after "GetFirmwareVersion" (UM0701-02 §7.2.2).
     * @see pn532::controller::get_firmware_version
     */
    struct firmware_version {
        std::uint8_t ic;         //!< The IC version, for PN532 is always `0x32`
        std::uint8_t version;    //!< IC firmware version
        std::uint8_t revision;   //!< IC firmware revision
        bool iso_18092;          //!< The chip supports ISO18092 tags
        bool iso_iec_14443_typea;//!< The chip supports ISO 14443 TypeA tags
        bool iso_iec_14443_typeb;//!< The chip supports ISO 14443 TypeB tags
    };

    /**
     * @brief Data returned after most of initiator calls on @ref controller (UM0701-02 §7.1)
     * This represents the status of the RF communication after the completed command.
     */
    struct rf_status {
        bool nad_present;         //!< True if NAD bit is present
        bool expect_more_info;    //!< True if the tag expect another byte to be sent
        internal_error_code error;//!< PN532-specific error

        /**
         * @return True if @ref error is @ref internal_error_code::none.
         */
        inline explicit operator bool() const;
    };

    /**
     * @brief PN532 settings, i.e. data consumed by "SetParameters" (UM0701-02 §7.2.9)
     * @see pn532::controller::set_parameters
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
     * @brief Status of each activated target in the PN532 RF field. (UM0701-02 §7.2.3)
     * Only used as a member of @ref general_status.
     * @see general_status
     */
    struct general_status_target {
        std::uint8_t logical_index;//!< Tag index (given at initialization from the PN532)
        baudrate baudrate_rx;      //!< Bit rate in reception
        baudrate baudrate_tx;      //!< Bit rate in transmission
        modulation modulation_type;//!< Modulation type
    };

    /**
     * @brief Status of the SAM companion chip (UM0701-02 §7.2.3).
     * Only used as a member of @ref general_status.
     * @see general_status
     */
    struct general_status_sam {
        /// A full negative pulse has been detected on the CLAD line.
        bool neg_pulse_on_clad_line;
        /// An external RF field has been detected and switched off during or after a transaction.
        bool detected_rf_field_off;
        /// A timeout has been detected after SigActIRQ has felt down.
        bool timeout_after_sig_act_irq;
        /// The CLAD line is high level if and only if this bit is set.
        bool clad_line_high;
    };
    /**
     * @brief Data returned after "GetGeneralStatus" (UM0701-02 §7.2.3)
     * Represents the overall status of the PN532.
     * @see
     *  - general_status_sam
     *  - general_status_target
     *  - controller::get_general_status
     */
    struct general_status {
        internal_error_code last_error;            //!< Last error of the controller
        bool rf_field_present;                     //!< True if the RF field is switched on
        std::vector<general_status_target> targets;//!< Status of each of the targets (max 2) activated by the PN532.
        general_status_sam sam;                    //!< SAM status information
    };

    /**
     * @brief Status of the PN532 when operating as a target.
     * Data returned after "TgGetTargetStatus" (UM0701-02 §7.2.21)
     * @see controller::target_get_target_status
     */
    struct status_as_target {
        nfcip1_picc_status status;//!< Activation status.
        baudrate initiator_speed; //!< @ref baudrate supported by the initiator (only meaningful when the PN532 is activated).
        baudrate target_speed;    //!< @ref baudrate supported by the target (only meaningful when the PN532 is activated).
    };

    /**
     * @brief Result of the activation of target (active or passive) with DEP or PSL.
     * Data returned after "InJumpForDEP" and "InJumpForPSL" (UM0701-02 §7.3.3)
     * @see
     *  - pn532::controllerinitiator_jump_for_dep_active
     *  - pn532::controllerinitiator_jump_for_dep_passive_106kbps
     *  - pn532::controllerinitiator_jump_for_dep_passive_212kbps
     *  - pn532::controllerinitiator_jump_for_dep_passive_424kbps
     *  - pn532::controllerinitiator_jump_for_psl_active
     *  - pn532::controllerinitiator_jump_for_psl_passive_106kbps
     *  - pn532::controllerinitiator_jump_for_psl_passive_212kbps
     *  - pn532::controllerinitiator_jump_for_psl_passive_424kbps
     */
    struct jump_dep_psl {
        rf_status status{};                 //!< RF communication status (UM0701-02 §7.1)
        std::uint8_t target_logical_index{};//!< Logical number assigned to the target
        atr_res_info atr_info;              //!< ATR_RES sent by the target
    };

    /**
     * @brief Parameters for the PN532 to act as a Mifare target (UM0701-02 §7.3.21).
     * @see controller::target_init_as_target
     */
    struct mifare_params {
        std::array<std::uint8_t, 2> sens_res;//!< `SENS_RES` bytes
        std::array<std::uint8_t, 3> nfcid_1t;//!< NFCID 1t.
        std::uint8_t sel_res;                //!< `SEL_RES` byte
    };

    /**
     * @brief Parameters for the PN532 to act as a FeliCa target (UM0701-02 §7.3.21).
     * @note Identical to @ref target<baudrate_modulation::kbps212_felica>.
     */
    struct felica_params {
        std::array<std::uint8_t, 8> nfcid_2t; //!< NFCID 2t (includes a cascade byte).
        std::array<std::uint8_t, 8> pad;      //!< Padding bytes.
        std::array<std::uint8_t, 2> syst_code;//!< SYST_CODE.
    };

    /**
     * @brief Description of the mode in which the PN532 has been activated.
     * Only used as a member of @ref activation_as_target.
     * @see activation_as_target
     */
    struct activation_as_target_mode {
        baudrate speed;                //!< Trasmission baud rate.
        bool iso_iec_14443_4_picc;     //!< Whether the PN532 behaves as a ISO/IEC 1443-4 PICC
        bool dep;                      //!< Whether uses DEP
        framing_as_target framing_type;//!< Type of framing
    };

    /**
     * @brief Result of the activation procedure as a target.
     * Data returned after "TgInitAsTarget"  (UM0701-02 §7.3.14)
     * @see pn532::controller::target_init_as_target
     */
    struct activation_as_target {
        activation_as_target_mode mode;             //!< A byte containing witch mode the PN532 has been activated
        std::vector<std::uint8_t> initiator_command;//!< A vector containing the first frame received by the PN532
    };

    /**
     * @brief Bitmap of the PN532's GPIO.
     * This class holds the values of all the GPIOs on the ports P3, P7 and I0/I1 of the PN532.
     * You can set and read the whole mask (@ref gpio_status::mask, @ref gpio_status::set_mask) or individual
     * bits with @ref gpio_status::operator[]:
     * @code
     * gpio_status gpio{};
     * gpio[{gpio_port::p3, 2}] = true;
     * @endcode
     * @see
     *  - pn532::controller::read_gpio
     *  - pn532::controller::write_gpio
     *  - pn532::controller::set_gpio_pin
     * @note Setting a bit in this class does not automatically set it on the PN532, this just holds the value.
     *  You need to call e.g. @ref controller::write_gpio
     */
    class gpio_status {
    private:
        std::uint8_t _p3_mask = 0x00;
        std::uint8_t _p7_mask = 0x00;
        std::uint8_t _i0i1_mask = 0x00;

    public:
        /// Zero-initializes the data structure (all GPIO low).
        gpio_status() = default;

        /// Initialized the value of the GPIO for a bitmask for each port.
        inline gpio_status(std::uint8_t p3_mask, std::uint8_t p7_mask, std::uint8_t i0i1_mask);

        /// Read the bitmask of a single GPIO port.
        [[nodiscard]] inline std::uint8_t mask(gpio_port loc) const;

        /// Set the bitmask of a single GPIO port.
        inline void set_mask(gpio_port loc, std::uint8_t mask);

        /**
         * Reads the status of a single GPIO.
         * @param gpio_idx A port, index pair, e.g. `{gpio_port::p3, 2}`.
         * @return True if the GPIO is high.
         */
        [[nodiscard]] inline bool operator[](std::pair<gpio_port, std::uint8_t> const &gpio_idx) const;

        /**
         * Returns a writable reference to a single bit, representing the status of a single GPIO.
         * @param gpio_idx A port, index pair, e.g. `{gpio_port::p3, 2}`.
         * @return A `mlab::bit_ref` instance (which should not outlive this object).
         */
        inline mlab::bit_ref operator[](std::pair<gpio_port, std::uint8_t> const &gpio_idx);
    };
}// namespace pn532

namespace mlab {
#ifndef DOXYGEN_SHOULD_SKIP_THIS
    /**
     * @addtogroup IOOperators
     * @{
     */
    bin_data &operator<<(bin_data &bd, pn532::reg::ciu_212_424kbps const &reg);

    bin_data &operator<<(bin_data &bd, pn532::reg::ciu_106kbps_typea const &reg);

    bin_data &operator<<(bin_data &bd, pn532::reg::ciu_typeb const &reg);

    bin_data &operator<<(bin_data &bd, pn532::reg::ciu_iso_iec_14443_4_at_baudrate const &reg);

    bin_data &operator<<(bin_data &bd, pn532::reg::ciu_iso_iec_14443_4 const &reg);

    bin_data &operator<<(bin_data &bd, pn532::nfcid_2t const &uid);

    bin_data &operator<<(bin_data &bd, pn532::nfcid_3t const &uid);

    bin_data &operator<<(bin_data &bd, pn532::bits::reg_antenna_detector const &r);

    bin_data &operator<<(bin_data &s, pn532::parameters const &p);

    bin_data &operator<<(bin_data &s, std::vector<pn532::wakeup_source> const &vws);

    bin_data &operator<<(bin_data &s, pn532::mifare_params const &p);

    bin_data &operator<<(bin_data &s, pn532::felica_params const &p);

    template <pn532::baudrate_modulation BrMd>
    bin_stream &operator>>(bin_stream &s, std::vector<pn532::target<BrMd>> &targets);

    /**
     * @note This is a custom operator because we do not have ATS bytes.
     */
    bin_stream &operator>>(bin_stream &s, pn532::poll_target<pn532::target_type::dep_passive_106kbps> &entry);

    template <pn532::target_type Type>
    bin_stream &operator>>(bin_stream &s, pn532::poll_target<Type> &entry);

    bin_stream &operator>>(bin_stream &s, pn532::any_poll_target &t);

    bin_stream &operator>>(bin_stream &s, std::vector<pn532::any_poll_target> &targets);

    bin_stream &operator>>(bin_stream &s, std::pair<pn532::rf_status, bin_data> &status_data_pair);

    bin_stream &operator>>(bin_stream &s, pn532::rf_status &status);

    bin_stream &operator>>(bin_stream &s, pn532::gpio_status &gpio);

    bin_stream &operator>>(bin_stream &s, pn532::firmware_version &fw);

    bin_stream &operator>>(bin_stream &s, pn532::general_status &gs);

    bin_stream &operator>>(bin_stream &s, pn532::general_status_target &ts);

    bin_stream &operator>>(bin_stream &s, pn532::target_kbps106_typea &target);

    bin_stream &operator>>(bin_stream &s, pn532::target_kbps212_felica &target);

    bin_stream &operator>>(bin_stream &s, pn532::target_kbps424_felica &target);

    bin_stream &operator>>(bin_stream &s, pn532::target_kbps106_typeb &target);

    bin_stream &operator>>(bin_stream &s, pn532::target_kbps106_jewel_tag &target);

    bin_stream &operator>>(bin_stream &s, pn532::atr_res_info &atr_res);

    bin_stream &operator>>(bin_stream &s, std::pair<pn532::rf_status, pn532::atr_res_info> &status_atr_res);

    bin_stream &operator>>(bin_stream &s, pn532::bits::reg_antenna_detector &r);

    bin_stream &operator>>(bin_stream &s, pn532::jump_dep_psl &r);

    bin_stream &operator>>(bin_stream &s, pn532::general_status_sam &sams);

    bin_stream &operator>>(bin_stream &s, pn532::status_as_target &st);

    bin_stream &operator>>(bin_stream &s, pn532::activation_as_target_mode &mt);

    bin_stream &operator>>(bin_stream &s, pn532::activation_as_target &mt);
    /**
     * @}
     */
#endif
}// namespace mlab

namespace pn532 {

    rf_status::operator bool() const {
        return error == internal_error_code::none;
    }

    bool gpio_status::operator[](std::pair<gpio_port, std::uint8_t> const &gpio_idx) const {
        switch (gpio_idx.first) {
            case gpio_port::p3:
                return 0 != (_p3_mask & (1 << gpio_idx.second));
            case gpio_port::p7:
                return 0 != (_p7_mask & (1 << gpio_idx.second));
            case gpio_port::i0i1:
                return 0 != (_i0i1_mask & (1 << gpio_idx.second));
        }
    }

    mlab::bit_ref gpio_status::operator[](std::pair<gpio_port, std::uint8_t> const &gpio_idx) {
        static std::uint8_t _garbage = 0x00;
        switch (gpio_idx.first) {
            case gpio_port::p3:
                return mlab::bit_ref{_p3_mask, gpio_idx.second, bits::gpio_p3_pin_mask};
            case gpio_port::p7:
                return mlab::bit_ref{_p7_mask, gpio_idx.second, bits::gpio_p7_pin_mask};
            case gpio_port::i0i1:
                return mlab::bit_ref{_i0i1_mask, gpio_idx.second, bits::gpio_i0i1_pin_mask};
        }
        return mlab::bit_ref{_garbage, gpio_idx.second, 0xff};
    }

    gpio_status::gpio_status(std::uint8_t p3_mask, std::uint8_t p7_mask, std::uint8_t i0i1_mask) : _p3_mask{p3_mask}, _p7_mask{p7_mask}, _i0i1_mask{i0i1_mask} {}

    inline std::uint8_t gpio_status::mask(gpio_port loc) const {
        switch (loc) {
            case gpio_port::p3:
                return _p3_mask;
            case gpio_port::p7:
                return _p7_mask;
            case gpio_port::i0i1:
                return _i0i1_mask;
        }
        return 0x00;
    }

    void gpio_status::set_mask(gpio_port loc, std::uint8_t mask) {
        switch (loc) {
            case gpio_port::p3:
                _p3_mask = mask & bits::gpio_p3_pin_mask;
                break;
            case gpio_port::p7:
                _p7_mask = mask & bits::gpio_p7_pin_mask;
                break;
            case gpio_port::i0i1:
                _i0i1_mask = mask & bits::gpio_i0i1_pin_mask;
                break;
        }
    }

}// namespace pn532

namespace mlab {
    template <pn532::baudrate_modulation BrMd>
    bin_stream &operator>>(bin_stream &s, std::vector<pn532::target<BrMd>> &targets) {
        if (s.remaining() < 1) {
            PN532_LOGE("Parsing vector<target<%s>>: not enough data.", pn532::to_string(BrMd));
            s.set_bad();
            return s;
        }
        const auto num_targets = s.pop();
        if (num_targets > pn532::bits::max_num_targets) {
            PN532_LOGW("Parsing vector<target<%s>>: found %u targets, which is more than the number of supported targets %u.",
                       pn532::to_string(BrMd), num_targets, pn532::bits::max_num_targets);
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

    template <pn532::target_type Type>
    bin_stream &operator>>(bin_stream &s, pn532::poll_target<Type> &entry) {
        static constexpr pn532::baudrate_modulation BrMod = pn532::baudrate_modulation_of(Type);
        if constexpr (std::is_base_of_v<pn532::target<BrMod>, pn532::poll_target<Type>>) {
            s >> static_cast<pn532::target<BrMod> &>(entry);
        }
        if constexpr (std::is_base_of_v<pn532::poll_target_with_atr, pn532::poll_target<Type>>) {
            s >> static_cast<pn532::poll_target_with_atr &>(entry).atr_info;
        }
        return s;
    }

}// namespace mlab

#endif//PN532_DATA_HPP
