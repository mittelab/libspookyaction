//
// Created by Pietro Saccardi on 20/12/2020.
//

#ifndef PN532_CONTROLLER_HPP
#define PN532_CONTROLLER_HPP

#include <mlab/result.hpp>
#include <mutex>
#include <pn532/bits.hpp>
#include <pn532/channel.hpp>
#include <pn532/data.hpp>
#include <pn532/msg.hpp>

namespace pn532 {
    using namespace std::chrono_literals;
    /**
     * Default timeout for a regular PN532 operation. This value is very generous.
     */
    static constexpr ms default_timeout = 1s;
    /**
     * Default timeout for a long PN532 operation (e.g. diagnostics, or polling).
     */
    static constexpr ms long_timeout = 3s;
    using namespace mlab_literals;

    /**
     * @brief Class that controls a PN532, i.e. a `pn532::controller`, over some @ref channel.
     *
     * The PN532 can act both as an initiator and as a target; the members are thus prefixed with `initiator_` or
     * `target_`. This class has a move-only semantics.
     */
    class controller {
        std::recursive_mutex _mtx;

    public:
        /**
         * A list of all possible targets to poll.
         *
         * @note This does not contain every enum of @ref target_type, but rather one target for each
         *  @ref baudrate_modulation, which suffices for the PN532 to list all targets.
         *
         * @see initiator_auto_poll
         */
        static const std::vector<target_type> poll_all_targets;

        /**
         * Maximum number of targets the PN532 can scan for simultaneously.
         */
        static constexpr auto max_supported_targets = bits::max_num_targets;

        /**
         * @brief Constructs a PN532 controller over the given @ref channel implementation.
         *
         * The immediate steps after constructing a PN532 controller should be then
         *  1. calling @ref channel::wake to wake up the PN532;
         *  2. immediately afterwards, call @ref sam_configuration.
         * This is the procedure for priming the PN532 for usage
         *
         * @param chn An implementation of the PN532 communication channel. The caller is responsible of
         *  making sure that @p chn is a valid reference until this object is destructed.
         *
         * @todo Consider taking a `std::shared_ptr` for @p chn.
         */
        inline explicit controller(channel &chn);

        controller(controller const &) = delete;

        controller(controller &&) = delete;

        controller &operator=(controller const &) = delete;

        controller &operator=(controller &&) = delete;

        /**
         * @name Miscellanea commands
         * Instruction for configuration and self-test of the reader.
         * @{
         */

        /**
         * @brief Self-check PN532 ROM memory (UM0701-02 §7.2.1)
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return True if self-test is successful, false otherwise, or any of the @ref channel_error error conditions.
         */
        [[nodiscard]] result<bool> diagnose_rom(ms timeout = long_timeout);

        /**
         * @brief Self-check PN532 RAM memory (UM0701-02 §7.2.1)
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return True if self-test is successful, false otherwise, or any of the @ref channel_error error conditions.
         */
        [[nodiscard]] result<bool> diagnose_ram(ms timeout = long_timeout);

        /**
         * @brief Check if card is still inside the field (UM0701-02 §7.2.1).
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return True if card still present inside the field, false otherwise, or any of the @ref channel_error error conditions.
         */
        [[nodiscard]] result<bool> diagnose_attention_req_or_card_presence(ms timeout = long_timeout);

        /**
         * @brief Check communication channel by sending random data, and read it back (UM0701-02 §7.2.1).
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return True if data echoes without error, false otherwise, or any of the @ref channel_error error conditions.
         */
        [[nodiscard]] result<bool> diagnose_comm_line(ms timeout = long_timeout);

        /**
         * @brief Sends FeliCa polling command and count fails attempts (UM0701-02 §7.2.1).
         * @param slow Poll targets at 212Kbps.
         * @param fast Poll targets at 424Kbps.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return Number of fails (<128) at 212 Kbps, number of fails (<128) as 424 Kbps, or any of the @ref channel_error error conditions.
         */
        [[nodiscard]] result<unsigned, unsigned> diagnose_poll_target(bool slow = true, bool fast = true, ms timeout = long_timeout);

        /**
         * @brief Set the PN532 in target mode (simulating a NFC tag), and echo data back to the initiator after a delay (UM0701-02 §7.2.1).
         * @param reply_delay The time after which data is sent back to the initiator.
         * @param tx_mode Cfr. CIU_TxMode register (0x6302), §8.6.23.18 PN532/C1 Data sheet.
         * @param rx_mode Cfr. CIU_RxMode register (0x6303), §8.6.23.19 PN532/C1 Data sheet.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return Either `mlab::result_success` or any of the @ref channel_error error conditions.
         */
        [[nodiscard]] result<> diagnose_echo_back(ms reply_delay, std::uint8_t tx_mode, std::uint8_t rx_mode, ms timeout = long_timeout);

        /**
         * @brief Test antenna for open circuits, or shorts (UM0701-02 §7.2.1).
         * @param low_threshold Current threshold for low current error.
         * @param high_threshold Current threshold for high current error.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return True if self-test is successful, false otherwise, or any of the @ref channel_error error conditions.
         */
        [[nodiscard]] result<bool> diagnose_self_antenna(low_current_thr low_threshold, high_current_thr high_threshold, ms timeout = long_timeout);

        /**
         * @brief Retrieve the silicon version and firmware information and support (UM0701-02 §7.2.2).
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return Silicon version and firmware functionality support, or any of the @ref channel_error error conditions.
         */
        [[nodiscard]] result<firmware_version> get_firmware_version(ms timeout = default_timeout);

        /**
         * @brief Read the general status of the PN532 (last error, bitrate TX/RX, modulation and SAM status) (UM0701-02 §7.2.3).
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return PN532 status, or any of the @ref channel_error error conditions.
         */
        [[nodiscard]] result<general_status> get_general_status(ms timeout = default_timeout);

        /**
         * @brief Read multiple internal PN532 registers (UM0701-02 §7.2.4).
         * @param addresses Max 131 elements.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return Register values (respecting @p addresses order), or any of the @ref channel_error error conditions.
         */
        [[nodiscard]] result<std::vector<uint8_t>> read_registers(std::vector<reg::addr> const &addresses, ms timeout = default_timeout);

        /**
         * @brief Read a single internal PN532 register (UM0701-02 §7.2.4).
         * @param addr Register address.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return Register value, or any of the @ref channel_error error conditions.
         */
        inline result<uint8_t> read_register(reg::addr const &addr, ms timeout = default_timeout);

        /**
         * @brief Write multiple internal PN532 registers (UM0701-02 §7.2.5).
         * @param addr_value_pairs Max 87 register address-value pairs.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return Either `mlab::result_success` or any of the @ref channel_error error conditions.
         */
        result<> write_registers(std::vector<std::pair<reg::addr, std::uint8_t>> const &addr_value_pairs, ms timeout = default_timeout);

        /**
         * @brief Write a single internal PN532 register (UM0701-02 §7.2.5).
         * @param addr Register address.
         * @param val Value to write at @p addr.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return Either `mlab::result_success` or any of the @ref channel_error error conditions.
         */
        inline result<> write_register(reg::addr const &addr, std::uint8_t val, ms timeout = default_timeout);

        /**
         * @brief Read all GPIOs (UM0701-02 §7.2.6).
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return GPIO status, or any of the @ref channel_error error conditions.
         */
        [[nodiscard]] result<gpio_status> read_gpio(ms timeout = default_timeout);

        /**
         * @brief Write all GPIOs (UM0701-02 §7.2.7).
         * @param status GPIOs values to write
         * @param write_p3 Flag for masking the P3 GPIO bank (true is write, false is skip, in the latter case the value in @p status is ignored).
         * @param write_p7 Flag for masking the P7 GPIO bank (true is write, false is skip, in the latter case the value in @p status is ignored).
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return Either `mlab::result_success` or any of the @ref channel_error error conditions.
         */
        result<> write_gpio(gpio_status const &status, bool write_p3 = true, bool write_p7 = true, ms timeout = default_timeout);

        /**
         * @brief Write a single GPIO by doing @ref read_gpio followed by @ref write_gpio.
         * @param loc GPIO bank (e.g. P35 -> @ref pn532::gpio_port::p3).
         * @param pin_idx Pin number (e.g. P35 -> 5).
         * @param value Value for the GPIO pin.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return Either `mlab::result_success` or any of the @ref channel_error error conditions.
         */
        result<> set_gpio_pin(gpio_port loc, std::uint8_t pin_idx, bool value, ms timeout = default_timeout);

        /**
         * @brief Set the UART/HSU baudrate (UM0701-02 §7.2.8).
         * @note This command is allowed only for HSU communication.
         *       After 200uS from the ACK, commands with the new baudrate can be sent.
         * @param br New baudrate for subsequent commands.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return Either `mlab::result_success` or any of the @ref channel_error error conditions.
         */
        result<> set_serial_baud_rate(serial_baudrate br, ms timeout = default_timeout);

        /**
         * @brief Configure the SAM data path (UM0701-02 §7.2.10).
         * @param mode Configure how the SAM shall be used
         * @param sam_timeout In virtual card mode only, defines the timeout for transactions.
         * @param controller_drives_irq Specifies if the PN532 shall use the P70 pin for IRQ.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return Either `mlab::result_success` or any of the @ref channel_error error conditions.
         */
        result<> sam_configuration(sam_mode mode, ms sam_timeout, bool controller_drives_irq = true, ms timeout = default_timeout);

        /**
         * @brief Sets the PN532 working parameters (UM0701-02 §7.2.9).
         * @param parms Parameter settings.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return Either `mlab::result_success`, or any of the @ref channel_error error conditions.
         */
        result<> set_parameters(parameters const &parms, ms timeout = default_timeout);

        /**
         * @name Power down commands
         * @{
         * @brief Puts the PN532 (including the analog RF frontend) in power down mode (UM0701-02 §7.3.11).
         * @param wakeup_sources List of authorized sources that can wake the PN532 up.
         * @param generate_irq Defines whether once waken up, the PN532 handles the IRQ pin. This is only useful
         *  if @ref wakeup_source::rf is in @p wakeup_sources; in that case, when the RF field wakes the PN532 up,
         *  the IRQ pin is asserted.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return The @ref rf_status, or any of the @ref channel_error error conditions.
         */
        result<rf_status> power_down(std::vector<wakeup_source> const &wakeup_sources, bool generate_irq, ms timeout = default_timeout);
        result<rf_status> power_down(std::vector<wakeup_source> const &wakeup_sources, ms timeout = default_timeout);
        /**
         * @}
         */

        /**
         * @brief Performs SAM activation and some basic line and antenna tests.
         * Normally this is what you call right after waking up the PN532 via @ref channel::wake.
         * @return True if all critical tests passed, false otherwise.
         * @see
         *  - sam_configuration
         *  - diagnose_comm_line
         *  - diagnose_rom
         *  - diagnose_ram
         *  - diagnose_self_antenna
         */
        [[nodiscard]] bool init_and_test();
        /**
         * @}
         */

        /**
         * @name Configure RF parameters
         * Instruction for configuring the antenna parameters.
         * @{
         */

        /**
         * @brief Switch on or off the RF field (UM0701-02 §7.3.1).
         * @param auto_rfca Enable automatic RF field detection.
         * @param rf_on True for on, false for off.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return Either `mlab::result_success` or any of the @ref channel_error error conditions.
         */
        result<> rf_configuration_field(bool auto_rfca, bool rf_on, ms timeout = default_timeout);

        /**
         * @brief Set timeout for `ATR_RES` and non-DEP communications (UM0701-02 §7.3.1).
         * @param atr_res_timeout Set timeout for ATR request (use when PN532 is the initiator).
         * @param retry_timeout Set internal timeout for @ref controller::initiator_communicate_through. This is the timeout
         *  after which the PN532 itself gives up, not the timeout for the command we launch.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return Either `mlab::result_success` or any of the @ref channel_error error conditions.
         */
        result<> rf_configuration_timings(rf_timeout atr_res_timeout = rf_timeout::ms_102_4, rf_timeout retry_timeout = rf_timeout::ms_51_2, ms timeout = default_timeout);

        /**
         * @brief Set maximum retries for communicating with the target (UM0701-02 §7.3.1).
         * @param comm_retries Number of retries used for @ref controller::initiator_communicate_through.
         *  You can pass @ref infty here for infinite retries.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return Either `mlab::result_success` or any of the @ref channel_error error conditions.
         */
        result<> rf_configuration_retries(infbyte comm_retries = 0_b, ms timeout = default_timeout);

        /**
         * @brief Set maximum retries for ATR, PSL and passive actions (UM0701-02 §7.3.1).
         * @param atr_retries Number of retries after `ATR_RES`. You can pass @ref infty here for infinite retries.
         *  In passive mode, the PN532 will ignore this and always try twice.
         * @param psl_retries Number of retries after a `PSL_RES` or `PPS` response. You can pass @ref infty here for infinite retries.
         * @param passive_activation_retries Timeout for @ref controller::initiator_communicate_through; this is the timeout
         *  after which the PN532 itself gives up, not the timeout for the command we laucnh.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return Either `mlab::result_success` or any of the @ref channel_error error conditions.
         */
        result<> rf_configuration_retries(infbyte atr_retries, infbyte psl_retries, infbyte passive_activation_retries = infty, ms timeout = default_timeout);

        /**
         * @brief Set RF analog parameters for 106kbps type A tags (UM0701-02 §7.3.1).
         * @param config Register content with all the configuration options.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return Either `mlab::result_success` or any of the @ref channel_error error conditions.
         */
        result<> rf_configuration_analog_106kbps_typea(reg::ciu_106kbps_typea const &config, ms timeout = default_timeout);

        /**
         * @brief Set RF analog parameters for 212kbps and 424kbps tags (UM0701-02 §7.3.1).
         * @param config Register content with all the configuration options.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return Either `mlab::result_success` or any of the @ref channel_error error conditions.
         */
        result<> rf_configuration_analog_212_424kbps(reg::ciu_212_424kbps const &config, ms timeout = default_timeout);

        /**
         * @brief Set RF analog parameters for type B tags (UM0701-02 §7.3.1).
         * @param config Register content with all the configuration options.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return Either `mlab::result_success` or any of the @ref channel_error error conditions.
         */
        result<> rf_configuration_analog_typeb(reg::ciu_typeb const &config, ms timeout = default_timeout);

        /**
         * @brief Set RF analog parameters for 212kbps,424kbps and 848kbps tags communicating with the ISO/IEC14443-4 protocol (UM0701-02 §7.3.1).
         * @param config Register content with all the configuration options.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return Either `mlab::result_success` or any of the @ref channel_error error conditions.
         */
        result<> rf_configuration_analog_iso_iec_14443_4(reg::ciu_iso_iec_14443_4 const &config, ms timeout = default_timeout);

        /**
         * @brief Perform radio regulation test (UM0701-02 §7.3.2).
         * The PN532 transmits data until a new command is sent to it.
         * @param mode Bit rate and framing used for testing
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return The @ref rf_status, or any of the @ref channel_error error conditions.
         */
        result<> rf_regulation_test(rf_test_mode mode, ms timeout = default_timeout);

        /**
         * @}
         */


        /**
         * @name Talk to a PICC
         * Instruction for interfacing with a PICC (NFC tag).
         * @{
         */

        /**
         * @brief Exchange data with the target (UM0701-02 §7.3.8).
         * @param target_logical_index Index the PN532 has given to the tag,
         *  can be retrieved with `initiator_list_passive_*` commands or via @ref initiator_auto_poll.
         * @param data Any object that can be injected into a `mlab::bin_data` object. If the total payload exceeds 262
         *  bytes, multiple commands will be issued.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return The @ref rf_status and the data sent by the target as a response, or any of the @ref channel_error error conditions.
         */
        template <class T, class = typename std::enable_if<not std::is_same_v<bin_data, typename std::decay_t<T>::type>>::type>
        [[nodiscard]] result<rf_status, bin_data> initiator_data_exchange(std::uint8_t target_logical_index, T &&data, ms timeout = default_timeout);

        /**
         * @brief Exchange data with the target (UM0701-02 §7.3.8).
         * @param target_logical_index Index the PN532 has given to the tag,
         *  can be retrieved with `initiator_list_passive_*` commands or via @ref initiator_auto_poll.
         * @param data If the total payload exceeds 262 bytes, multiple commands will be issued.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return The @ref rf_status and the data sent by the target as a response, or any of the @ref channel_error error conditions.
         */
        [[nodiscard]] result<rf_status, bin_data> initiator_data_exchange(std::uint8_t target_logical_index, bin_data const &data, ms timeout = default_timeout);

        /**
         * @brief Select the tag, subsequent commands will effect the selected tag (UM0701-02 §7.3.12).
         * @param target_logical_index Index the PN532 has given to the tag,
         *  can be retrieved with `initiator_list_passive_*` commands or via @ref initiator_auto_poll.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return The @ref rf_status, or any of the @ref channel_error error conditions.
         */
        result<rf_status> initiator_select(std::uint8_t target_logical_index, ms timeout = default_timeout);

        /**
         * @brief Deselect the tag, but maintain the information (UM0701-02 §7.3.10).
         * @param target_logical_index Index the PN532 has given to the tag,
         *  can be retrieved with `initiator_list_passive_*` commands or via @ref initiator_auto_poll.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return The @ref rf_status, or any of the @ref channel_error error conditions.
         */
        result<rf_status> initiator_deselect(std::uint8_t target_logical_index, ms timeout = default_timeout);

        /**
         * @brief Release the tag, deselect and delete the information (UM0701-02 §7.3.11).
         * @param target_logical_index Index the PN532 has given to the tag,
         *  can be retrieved with `initiator_list_passive_*` commands or via @ref initiator_auto_poll.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return The @ref rf_status, or any of the @ref channel_error error conditions.
         */
        result<rf_status> initiator_release(std::uint8_t target_logical_index, ms timeout = default_timeout);

        /**
         * @brief Change baudrate of a TPE or ISO/IEC14443-4 target (UM0701-02 §7.3.7).
         * @param target_logical_index Index the PN532 has given to the tag,
         *  can be retrieved with `initiator_list_passive_*` commands or via @ref initiator_auto_poll.
         * @param in_to_trg Baudrate for communications from the initiator (PN532) to the target (tag).
         * @param trg_to_in Baudrate for communications from the target (tag) to the initiator (PN532).
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return The @ref rf_status, or any of the @ref channel_error error conditions.
         */
        result<rf_status> initiator_psl(std::uint8_t target_logical_index, baudrate in_to_trg, baudrate trg_to_in, ms timeout = default_timeout);

        /**
         * @brief List all TypeA tags in range (at 106kbps baudrate) (UM0701-02 §7.3.5).
         * @param max_targets Max number of target to list and initialize.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return A list of targets @ref target<baudrate_modulation::kbps106_iso_iec_14443_typea>, or any of the @ref channel_error error conditions.
         */
        [[nodiscard]] result<std::vector<target_kbps106_typea>> initiator_list_passive_kbps106_typea(std::uint8_t max_targets = max_supported_targets, ms timeout = long_timeout);

        /**
         * @name Listing passive 106kbps type A targets
         * @{
         * @brief Check for a specific TypeA tag by UID (at 106kbps baudrate) (UM0701-02 §7.3.5).
         * @param max_targets Max number of target to list and initialize.
         * @param uid The UID of the tag to initialize.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return A list of targets @ref target<baudrate_modulation::kbps106_iso_iec_14443_typea>, or any of the @ref channel_error error conditions.
         */
        [[nodiscard]] result<std::vector<target_kbps106_typea>> initiator_list_passive_kbps106_typea(nfcid_1t uid, std::uint8_t max_targets = 1, ms timeout = long_timeout);
        [[nodiscard]] result<std::vector<target_kbps106_typea>> initiator_list_passive_kbps106_typea(nfcid_2t uid, std::uint8_t max_targets = 1, ms timeout = long_timeout);
        [[nodiscard]] result<std::vector<target_kbps106_typea>> initiator_list_passive_kbps106_typea(nfcid_3t uid, std::uint8_t max_targets = 1, ms timeout = long_timeout);

        /**
         * @}
         */

        /**
         * @brief List all TypeB tags in range (at 106kbps baudrate) (UM0701-02 §7.3.5).
         * @param application_family_id The application family identifier (AFI) to pre-select before ATQB.
         * @param method Type of ISO/IEC14443-3B polling, options are @ref polling_method::timeslot and @ref polling_method::probabilistic.
         * @param max_targets Max number of target to list and initialize.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return A list of targets @ref target<baudrate_modulation::kbps106_iso_iec_14443_3_typeb>, or any of the @ref channel_error error conditions.
         */
        [[nodiscard]] result<std::vector<target_kbps106_typeb>> initiator_list_passive_kbps106_typeb(
                std::uint8_t application_family_id, polling_method method = polling_method::timeslot,
                std::uint8_t max_targets = max_supported_targets, ms timeout = long_timeout);

        /**
         * @brief List all FeliCa tags in range (at 212kbps baudrate) (UM0701-02 §7.3.5).
         * @param payload The payload to send to the tags (structure defined in ISO/IEC 18092 §11.2.2.5).
         * @param max_targets Max number of target to list and initialize.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return a list of targets @ref target<baudrate_modulation::kbps212_felica>, or any of the @ref channel_error error conditions.
         */
        [[nodiscard]] result<std::vector<target_kbps212_felica>> initiator_list_passive_kbps212_felica(
                std::array<std::uint8_t, 5> const &payload, std::uint8_t max_targets = max_supported_targets,
                ms timeout = long_timeout);

        /**
         * @brief List all FeliCa tags in range (at 424kbps baudrate) (UM0701-02 §7.3.5).
         * @param payload The payload to send to the tags (structure defined in ISO/IEC 18092 §11.2.2.5).
         * @param max_targets Max number of target to list and initialize.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return a list of targets @ref target<baudrate_modulation::kbps424_felica>, or any of the @ref channel_error error conditions.
         */
        [[nodiscard]] result<std::vector<target_kbps424_felica>> initiator_list_passive_kbps424_felica(
                std::array<std::uint8_t, 5> const &payload, std::uint8_t max_targets = max_supported_targets,
                ms timeout = long_timeout);

        /**
         * @brief List all Innovision Jewel tags in range (at 106kbps baudrate) (UM0701-02 §7.3.5).
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return A list of targets @ref target<baudrate_modulation::kbps106_innovision_jewel_tag>, or any of the @ref channel_error error conditions.
         */
        [[nodiscard]] result<std::vector<target_kbps106_jewel_tag>> initiator_list_passive_kbps106_jewel_tag(ms timeout = long_timeout);

        /**
         * @name Activate a known logical target
         * @{
         * @brief Launch an activation request of the target (UM0701-02 §7.3.6).
         * @param target_logical_index Index the PN532 has given to the tag,
         *  can be retrieved with `initiator_list_passive_*` commands or via @ref initiator_auto_poll.
         * @param nfcid the NFCID3 used for the `ATR_REQ`
         * @param general_info General info bytes to send. Max 48 bytes.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return The @ref rf_status and @ref atr_res_info, or any of the @ref channel_error error conditions.
         */
        result<rf_status, atr_res_info> initiator_activate_target(std::uint8_t target_logical_index, nfcid_3t const &nfcid, std::vector<std::uint8_t> const &general_info, ms timeout = default_timeout);
        result<rf_status, atr_res_info> initiator_activate_target(std::uint8_t target_logical_index, std::vector<std::uint8_t> const &general_info, ms timeout = default_timeout);
        result<rf_status, atr_res_info> initiator_activate_target(std::uint8_t target_logical_index, nfcid_3t const &nfcid, ms timeout = default_timeout);
        result<rf_status, atr_res_info> initiator_activate_target(std::uint8_t target_logical_index, ms timeout = default_timeout);
        /**
         * @}
         */

        /**
         * @brief Check specified tags in range, and automatically initialize them (UM0701-02 §7.3.13).
         * @note @p timeout >= @p types_to_poll.size() * @p polls_per_type * @p period
         * @param types_to_poll Minimum 1, maximum 15 elements.
         * @param polls_per_type Poll attempts for each tag type. You can pass @ref infty for infinite retries.
         * @param period Time between each attempt.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return List of targets @ref any_poll_target, or any of the @ref channel_error error conditions.
         */
        [[nodiscard]] result<std::vector<any_poll_target>> initiator_auto_poll(
                std::vector<target_type> const &types_to_poll = poll_all_targets,
                infbyte polls_per_type = 3_b, poll_period period = poll_period::ms_150, ms timeout = long_timeout);

        /**
         * @brief Exchange data with the tag, but directly (no chaining and error handling) (UM0701-02 §7.3.9).
         * @param raw_data Max 264 bytes, data will be truncated. To transmit more, use @ref initiator_data_exchange.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return The @ref rf_status and the data sent by the target as a response, or any of the @ref channel_error error conditions.
         */
        [[nodiscard]] result<rf_status, bin_data> initiator_communicate_through(bin_data raw_data, ms timeout = default_timeout);

        /**
         * @name Activate any active DEP target
         * @{
         * @brief Activate the target with active or passive communication (UM0701-02 §7.3.3).
         * @param speed Communication baudrate.
         * @param nfcid The NFCID3 used for the `ATR_REQ`.
         * @param general_info General info bytes to send. Max 48 bytes.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return The outcome @ref jump_dep_psl, or any of the @ref channel_error error conditions.
         */
        result<jump_dep_psl> initiator_jump_for_dep_active(baudrate speed, nfcid_3t const &nfcid, std::vector<std::uint8_t> const &general_info, ms timeout = default_timeout);
        result<jump_dep_psl> initiator_jump_for_dep_active(baudrate speed, std::vector<std::uint8_t> const &general_info, ms timeout = default_timeout);
        result<jump_dep_psl> initiator_jump_for_dep_active(baudrate speed, nfcid_3t const &nfcid, ms timeout = default_timeout);
        result<jump_dep_psl> initiator_jump_for_dep_active(baudrate speed, ms timeout = default_timeout);
        /**
         * @}
         */

        /**
         * @name Activate a specific passive 106 kbps DEP target
         * @{
         * @brief Activate the target with active or passive communication (UM0701-02 §7.3.3).
         * @param target_id NFCID of the target to activate.
         * @param nfcid The NFCID3 used for the `ATR_REQ`.
         * @param general_info General info bytes to send. Max 48 bytes.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return The outcome @ref jump_dep_psl, or any of the @ref channel_error error conditions.
         */
        result<jump_dep_psl> initiator_jump_for_dep_passive_106kbps(nfcid_1t target_id, nfcid_3t const &nfcid, std::vector<std::uint8_t> const &general_info, ms timeout = default_timeout);
        result<jump_dep_psl> initiator_jump_for_dep_passive_106kbps(nfcid_1t target_id, std::vector<std::uint8_t> const &general_info, ms timeout = default_timeout);
        result<jump_dep_psl> initiator_jump_for_dep_passive_106kbps(nfcid_1t target_id, nfcid_3t const &nfcid, ms timeout = default_timeout);
        result<jump_dep_psl> initiator_jump_for_dep_passive_106kbps(nfcid_1t target_id, ms timeout = default_timeout);
        /**
         * @}
         */

        /**
         * @name Activate any passive 106 kbps DEP target
         * @{
         * @brief Activate the target with active or passive communication (UM0701-02 §7.3.3).
         * @param nfcid The NFCID3 used for the `ATR_REQ`.
         * @param general_info General info bytes to send. Max 48 bytes.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return The outcome @ref jump_dep_psl, or any of the @ref channel_error error conditions.
         */
        result<jump_dep_psl> initiator_jump_for_dep_passive_106kbps(nfcid_3t const &nfcid, std::vector<std::uint8_t> const &general_info, ms timeout = default_timeout);
        result<jump_dep_psl> initiator_jump_for_dep_passive_106kbps(std::vector<std::uint8_t> const &general_info, ms timeout = default_timeout);
        result<jump_dep_psl> initiator_jump_for_dep_passive_106kbps(nfcid_3t const &nfcid, ms timeout = default_timeout);
        result<jump_dep_psl> initiator_jump_for_dep_passive_106kbps(ms timeout = default_timeout);
        /**
         * @}
         */


        /**
         * @name Activate a specific passive 212 kbps DEP target
         * @{
         * @brief Activate the target with active or passive communication (UM0701-02 §7.3.3).
         * @param payload The payload to send to the tags (structure defined in ISO/IEC 18092 §11.2.2.5).
         * @param general_info General info bytes to send. Max 48 bytes.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return The outcome @ref jump_dep_psl, or any of the @ref channel_error error conditions.
         */
        result<jump_dep_psl> initiator_jump_for_dep_passive_212kbps(std::array<std::uint8_t, 5> const &payload, std::vector<std::uint8_t> const &general_info, ms timeout = default_timeout);
        result<jump_dep_psl> initiator_jump_for_dep_passive_212kbps(std::array<std::uint8_t, 5> const &payload, ms timeout = default_timeout);
        /**
         * @}
         */

        /**
         * @name Activate a specific passive 424 kbps DEP target
         * @{
         * @brief Activate the target with active or passive communication (UM0701-02 §7.3.3).
         * @param payload The payload to send to the tags (structure defined in ISO/IEC 18092 §11.2.2.5).
         * @param general_info General info bytes to send. Max 48 bytes.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return The outcome @ref jump_dep_psl, or any of the @ref channel_error error conditions.
         */
        result<jump_dep_psl> initiator_jump_for_dep_passive_424kbps(std::array<std::uint8_t, 5> const &payload, std::vector<std::uint8_t> const &general_info, ms timeout = default_timeout);
        result<jump_dep_psl> initiator_jump_for_dep_passive_424kbps(std::array<std::uint8_t, 5> const &payload, ms timeout = default_timeout);
        /**
         * @}
         */

        /**
         * @name Activate any active PSL target
         * @{
         * @brief Activate the target with active or passive communication (UM0701-02 §7.3.3).
         * @param speed Communication baudrate.
         * @param nfcid The NFCID3 used for the `ATR_REQ`.
         * @param general_info General info bytes to send. Max 48 bytes.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return The outcome @ref jump_dep_psl, or any of the @ref channel_error error conditions.
         */
        result<jump_dep_psl> initiator_jump_for_psl_active(baudrate speed, nfcid_3t const &nfcid, std::vector<std::uint8_t> const &general_info, ms timeout = default_timeout);
        result<jump_dep_psl> initiator_jump_for_psl_active(baudrate speed, std::vector<std::uint8_t> const &general_info, ms timeout = default_timeout);
        result<jump_dep_psl> initiator_jump_for_psl_active(baudrate speed, nfcid_3t const &nfcid, ms timeout = default_timeout);
        result<jump_dep_psl> initiator_jump_for_psl_active(baudrate speed, ms timeout = default_timeout);
        /**
         * @}
         */

        /**
         * @name Activate any passive PSL 106 kbps target
         * @{
         * @brief Activate the target with active or passive communication (UM0701-02 §7.3.3).
         * @param nfcid The NFCID3 used for the `ATR_REQ`.
         * @param general_info General info bytes to send. Max 48 bytes.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return The outcome @ref jump_dep_psl, or any of the @ref channel_error error conditions.
         */
        result<jump_dep_psl> initiator_jump_for_psl_passive_106kbps(nfcid_3t const &nfcid, std::vector<std::uint8_t> const &general_info, ms timeout = default_timeout);
        result<jump_dep_psl> initiator_jump_for_psl_passive_106kbps(std::vector<std::uint8_t> const &general_info, ms timeout = default_timeout);
        result<jump_dep_psl> initiator_jump_for_psl_passive_106kbps(nfcid_3t const &nfcid, ms timeout = default_timeout);
        result<jump_dep_psl> initiator_jump_for_psl_passive_106kbps(ms timeout = default_timeout);
        /**
         * @}
         */

        /**
         * @name Activate a specific passive PSL 106 kbps target
         * @{
         * @brief Activate the target with active or passive communication (UM0701-02 §7.3.3).
         * @param target_id NFCID of the target to activate.
         * @param nfcid The NFCID3 used for the `ATR_REQ`.
         * @param general_info General info bytes to send. Max 48 bytes.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return The outcome @ref jump_dep_psl, or any of the @ref channel_error error conditions.
         */
        result<jump_dep_psl> initiator_jump_for_psl_passive_106kbps(nfcid_1t target_id, nfcid_3t const &nfcid, std::vector<std::uint8_t> const &general_info, ms timeout = default_timeout);
        result<jump_dep_psl> initiator_jump_for_psl_passive_106kbps(nfcid_1t target_id, std::vector<std::uint8_t> const &general_info, ms timeout = default_timeout);
        result<jump_dep_psl> initiator_jump_for_psl_passive_106kbps(nfcid_1t target_id, nfcid_3t const &nfcid, ms timeout = default_timeout);
        result<jump_dep_psl> initiator_jump_for_psl_passive_106kbps(nfcid_1t target_id, ms timeout = default_timeout);
        /**
         * @}
         */

        /**
         * @name Activate a specific passive PSL 212 kbps target
         * @{
         * @brief Activate the target with active or passive communication (UM0701-02 §7.3.3).
         * @param payload The payload to send to the tags (structure defined in ISO/IEC 18092 §11.2.2.5).
         * @param general_info General info bytes to send. Max 48 bytes.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return The outcome @ref jump_dep_psl, or any of the @ref channel_error error conditions.
         */
        result<jump_dep_psl> initiator_jump_for_psl_passive_212kbps(std::array<std::uint8_t, 5> const &payload, std::vector<std::uint8_t> const &general_info, ms timeout = default_timeout);
        result<jump_dep_psl> initiator_jump_for_psl_passive_212kbps(std::array<std::uint8_t, 5> const &payload, ms timeout = default_timeout);
        /**
         * @}
         */

        /**
         * @name Activate a specific passive PSL 424 kbps target
         * @{
         * @brief Activate the target with active or passive communication (UM0701-02 §7.3.3).
         * @param payload The payload to send to the tags (structure defined in ISO/IEC 18092 §11.2.2.5).
         * @param general_info General info bytes to send. Max 48 bytes.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return The outcome @ref jump_dep_psl, or any of the @ref channel_error error conditions.
         */
        result<jump_dep_psl> initiator_jump_for_psl_passive_424kbps(std::array<std::uint8_t, 5> const &payload, std::vector<std::uint8_t> const &general_info, ms timeout = default_timeout);
        result<jump_dep_psl> initiator_jump_for_psl_passive_424kbps(std::array<std::uint8_t, 5> const &payload, ms timeout = default_timeout);
        /**
         * @}
         */

        /**
         * @}
         */

        /**
         * @name Emulating a PICC
         * Instruction for Emulating a PICC (NFC tag).
         * @{
         */

        /**
         * @brief Queries in what state the PN532 is, as a target (UM0701-02 §7.3.21).
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return The @ref status_as_target, or any of the @ref channel_error error conditions.
         */
        [[nodiscard]] result<status_as_target> target_get_target_status(ms timeout = default_timeout);

        /**
         * @brief Configure the PN532 as a target (UM0701-02 §7.3.14).
         * @param picc_only If true, the PN532 can only be initialized via a `RATS` frame,
         *  i.e. as a ISO/IEC14443-4 PICC.
         * @param dep_only If true, the PN532 can only be initialized via a `ATR_REQ` frame,
         *  i.e. as an active or passive DEP target.
         * @param passive_only If true, the PN532 refuses the active mode.
         * @param mifare Information needed to be activate at 106 Kbps in passive mode.
         * @param felica Information needed to be able to respond to a polling request at
         *  212/424 Kbps in passive mode.
         * @param nfcid The NFCID3 used for the `ATR_REQ` response.
         * @param general_info General bytes to use in the `ATR_RES` response.
         *  Max 47 bytes, if exceeding, it will be truncated.
         * @param historical_bytes Historical bytes to be used in the `ATS` when the PN532 is
         *  in ISO/IEC14443-4 PICC emulation mode.
         *  Max 48 bytes, if exceeding, it will be truncated.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return The outcome @ref activation_as_target, or any of the @ref channel_error error conditions.
         */
        [[nodiscard]] result<activation_as_target> target_init_as_target(
                bool picc_only, bool dep_only, bool passive_only, mifare_params const &mifare,
                felica_params const &felica, nfcid_3t const &nfcid,
                std::vector<std::uint8_t> const &general_info = {},
                std::vector<std::uint8_t> const &historical_bytes = {}, ms timeout = default_timeout);

        /**
         * @brief Used in combination with @ref target_init_as_target for generating the ATR_RES request (UM0701-02 §7.3.15).
         * When used, it must follow @ref target_init_as_target.
         * @param general_info General bytes to use in the `ATR_RES` response to the initiator.
         *  Max 47 bytes, if exceeding, it will be truncated.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return The @ref rf_status, or any of the @ref channel_error error conditions.
         */
        result<rf_status> target_set_general_bytes(std::vector<std::uint8_t> const &general_info, ms timeout = default_timeout);

        /**
         * @brief Get data sent by the initiator (UM0701-02 §7.3.16).
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return The @ref rf_status and the data sent by the initiator, or any of the @ref channel_error error conditions.
         */
        [[nodiscard]] result<rf_status, bin_data> target_get_data(ms timeout = default_timeout);

        /**
         * @brief Set data to be sent at the initiator (UM0701-02 §7.3.17).
         * @param data Max 262 bytes, if exceeding, it will be truncated. To send more, use several
         *  @ref target_set_metadata calls, and conclude with @ref target_set_data.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return The @ref rf_status, or any of the @ref channel_error error conditions.
         * @see target_set_metadata
         */
        result<rf_status> target_set_data(std::vector<std::uint8_t> const &data, ms timeout = default_timeout);

        /**
         * @brief Used to send more than 262 bytes when in DEP mode (UM0701-02 §7.3.18).
         * As long as more data has to be sent, call @ref target_set_metadata; as the last <262 packet is being
         * sent, call instead @ref target_set_metadata.
         * @note The name is misleading; in fact, this sends data with the "more information" bit set, while
         *  @ref target_set_data does not (chaining).
         * @param data Max 262 bytes, if exceeding, it will be truncated.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return The @ref rf_status, or any of the @ref channel_error error conditions.
         * @see target_set_data
         */
        result<rf_status> target_set_metadata(std::vector<std::uint8_t> const &data, ms timeout = default_timeout);

        /**
         * @brief Get a packet from the initiator (UM0701-02 §7.3.19).
         * This is similar to @ref target_get_data, but here the PN532 does not handle supervisory, chaining, error
         * handling and so on.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return The @ref rf_status and the data sent by the initiator, or any of the @ref channel_error error conditions.
         * @see target_get_data
         */
        [[nodiscard]] result<rf_status, bin_data> target_get_initiator_command(ms timeout = default_timeout);

        /**
         * @brief Send a response packet to the initiator (UM0701-02 §7.3.21).
         * This is similar to @ref target_set_data, but here the PN532 does not handle supervisory, chaining, error
         * handling and so on.
         * @param data Max 262 bytes, if exceeding, it will be truncated.
         * @param timeout Maximum time after which @ref channel_error::timeout is returned.
         * @return The @ref rf_status, or any of the @ref channel_error error conditions.
         * @see target_set_data
         */
        result<rf_status> target_response_to_initiator(std::vector<std::uint8_t> const &data, ms timeout = default_timeout);
        /**
         * @}
         */

    private:
        channel *_channel;

        [[nodiscard]] inline channel &chn() const;

        [[nodiscard]] static std::uint8_t get_target(command_code cmd, std::uint8_t target_logical_index, bool expect_more_data);

        template <baudrate_modulation BrMd>
        result<std::vector<target<BrMd>>> initiator_list_passive(std::uint8_t max_targets, bin_data const &initiator_data, ms timeout);
    };

}// namespace pn532


namespace pn532 {

    controller::controller(channel &chn) : _channel{&chn} {}

    channel &controller::chn() const { return *_channel; }

    result<uint8_t> controller::read_register(reg::addr const &addr, ms timeout) {
        if (const auto res_cmd = read_registers({addr}, timeout); res_cmd) {
            return res_cmd->at(0);
        } else {
            return res_cmd.error();
        }
    }

    result<> controller::write_register(reg::addr const &addr, std::uint8_t val, ms timeout) {
        return write_registers({{addr, val}}, timeout);
    }

    template <class T, class>
    result<rf_status, bin_data> controller::initiator_data_exchange(std::uint8_t target_logical_index, T &&data, ms timeout) {
        static bin_data buffer{};
        buffer.clear();
        buffer << std::forward<T>(data);
        return initiator_data_exchange(target_logical_index, buffer, timeout);
    }

}// namespace pn532


#endif//PN532_CONTROLLER_HPP
