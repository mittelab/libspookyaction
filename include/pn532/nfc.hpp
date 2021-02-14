//
// Created by Pietro Saccardi on 20/12/2020.
//

/**
 * @defgroup NFC Reader
 * @{
 */

/**
 * @defgroup Miscellaneous Miscelanea commands
 * Instruction for configuration and self-test of the reader
 */

/**
 * @defgroup RF Configure RF parameters
 * Instruction for configurating the antenna parameters
 */

/**
 * @defgroup Initiator Talk to a PICC
 * Instruction for interfacing with a PICC(NFC tag)
 */

/**
 * @defgroup Target Emulating a PICC
 * Instruction for Emulating a PICC(NFC tag)
 */

/**
 * @}
 */

#ifndef APERTURAPORTA_NFC_HPP
#define APERTURAPORTA_NFC_HPP

#include "bits.hpp"
#include "channel.hpp"
#include "data.hpp"
#include "mlab/result.hpp"
#include "msg.hpp"

namespace pn532 {

    static constexpr ms default_timeout = one_sec;
    static constexpr ms long_timeout = 3 * default_timeout;

    class nfc {
    public:
        enum struct error {
            canceled,
            comm_timeout,
            comm_checksum_fail,
            comm_error,
            comm_malformed,
            nack,
            failure
        };

        static const std::vector<bits::target_type> poll_all_targets;

        template <class... Tn>
        using r = result<error, Tn...>;

        inline explicit nfc(channel &chn);

        nfc(nfc const &) = delete;

        nfc(nfc &&) = default;

        nfc &operator=(nfc const &) = delete;

        nfc &operator=(nfc &&) = default;

        /**
         * @brief send ACK or NACK frame
         * @internal
         * @param ack true for sending ACK, otherwhise sends NACK
         * @param timeout maximum time for getting a response
         * @return No data, but can return the following errors: @ref error::comm_timeout.
         */
        r<> raw_send_ack(bool ack = true, ms timeout = default_timeout);

        /**
         * @brief Send command via the channel defined in the cosnstructor @ref pn532::nfc::chn
         * @internal
         * @param cmd Command code
         * @param payload Max 263 bytes, will be truncated
         * @param timeout maximum time for getting a response
         * @return No data, but can return the following errors: @ref error::comm_timeout.
         */
        r<> raw_send_command(command_code cmd, bin_data const &payload, ms timeout = default_timeout);

        /**
         * @brief Wait for an ACK or NACK
         * @internal
         * @param timeout maximum time for getting a response
         * @returns true if ACK otherwhise false if NACK or the following errors: @ref error::comm_error,
         *  @ref error::comm_malformed, @ref error::comm_timeout
         */
        r<bool> raw_await_ack(ms timeout = default_timeout);

        /**
         * @brief Wait for a response frame of a command
         * @internal
         * @param cmd Command code
         * @param timeout maximum time for getting a response
         * @return Either the received data, or one of the following errors: @ref error::comm_malformed,
         *  @ref error::comm_checksum_fail, or @ref error::comm_timeout. No other error codes are produced.
         */
        r<bin_data> raw_await_response(command_code cmd, ms timeout = default_timeout);

        /**
         * @brief Command without response
         * @internal
         * @param cmd Command code
         * @param payload Max 263 bytes, will be truncated
         * @param timeout maximum time for getting a response
         * @return No data, but can return the following errors: @ref error::comm_timeout, @ref error::nack,
         *   @ref error::comm_malformed
         */
        r<> command(command_code cmd, bin_data const &payload, ms timeout = default_timeout);

        /**
         * @brief Command with response
         * @internal
         * @param cmd Command code
         * @param payload Max 263 bytes, will be truncated
         * @param timeout maximum time for getting a response
         * @return Either the received data, or one of the following errors:
         *         - @ref error::comm_malformed
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<bin_data> command_response(command_code cmd, bin_data const &payload, ms timeout = default_timeout);

        /**
         * @brief Get data from a command response
         * @internal
         * @param cmd Command code
         * @param payload Max 263 bytes, will be truncated
         * @param timeout maximum time for getting a response
         * @return Either Data, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        template <class Data, class = typename std::enable_if<bin_stream::is_extractable<Data>::value>::type>
        r<Data> command_parse_response(command_code cmd, bin_data const &payload, ms timeout = default_timeout);

        /**
         * @brief Selfcheck PN532 ROM memory (UM0701-02 §7.2.1)
         * @ingroup Miscellaneous
         * @param timeout maximum time for getting a response
         * @return True if self-test is successful, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<bool> diagnose_rom(ms timeout = long_timeout);

        /**
         * @brief Self-check PN532 RAM memory (UM0701-02 §7.2.1)
         * @ingroup Miscellaneous
         * @param timeout maximum time for getting a response
         * @return True if self-test is successful, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<bool> diagnose_ram(ms timeout = long_timeout);

        /**
         * @brief Check if card is still inside the field (UM0701-02 §7.2.1)
         * @ingroup Miscellaneous
         * @param timeout maximum time for getting a response
         * @return True if card still present inside the field, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<bool> diagnose_attention_req_or_card_presence(ms timeout = long_timeout);

        /**
         * @brief Check comunication channel by sending random data, and read it back (UM0701-02 §7.2.1)
         * @ingroup Miscellaneous
         * @param timeout maximum time for getting a response
         * @return True if data ecoes without error, False otherwise; or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<bool> diagnose_comm_line(ms timeout = long_timeout);

        /**
         * @brief Sends FeliCa polling comand and count fails attempt (UM0701-02 §7.2.1)
         * @ingroup Miscellaneous
         * @param slow poll target at 212Kbps
         * @param fast poll target at 424Kbps
         * @param timeout maximum time for getting a response
         * @return Number of fails (<128) at 212 kbps, number of fails (<128) as 424 kbps, command_code result.
         */
        r<unsigned, unsigned> diagnose_poll_target(bool slow = true, bool fast = true, ms timeout = long_timeout);

        /**
         * @brief Set the PN532 in target mode(simulating a tag), and echo data back to the initiator after a delay (UM0701-02 §7.2.1)
         * @ingroup Miscellaneous
         * @param reply_delay the time after sending back the data back to the initiator
         * @param tx_mode Cfr. CIU_TxMode register (0x6302), §8.6.23.18 PN532/C1 Data sheet
         * @param rx_mode Cfr. CIU_RxMode register (0x6303), §8.6.23.19 PN532/C1 Data sheet
         * @param timeout maximum time for getting a response
         * @return No data, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<> diagnose_echo_back(ms reply_delay, std::uint8_t tx_mode, std::uint8_t rx_mode, ms timeout = long_timeout);

        /**
         * @brief test antenna for open circuits, or shorts (UM0701-02 §7.2.1)
         * @ingroup Miscellaneous
         * @param low_threshold current threshold for low current error
         * @param high_threshold current threshold for high current error
         * @param timeout maximum time for getting a response
         * @return True if self-test is successful, False otherwhise; or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<bool> diagnose_self_antenna(
                low_current_thr low_threshold, high_current_thr high_threshold,
                ms timeout = long_timeout);

        /**
         * @brief Retrive the silicon version and firmware information and support (UM0701-02 §7.2.2)
         * @ingroup Miscellaneous
         * @param timeout maximum time for getting a response
         * @return Silicon version and firmware functionality support, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<firmware_version> get_firmware_version(ms timeout = default_timeout);

        /**
         * @brief Red the general status of the PN532 (last error, bitrate TX/RX, modulation and SAM status) (UM0701-02 §7.2.3)
         * @ingroup Miscellaneous
         * @param timeout maximum time for getting a response
         * @return Tag reader status, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<general_status> get_general_status(ms timeout = default_timeout);

        /**
         * @brief read multiple registers (UM0701-02 §7.2.4)
         * @ingroup Miscellaneous
         * @param addresses Max 131 elements.
         * @return Register values (respecting @p addresses order), or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<std::vector<uint8_t>> read_registers(std::vector<reg_addr> const &addresses, ms timeout = default_timeout);

        /**
         * @brief read a single register (UM0701-02 §7.2.4)
         * @ingroup Miscellaneous
         * @param reg_addr register address
         * @param timeout maximum time for getting a response
         * @return Register value, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        inline r<uint8_t> read_register(reg_addr const &addr, ms timeout = default_timeout);

        /**
         * @brief write multiple registers (UM0701-02 §7.2.5)
         * @ingroup Miscellaneous
         * @param addr_value_pairs Max 87 elements.
         * @param timeout maximum time for getting a response
         * @return No data, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<> write_registers(
                std::vector<std::pair<reg_addr, std::uint8_t>> const &addr_value_pairs,
                ms timeout = default_timeout);

        /**
         * @brief write a single register (UM0701-02 §7.2.5)
         * @ingroup Miscellaneous
         * @param addr register address
         * @param val value to write at @p addr
         * @param timeout maximum time for getting a response
         * @return No data, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        inline r<> write_register(reg_addr const &addr, std::uint8_t val, ms timeout = default_timeout);

        /**
         * @brief Read all GPIOs (UM0701-02 §7.2.6)
         * @ingroup Miscellaneous
         * @param timeout maximum time for getting a response
         * @return gpio status, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<gpio_status> read_gpio(ms timeout = default_timeout);

        /**
         * @brief Write on GPIOs (UM0701-02 §7.2.7)
         * @ingroup Miscellaneous
         * @param status GPIOs values to write
         * @param write_p3 flag for masking the P3 GPIO bank (true=write)
         * @param write_p7 flag for masking the P7 GPIO bank (true=write)
         * @param timeout maximum time for getting a response
         * @return No data, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<>
        write_gpio(gpio_status const &status, bool write_p3 = true, bool write_p7 = true, ms timeout = default_timeout);

        /**
         * @brief write on a single GPIO (read_gpio + write_gpio)
         * @ingroup Miscellaneous
         * @param loc GPIO BANK (e.g. P35 -> @ref pn532::gpio_loc::p3)
         * @param pin_idx pin number (e.g. P35 -> 5)
         * @param value the value for the GPIO pin
         * @param timeout maximum time for getting a response
         * @return No data, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<> set_gpio_pin(gpio_loc loc, std::uint8_t pin_idx, bool value, ms timeout = default_timeout);

        /**
         * @brief Set the UART/HSU baudrate (UM0701-02 §7.2.8)
         * @note This command is allowed only for HSU comunication.
         *       After 200uS from the ACK, commands with the new baudrate can be sent.
         * @ingroup Miscellaneous
         * @param br new baudrate for successive commands
         * @param timeout maximum time for getting a response
         * @return No data, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<> set_serial_baud_rate(serial_baudrate br, ms timeout = default_timeout);

        /**
         * @brief Configure the SAM data path (UM0701-02 §7.2.10)
         * @ingroup Miscellaneous
         * @param mode configure how the SAM shall be used
         * @param sam_timeout in virtual card mode only, defines the timeout for transactions
         * @param controller_drives_irq specifies if the PN532 shall use the P70 pin for IRQ
         * @param timeout maximum time for getting a response
         * @return No data, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<> sam_configuration(
                sam_mode mode, ms sam_timeout, bool controller_drives_irq = true,
                ms timeout = default_timeout);
        /**
         * @brief Switch on, or off the RF field (UM0701-02 §7.3.1)
         * @ingroup RF
         * @param auto_rfca enable automatic rf field detection
         * @param rf_on switch ON or OFF the RF field
         * @param timeout maximum time for getting a response
         * @return No data, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<> rf_configuration_field(bool auto_rfca, bool rf_on, ms timeout = default_timeout);

        /**
         * @brief Set timeout for ATR_RES and non-DEP communications (UM0701-02 §7.3.1)
         * @ingroup RF
         * @todo remove rfu byte, becouse it is constant (ReserveForFutureUse)
         * @param atr_res_timeout set timeout for ATR request (use when pn532 is the Initiator)
         * @param retry_timeout set timeout for InCommunicateThru @ref nfc::initiator_communicate_through
         * @param timeout maximum time for getting a response
         * @return No data, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<> rf_configuration_timings(
                std::uint8_t rfu, rf_timeout atr_res_timeout = rf_timeout::ms_102_4,
                rf_timeout retry_timeout = rf_timeout::ms_51_2, ms timeout = default_timeout);

        /**
         * @brief Set maximum retries for comunicating with the target (UM0701-02 §7.3.1)
         * @ingroup RF
         * @param comm_retries number of retries used fr a InCommunicateThru: 0x00 -> no retries, 0xFF -> try indefinitely (or you can use @ref infty)
         * @param timeout maximum time for getting a response
         * @return No data, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<> rf_configuration_retries(infbyte comm_retries = 0, ms timeout = default_timeout);

        /**
         * @brief Set maximum retries for ATR, PSL and passive actions (UM0701-02 §7.3.1)
         * @ingroup RF
         * @param atr_retries
         * @parblock
         * number of sending retries after an ATR_RES:
         * - active mode: 0x00 -> try once, 0xFF -> try indefinitely
         * - passive mode: don't care, pn532 will just try twice
         * @endparblock
         * @param psl_retries number of retries after a PSL_RES or PPS response: 0x00 -> try once, 0xFF -> try indefinitely (or you can use @ref infty)
         * @param passive_activation_retries set timeout for InCommunicateThru @ref nfc::initiator_communicate_through
         * @param timeout maximum time for getting a response
         * @return No data, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<> rf_configuration_retries(
                infbyte atr_retries, infbyte psl_retries,
                infbyte passive_activation_retries = infty,
                ms timeout = default_timeout);

        /**
         * @brief Set RF analog parameters for 106kbps type A tags (UM0701-02 §7.3.1)
         * @ingroup RF
         * @param config struct with all the analog configuration
         * @param timeout maximum time for getting a response
         * @return No data, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<> rf_configuration_analog_106kbps_typea(ciu_reg_106kbps_typea const &config, ms timeout = default_timeout);

        /**
         * @brief Set RF analog parameters for 212kbps and 424kbps tags (UM0701-02 §7.3.1)
         * @ingroup RF
         * @param config struct with all the analog configuration
         * @param timeout maximum time for getting a response
         * @return No data, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<> rf_configuration_analog_212_424kbps(ciu_reg_212_424kbps const &config, ms timeout = default_timeout);

        /**
         * @brief Set RF analog parameters for type B tags (UM0701-02 §7.3.1)
         * @ingroup RF
         * @param config struct with all the analog configuration
         * @param timeout maximum time for getting a response
         * @return No data, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<> rf_configuration_analog_typeb(ciu_reg_typeb const &config, ms timeout = default_timeout);

        /**
         * @brief Set RF analog parameters for 212kbps,424kbps and 848kbps tags comunicating with the ISO/IEC14443-4 protocol (UM0701-02 §7.3.1)
         * @ingroup RF
         * @param config struct with all the analog configuration
         * @param timeout maximum time for getting a response
         * @return No data, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<>
        rf_configuration_analog_iso_iec_14443_4(ciu_reg_iso_iec_14443_4 const &config, ms timeout = default_timeout);

        /**
         * @brief Exchange data with the tag (UM0701-02 §7.3.8)
         * @ingroup Initiator
         * @param target_logical_index index the PN532 has given to the tag,
         *  can be retrived with initiator_list_passive_* commands or via @ref initiator_auto_poll
         * @param data Any object that can be injected into a @ref bin_data object. If the total payload exceeds 262
         *  bytes, multiple commands will be issued.
         * @param timeout maximum time for getting a response
         * @return @ref rf_status and @ref bin_data, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        template <class T, class = typename std::enable_if<not std::is_same<bin_data, typename std::remove_const<typename std::remove_reference<T>::type>::type>::value>::type>
        r<rf_status, bin_data>
        initiator_data_exchange(std::uint8_t target_logical_index, T &&data, ms timeout = default_timeout);

        /**
         * @brief Exchange data with the tag (UM0701-02 §7.3.8)
         * @ingroup Initiator
         * @param target_logical_index index the PN532 has given to the tag,
         *  can be retrived with initiator_list_passive_* commands or via @ref initiator_auto_poll
         * @param data If the total payload exceeds 262 bytes, multiple commands will be issued.
         * @param timeout maximum time for getting a response
         * @return @ref rf_status and @ref bin_data, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<rf_status, bin_data>
        initiator_data_exchange(std::uint8_t target_logical_index, bin_data const &data, ms timeout = default_timeout);

        /**
         * @brief Select the tag, next commands will effect the selected tag (UM0701-02 §7.3.12)
         * @ingroup Initiator
         * @param target_logical_index index the PN532 has given to the tag,
         *  can be retrived with initiator_list_passive_* commands or via @ref initiator_auto_poll
         * @param timeout maximum time for getting a response
         * @return @ref rf_status, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<rf_status> initiator_select(std::uint8_t target_logical_index, ms timeout = default_timeout);

        /**
         * @brief Deselect the tag, but maintain the information (UM0701-02 §7.3.10)
         * @ingroup Initiator
         * @param target_logical_index index the PN532 has given to the tag,
         *  can be retrived with initiator_list_passive_* commands or via @ref initiator_auto_poll
         * @param timeout maximum time for getting a response
         * @return @ref rf_status, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<rf_status> initiator_deselect(std::uint8_t target_logical_index, ms timeout = default_timeout);

        /**
         * @brief Release the tag, deselect and delete the information (UM0701-02 §7.3.11)
         * @ingroup Initiator
         * @param target_logical_index index the PN532 has given to the tag,
         *  can be retrived with initiator_list_passive_* commands or via @ref initiator_auto_poll
         * @param timeout maximum time for getting a response
         * @return @ref rf_status, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<rf_status> initiator_release(std::uint8_t target_logical_index, ms timeout = default_timeout);

        /**
         * @brief change baudrate of a TPE or ISO/IEC14443-4 target (UM0701-02 §7.3.7)
         * @ingroup Initiator
         * @param target_logical_index index the PN532 has given to the tag,
         *  can be retrived with initiator_list_passive_* commands or via @ref initiator_auto_poll
         * @param in_to_trg baudrate for comunications from the initiator(PN532) to the target(tag)
         * @param trg_to_in baudrate for comunications from the target(tag) to the initiator(PN532)
         * @param timeout maximum time for getting a response
         * @return @ref rf_status, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<rf_status> initiator_psl(
                std::uint8_t target_logical_index, baudrate in_to_trg, baudrate trg_to_in,
                ms timeout = default_timeout);

        /**
         * @brief list all TypeA tags in range (at 106kbps baudrate) (UM0701-02 §7.3.5)
         * @ingroup Initiator
         * @param max_targets max number of target to list and initialize
         * @param timeout maximum time for getting a response
         * @return a list of targets @ref target_kbps106_typea, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<std::vector<target_kbps106_typea>> initiator_list_passive_kbps106_typea(
                std::uint8_t max_targets = bits::max_num_targets, ms timeout = long_timeout);

        /**
         * @brief check for a specific TypeA tag by UID (at 106kbps baudrate) (UM0701-02 §7.3.5)
         * @ingroup Initiator
         * @param max_targets max number of target to list and initialize
         * @param uid the UID of the tag to initialize
         * @param timeout maximum time for getting a response
         * @return a list of targets @ref target_kbps106_typea, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<std::vector<target_kbps106_typea>> initiator_list_passive_kbps106_typea(
                uid_cascade_l1 uid, std::uint8_t max_targets = 1, ms timeout = long_timeout);

        /**
         * @copydoc initiator_list_passive_kbps106_typea(uid_cascade_l1,std::uint8_t,ms)
         */
        r<std::vector<target_kbps106_typea>> initiator_list_passive_kbps106_typea(
                uid_cascade_l2 uid, std::uint8_t max_targets = 1, ms timeout = long_timeout);

        /**
         * @copydoc initiator_list_passive_kbps106_typea(uid_cascade_l1,std::uint8_t,ms)
         */
        r<std::vector<target_kbps106_typea>> initiator_list_passive_kbps106_typea(
                uid_cascade_l3 uid, std::uint8_t max_targets = 1, ms timeout = long_timeout);

        /**
         * @brief list all TypeB tags in range (at 106kbps baudrate) (UM0701-02 §7.3.5)
         * @ingroup Initiator
         * @param application_family_id the application family identifier (AFI) to pre-select before ATQB
         * @param method tipe of ISO/IEC14443-3B polling, options are @ref bits::polling_method::timeslot and @ref bits::polling_method::probabilistic
         * @param max_targets max number of target to list and initialize
         * @param timeout maximum time for getting a response
         * @return a list of targets @ref target_kbps106_typeb, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<std::vector<target_kbps106_typeb>> initiator_list_passive_kbps106_typeb(
                std::uint8_t application_family_id, polling_method method = polling_method::timeslot,
                std::uint8_t max_targets = bits::max_num_targets, ms timeout = long_timeout);

        /**
         * @brief list all Felica tags in range (at 212kbps baudrate) (UM0701-02 §7.3.5)
         * @ingroup Initiator
         * @param payload the payload to send to the tags (structure defined in §11.2.2.5 of @todo find doc)
         * @param max_targets max number of target to list and initialize
         * @param timeout maximum time for getting a response
         * @return a list of targets @ref target_kbps212_felica, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<std::vector<target_kbps212_felica>> initiator_list_passive_kbps212_felica(
                std::array<std::uint8_t, 5> const &payload, std::uint8_t max_targets = bits::max_num_targets,
                ms timeout = long_timeout);

        /**
         * @brief list all Felica tags in range (at 424kbps baudrate) (UM0701-02 §7.3.5)
         * @ingroup Initiator
         * @param payload the payload to send to the tags (structure defined in §11.2.2.5 of @todo find doc)
         * @param max_targets max number of target to list and initialize
         * @param timeout maximum time for getting a response
         * @return a list of targets @ref target_kbps424_felica, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<std::vector<target_kbps424_felica>> initiator_list_passive_kbps424_felica(
                std::array<std::uint8_t, 5> const &payload, std::uint8_t max_targets = bits::max_num_targets,
                ms timeout = long_timeout);

        /**
         * @brief list all Innovision Jewel tags in range (at 106kbps baudrate) (UM0701-02 §7.3.5)
         * @ingroup Initiator
         * @param timeout maximum time for getting a response
         * @return a list of targets @ref target_kbps106_jewel_tag, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<std::vector<target_kbps106_jewel_tag>> initiator_list_passive_kbps106_jewel_tag(
                ms timeout = long_timeout);

        /**
         * @brief launch an activation request of the target (UM0701-02 §7.3.6)
         * @ingroup Initiator
         * @param target_logical_index index the PN532 has given to the tag,
         *  can be retrived with initiator_list_passive_* commands or via @ref initiator_auto_poll
         * @param timeout maximum time for getting a response
         * @return @ref rf_status and @ref atr_res_info, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<rf_status, atr_res_info>
        initiator_activate_target(std::uint8_t target_logical_index, ms timeout = default_timeout);

        /**
         * @brief launch an activation request of the target (UM0701-02 §7.3.6)
         * @ingroup Initiator
         * @param target_logical_index index the PN532 has given to the tag,
         *  can be retrived with initiator_list_passive_* commands or via @ref initiator_auto_poll
         * @param nfcid_3t the NFCID3 used for the ATR_REQ
         * @param timeout maximum time for getting a response
         * @return @ref rf_status and @ref atr_res_info, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<rf_status, atr_res_info> initiator_activate_target(
                std::uint8_t target_logical_index,
                std::array<std::uint8_t, 10> const &nfcid_3t,
                ms timeout = default_timeout);

        /**
         * @brief launch an activation request of the target (UM0701-02 §7.3.6)
         * @ingroup Initiator
         * @param target_logical_index index the PN532 has given to the tag,
         *  can be retrived with initiator_list_passive_* commands or via @ref initiator_auto_poll
         * @param general_info Max 48 bytes.
         * @param timeout maximum time for getting a response
         * @return @ref rf_status and @ref atr_res_info, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<rf_status, atr_res_info> initiator_activate_target(
                std::uint8_t target_logical_index,
                std::vector<std::uint8_t> const &general_info,
                ms timeout = default_timeout);

        /**
         * @brief launch an activation request of the target (UM0701-02 §7.3.6)
         * @ingroup Initiator
         * @param target_logical_index index the PN532 has given to the tag,
         *  can be retrived with initiator_list_passive_* commands or via @ref initiator_auto_poll
         * @param nfcid_3t the NFCID3 used for the ATR_REQ
         * @param general_info Max 48 bytes.
         * @param timeout maximum time for getting a response
         * @return @ref rf_status and @ref atr_res_info, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<rf_status, atr_res_info> initiator_activate_target(
                std::uint8_t target_logical_index,
                std::array<std::uint8_t, 10> const &nfcid_3t,
                std::vector<std::uint8_t> const &general_info,
                ms timeout = default_timeout);

        /**
         * @brief check specified tags in range, and automatically initialize them (UM0701-02 §7.3.13)
         * @note @p timeout >= @p types_to_poll.size() * @p polls_per_type * @p period
         * @ingroup Initiator
         * @param types_to_poll Minimum 1, maximum 15 elements
         * @param polls_per_type poll attempts per each tag type (0x01-0xFE, 0xFF -> indefinite)
         * @param period time between each attempt
         * @param timeout maximum time for getting a response
         * @return list of targets @ref any_target, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<std::vector<any_target>> initiator_auto_poll(
                std::vector<target_type> const &types_to_poll = poll_all_targets,
                infbyte polls_per_type = 3,
                poll_period period = poll_period::ms_150,
                ms timeout = long_timeout);

        /**
         * @brief exchange data with the tag, but directly (no chaining and error handling) (UM0701-02 §7.3.9)
         * @ingroup Initiator
         * @param raw_data Max 264 bytes, data will be truncated. To trasmit more, use @ref initiator_data_exchange.
         * @param timeout maximum time for getting a response
         * @return @ref rf_status and @ref bin_data, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<rf_status, bin_data> initiator_communicate_through(bin_data const &raw_data, ms timeout = default_timeout);

        /**
         * @brief activate the target with active or passive comunication (UM0701-02 §7.3.3)
         * @ingroup Initiator
         * @param speed comunication baudrate
         * @param timeout maximum time for getting a response
         * @return @ref jump_dep_psl, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<jump_dep_psl> initiator_jump_for_dep_active(baudrate speed, ms timeout = default_timeout);

        /**
         * @brief activate the target with active or passive comunication (UM0701-02 §7.3.3)
         * @ingroup Initiator
         * @param speed comunication baudrate
         * @param general_info Max 48 bytes.
         * @param timeout maximum time for getting a response
         * @return @ref jump_dep_psl, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<jump_dep_psl> initiator_jump_for_dep_active(
                baudrate speed, std::vector<std::uint8_t> const &general_info,
                ms timeout = default_timeout);

        /**
         * @brief activate the target with active or passive comunication (UM0701-02 §7.3.3)
         * @ingroup Initiator
         * @param speed comunication baudrate
         * @param nfcid_3t the NFCID3 used for the ATR_REQ
         * @param timeout maximum time for getting a response
         * @return @ref jump_dep_psl, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<jump_dep_psl> initiator_jump_for_dep_active(
                baudrate speed, std::array<std::uint8_t, 10> const &nfcid_3t,
                ms timeout = default_timeout);

        /**
         * @brief activate the target with active or passive comunication (UM0701-02 §7.3.3)
         * @ingroup Initiator
         * @param speed comunication baudrate
         * @param nfcid_3t the NFCID3 used for the ATR_REQ
         * @param general_info Max 48 bytes.
         * @param timeout maximum time for getting a response
         * @return @ref jump_dep_psl, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<jump_dep_psl> initiator_jump_for_dep_active(
                baudrate speed, std::array<std::uint8_t, 10> const &nfcid_3t,
                std::vector<std::uint8_t> const &general_info,
                ms timeout = default_timeout);

        /**
         * @brief activate the target with active or passive comunication (UM0701-02 §7.3.3)
         * @ingroup Initiator
         * @param timeout maximum time for getting a response
         * @return @ref jump_dep_psl, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<jump_dep_psl> initiator_jump_for_dep_passive_106kbps(ms timeout = default_timeout);

        /**
         * @brief activate the target with active or passive comunication (UM0701-02 §7.3.3)
         * @ingroup Initiator
         * @param general_info Max 48 bytes.
         * @param timeout maximum time for getting a response
         * @return @ref jump_dep_psl, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<jump_dep_psl> initiator_jump_for_dep_passive_106kbps(
                std::vector<std::uint8_t> const &general_info,
                ms timeout = default_timeout);

        /**
         * @brief activate the target with active or passive comunication (UM0701-02 §7.3.3)
         * @ingroup Initiator
         * @param nfcid_3t the NFCID3 used for the ATR_REQ
         * @param timeout maximum time for getting a response
         * @return @ref jump_dep_psl, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<jump_dep_psl> initiator_jump_for_dep_passive_106kbps(
                std::array<std::uint8_t, 10> const &nfcid_3t,
                ms timeout = default_timeout);

        /**
         * @brief activate the target with active or passive comunication (UM0701-02 §7.3.3)
         * @ingroup Initiator
         * @param nfcid_3t the NFCID3 used for the ATR_REQ
         * @param general_info Max 48 bytes.
         * @param timeout maximum time for getting a response
         * @return @ref jump_dep_psl, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<jump_dep_psl> initiator_jump_for_dep_passive_106kbps(
                std::array<std::uint8_t, 10> const &nfcid_3t,
                std::vector<std::uint8_t> const &general_info,
                ms timeout = default_timeout);

        /**
         * @brief activate the target with active or passive comunication (UM0701-02 §7.3.3)
         * @ingroup Initiator
         * @param target_id number attributed to the activated target
         * @param timeout maximum time for getting a response
         * @return @ref jump_dep_psl, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<jump_dep_psl> initiator_jump_for_dep_passive_106kbps(
                std::array<std::uint8_t, 4> const &target_id,
                ms timeout = default_timeout);

        /**
         * @brief activate the target with active or passive comunication (UM0701-02 §7.3.3)
         * @ingroup Initiator
         * @param target_id number attributed to the activated target
         * @param general_info Max 48 bytes.
         * @param timeout maximum time for getting a response
         * @return @ref jump_dep_psl, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<jump_dep_psl> initiator_jump_for_dep_passive_106kbps(
                std::array<std::uint8_t, 4> const &target_id,
                std::vector<std::uint8_t> const &general_info,
                ms timeout = default_timeout);

        /**
         * @brief activate the target with active or passive comunication (UM0701-02 §7.3.3)
         * @ingroup Initiator
         * @param target_id number attributed to the activated target
         * @param nfcid_3t the NFCID3 used for the ATR_REQ
         * @param timeout maximum time for getting a response
         * @return @ref jump_dep_psl, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<jump_dep_psl> initiator_jump_for_dep_passive_106kbps(
                std::array<std::uint8_t, 4> const &target_id,
                std::array<std::uint8_t, 10> const &nfcid_3t,
                ms timeout = default_timeout);

        /**
         * @brief activate the target with active or passive comunication (UM0701-02 §7.3.3)
         * @ingroup Initiator
         * @param target_id number attributed to the activated target
         * @param nfcid_3t the NFCID3 used for the ATR_REQ
         * @param general_info Max 48 bytes.
         * @param timeout maximum time for getting a response
         * @return @ref jump_dep_psl, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<jump_dep_psl> initiator_jump_for_dep_passive_106kbps(
                std::array<std::uint8_t, 4> const &target_id,
                std::array<std::uint8_t, 10> const &nfcid_3t,
                std::vector<std::uint8_t> const &general_info,
                ms timeout = default_timeout);

        /**
         * @brief activate the target with active or passive comunication (UM0701-02 §7.3.3)
         * @ingroup Initiator
         * @param target_id number attributed to the activated target
         * @param timeout maximum time for getting a response
         * @return @ref jump_dep_psl, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<jump_dep_psl> initiator_jump_for_dep_passive_212kbps(
                std::array<std::uint8_t, 5> const &target_id,
                ms timeout = default_timeout);

        /**
         * @brief activate the target with active or passive comunication (UM0701-02 §7.3.3)
         * @ingroup Initiator
         * @param target_id number attributed to the activated target
         * @param general_info Max 48 bytes.
         * @param timeout maximum time for getting a response
         * @return @ref jump_dep_psl, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<jump_dep_psl> initiator_jump_for_dep_passive_212kbps(
                std::array<std::uint8_t, 5> const &target_id,
                std::vector<std::uint8_t> const &general_info,
                ms timeout = default_timeout);

        /**
         * @brief activate the target with active or passive comunication (UM0701-02 §7.3.3)
         * @ingroup Initiator
         * @param target_id number attributed to the activated target
         * @param timeout maximum time for getting a response
         * @return @ref jump_dep_psl, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<jump_dep_psl> initiator_jump_for_dep_passive_424kbps(
                std::array<std::uint8_t, 5> const &target_id,
                ms timeout = default_timeout);

        /**
         * @brief activate the target with active or passive comunication (UM0701-02 §7.3.3)
         * @ingroup Initiator
         * @param target_id number attributed to the activated target
         * @param general_info Max 48 bytes.
         * @param timeout maximum time for getting a response
         * @return @ref jump_dep_psl, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<jump_dep_psl> initiator_jump_for_dep_passive_424kbps(
                std::array<std::uint8_t, 5> const &target_id,
                std::vector<std::uint8_t> const &general_info,
                ms timeout = default_timeout);

        /**
         * @brief activate the target with active or passive comunication (UM0701-02 §7.3.3)
         * @ingroup Initiator
         * @param speed comunication baudrate
         * @param timeout maximum time for getting a response
         * @return @ref jump_dep_psl, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<jump_dep_psl> initiator_jump_for_psl_active(baudrate speed, ms timeout = default_timeout);

        /**
         * @brief activate the target with active or passive comunication (UM0701-02 §7.3.3)
         * @ingroup Initiator
         * @param speed comunication baudrate
         * @param general_info Max 48 bytes.
         * @param timeout maximum time for getting a response
         * @return @ref jump_dep_psl, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<jump_dep_psl> initiator_jump_for_psl_active(
                baudrate speed, std::vector<std::uint8_t> const &general_info,
                ms timeout = default_timeout);

        /**
         * @brief activate the target with active or passive comunication (UM0701-02 §7.3.3)
         * @ingroup Initiator
         * @param speed comunication baudrate
         * @param nfcid_3t the NFCID3 used for the ATR_REQ
         * @param timeout maximum time for getting a response
         * @return @ref jump_dep_psl, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<jump_dep_psl> initiator_jump_for_psl_active(
                baudrate speed, std::array<std::uint8_t, 10> const &nfcid_3t,
                ms timeout = default_timeout);

        /**
         * @brief activate the target with active or passive comunication (UM0701-02 §7.3.3)
         * @ingroup Initiator
         * @param speed comunication baudrate
         * @param nfcid_3t the NFCID3 used for the ATR_REQ
         * @param general_info Max 48 bytes.
         * @param timeout maximum time for getting a response
         * @return @ref jump_dep_psl, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<jump_dep_psl> initiator_jump_for_psl_active(
                baudrate speed, std::array<std::uint8_t, 10> const &nfcid_3t,
                std::vector<std::uint8_t> const &general_info,
                ms timeout = default_timeout);

        /**
         * @brief activate the target with active or passive comunication (UM0701-02 §7.3.3)
         * @ingroup Initiator
         * @param timeout maximum time for getting a response
         * @return @ref jump_dep_psl, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<jump_dep_psl> initiator_jump_for_psl_passive_106kbps(ms timeout = default_timeout);

        /**
         * @brief activate the target with active or passive comunication (UM0701-02 §7.3.3)
         * @ingroup Initiator
         * @param general_info Max 48 bytes.
         * @param timeout maximum time for getting a response
         * @return @ref jump_dep_psl, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<jump_dep_psl> initiator_jump_for_psl_passive_106kbps(
                std::vector<std::uint8_t> const &general_info,
                ms timeout = default_timeout);

        /**
         * @brief activate the target with active or passive comunication (UM0701-02 §7.3.3)
         * @ingroup Initiator
         * @param nfcid_3t the NFCID3 used for the ATR_REQ
         * @param timeout maximum time for getting a response
         * @return @ref jump_dep_psl, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<jump_dep_psl> initiator_jump_for_psl_passive_106kbps(
                std::array<std::uint8_t, 10> const &nfcid_3t,
                ms timeout = default_timeout);

        /**
         * @brief activate the target with active or passive comunication (UM0701-02 §7.3.3)
         * @ingroup Initiator
         * @param nfcid_3t the NFCID3 used for the ATR_REQ
         * @param general_info Max 48 bytes.
         * @param timeout maximum time for getting a response
         * @return @ref jump_dep_psl, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<jump_dep_psl> initiator_jump_for_psl_passive_106kbps(
                std::array<std::uint8_t, 10> const &nfcid_3t,
                std::vector<std::uint8_t> const &general_info,
                ms timeout = default_timeout);

        /**
         * @brief activate the target with active or passive comunication (UM0701-02 §7.3.3)
         * @ingroup Initiator
         * @param target_id number attributed to the activated target
         * @param timeout maximum time for getting a response
         * @return @ref jump_dep_psl, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<jump_dep_psl> initiator_jump_for_psl_passive_106kbps(
                std::array<std::uint8_t, 4> const &target_id,
                ms timeout = default_timeout);

        /**
         * @brief activate the target with active or passive comunication (UM0701-02 §7.3.3)
         * @ingroup Initiator
         * @param target_id number attributed to the activated target
         * @param general_info Max 48 bytes.
         * @param timeout maximum time for getting a response
         * @return @ref jump_dep_psl, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<jump_dep_psl> initiator_jump_for_psl_passive_106kbps(
                std::array<std::uint8_t, 4> const &target_id,
                std::vector<std::uint8_t> const &general_info,
                ms timeout = default_timeout);

        /**
         * @brief activate the target with active or passive comunication (UM0701-02 §7.3.3)
         * @ingroup Initiator
         * @param target_id number attributed to the activated target
         * @param nfcid_3t the NFCID3 used for the ATR_REQ
         * @param timeout maximum time for getting a response
         * @return @ref jump_dep_psl, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<jump_dep_psl> initiator_jump_for_psl_passive_106kbps(
                std::array<std::uint8_t, 4> const &target_id,
                std::array<std::uint8_t, 10> const &nfcid_3t,
                ms timeout = default_timeout);

        /**
         * @brief activate the target with active or passive comunication (UM0701-02 §7.3.3)
         * @ingroup Initiator
         * @param target_id number attributed to the activated target
         * @param nfcid_3t the NFCID3 used for the ATR_REQ
         * @param general_info Max 48 bytes.
         * @param timeout maximum time for getting a response
         * @return @ref jump_dep_psl, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<jump_dep_psl> initiator_jump_for_psl_passive_106kbps(
                std::array<std::uint8_t, 4> const &target_id,
                std::array<std::uint8_t, 10> const &nfcid_3t,
                std::vector<std::uint8_t> const &general_info,
                ms timeout = default_timeout);

        /**
         * @brief activate the target with active or passive comunication (UM0701-02 §7.3.3)
         * @ingroup Initiator
         * @param target_id number attributed to the activated target
         * @param timeout maximum time for getting a response
         * @return @ref jump_dep_psl, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<jump_dep_psl> initiator_jump_for_psl_passive_212kbps(
                std::array<std::uint8_t, 5> const &target_id,
                ms timeout = default_timeout);

        /**
         * @brief activate the target with active or passive comunication (UM0701-02 §7.3.3)
         * @ingroup Initiator
         * @param target_id number attributed to the activated target
         * @param general_info Max 48 bytes.
         * @param timeout maximum time for getting a response
         * @return @ref jump_dep_psl, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<jump_dep_psl> initiator_jump_for_psl_passive_212kbps(
                std::array<std::uint8_t, 5> const &target_id,
                std::vector<std::uint8_t> const &general_info,
                ms timeout = default_timeout);

        /**
         * @brief activate the target with active or passive comunication (UM0701-02 §7.3.3)
         * @ingroup Initiator
         * @param target_id number attributed to the activated target
         * @param timeout maximum time for getting a response
         * @return @ref jump_dep_psl, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<jump_dep_psl> initiator_jump_for_psl_passive_424kbps(
                std::array<std::uint8_t, 5> const &target_id,
                ms timeout = default_timeout);

        /**
         * @brief activate the target with active or passive comunication (UM0701-02 §7.3.3)
         * @ingroup Initiator
         * @param target_id number attributed to the activated target
         * @param general_info Max 48 bytes.
         * @param timeout maximum time for getting a response
         * @return @ref jump_dep_psl, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<jump_dep_psl> initiator_jump_for_psl_passive_424kbps(
                std::array<std::uint8_t, 5> const &target_id,
                std::vector<std::uint8_t> const &general_info,
                ms timeout = default_timeout);
        /**
         * @return None data, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<> set_parameters(parameters const &parms, ms timeout = default_timeout);

        /**
         * @return @ref rf_status, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<rf_status> power_down(std::vector<wakeup_source> const &wakeup_sources, ms timeout = default_timeout);

        /**
         * @return @ref rf_status, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<rf_status> power_down(
                std::vector<wakeup_source> const &wakeup_sources, bool generate_irq, ms timeout = default_timeout);

        /**
         * @return @ref rf_status, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<> rf_regulation_test(tx_mode mode, ms timeout = default_timeout);

        /**
         * @return @ref status_as_target, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<status_as_target> target_get_target_status(ms timeout = default_timeout);

        /**
         * @brief configure the PN532 as a target (UM0701-02 §7.3.14)
         * @ingroup Target
         * @param nfcid_3t the NFCID3 used for the ATR_REQ
         * @param general_info Max 47 bytes, if exceeding, it will be truncated.
         * @param historical_bytes Max 48 bytes, if exceeding, it will be truncated.
         * @param timeout maximum time for getting a response
         * @return @ref init_as_target_res, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<init_as_target_res> target_init_as_target(
                bool picc_only, bool dep_only, bool passive_only, mifare_params const &mifare,
                felica_params const &felica, std::array<std::uint8_t, 10> const &nfcid_3t,
                std::vector<std::uint8_t> const &general_info = {},
                std::vector<std::uint8_t> const &historical_bytes = {}, ms timeout = default_timeout);

        /**
         * @brief used in combination with @ref target_init_as_target for generating the ATR_RES request (UM0701-02 §7.3.15)
         * @ingroup Target
         * @param general_info Max 47 bytes, if exceeding, it will be truncated.
         * @param timeout maximum time for getting a response
         * @return @ref rf_status, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<rf_status> target_set_general_bytes(
                std::vector<std::uint8_t> const &general_info, ms timeout = default_timeout);

        /**
         * @brief get data sent by the initiator (UM0701-02 §7.3.16)
         * @ingroup Target
         * @param timeout maximum time for getting a response
         * @return @ref rf_status and @ref bin_data, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<rf_status, bin_data> target_get_data(ms timeout = default_timeout);

        /**
         * @brief set data to be sent at the initiator (UM0701-02 §7.3.17)
         * @ingroup Target
         * @param data Max 262 bytes, if exceeding, it will be truncated.
         * @param timeout maximum time for getting a response
         * @return @ref rf_status, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<rf_status> target_set_data(std::vector<std::uint8_t> const &data, ms timeout = default_timeout);

        /**
         * @ingroup Target
         * @param data Max 262 bytes, if exceeding, it will be truncated.
         * @param timeout maximum time for getting a response
         * @return @ref rf_status, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<rf_status> target_set_metadata(std::vector<std::uint8_t> const &data, ms timeout = default_timeout);

        /**
         * @ingroup Target
         * @param timeout maximum time for getting a response
         * @return @ref rf_status, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<rf_status, bin_data> target_get_initiator_command(ms timeout = default_timeout);

        /**
         * @ingroup Target
         * @param data Max 262 bytes, if exceeding, it will be truncated.
         * @param timeout maximum time for getting a response
         * @return @ref rf_status, or one of the following errors:
         *         - @ref error::comm_malformed,
         *         - @ref error::comm_checksum_fail
         *         - @ref error::comm_timeout
         */
        r<rf_status> target_response_to_initiator(std::vector<std::uint8_t> const &data, ms timeout = default_timeout);

    private:
        channel *_channel;

        struct frame_header;
        struct frame_body;

        inline channel &chn() const;

        bool await_frame(ms timeout);

        r<frame_header> read_header(ms timeout);

        r<frame_body> read_response_body(frame_header const &hdr, ms timeout);

        static bin_data get_command_info_frame(command_code cmd, bin_data const &payload);

        static bin_data const &get_ack_frame();

        static bin_data const &get_nack_frame();

        static std::uint8_t get_target(command_code cmd, std::uint8_t target_logical_index, bool expect_more_data);

        template <baudrate_modulation BrMd>
        r<std::vector<bits::target<BrMd>>> initiator_list_passive(
                std::uint8_t max_targets,
                bin_data const &initiator_data, ms timeout);
    };

    const char *to_string(nfc::error e);
}// namespace pn532


namespace pn532 {

    nfc::nfc(channel &chn) : _channel{&chn} {}

    channel &nfc::chn() const { return *_channel; }

    nfc::r<uint8_t> nfc::read_register(reg_addr const &addr, ms timeout) {
        const auto res_cmd = read_registers({addr}, timeout);
        if (res_cmd) {
            return res_cmd->at(0);
        }
        return res_cmd.error();
    }

    nfc::r<> nfc::write_register(reg_addr const &addr, std::uint8_t val, ms timeout) {
        return write_registers({{addr, val}}, timeout);
    }

    template <class Data, class>
    nfc::r<Data> nfc::command_parse_response(command_code cmd, bin_data const &payload, ms timeout) {
        const auto res_cmd = command_response(cmd, payload, timeout);
        if (not res_cmd) {
            return res_cmd.error();
        }
        bin_stream s{*res_cmd};
        Data data{};
        s >> data;
        if (s.bad()) {
            PN532_LOGE("%s: could not parse result from response data.", to_string(cmd));
            return error::comm_malformed;
        }
        return data;
    }

    template <class T, class>
    nfc::r<rf_status, bin_data> nfc::initiator_data_exchange(std::uint8_t target_logical_index, T &&data, ms timeout) {
        const bin_data bd = bin_data::chain(std::forward<T>(data));
        return initiator_data_exchange(target_logical_index, bd, timeout);
    }

}// namespace pn532


#endif//PN532_NFC_HPP
