//
// Created by Pietro Saccardi on 20/12/2020.
//

#ifndef PN532_BITS_HPP
#define PN532_BITS_HPP

#include <array>
#include <cstddef>
#include <mlab/bin_data.hpp>
#include <vector>

/**
 * Structures related to the PN532.
 */
namespace pn532 {

    /**
     * Supported PN532 command codes (UM0701-02 §7).
     */
    enum struct command_code : std::uint8_t {
        diagnose = 0x00,                ///< Run Diagnostic commands (UM0701-02 §7.2.1)
        get_firmware_version = 0x02,    ///< Query for PN532 version and info (UM0701-02 §7.2.2)
        get_general_status = 0x04,      ///< Get PN532 and initialized tag status (UM0701-02 §7.2.3)
        read_register = 0x06,           ///< Read low level registers (UM0701-02 §7.2.4)
        write_register = 0x08,          ///< Write low level registers (UM0701-02 §7.2.5)
        read_gpio = 0x0c,               ///< Get gpio state (UM0701-02 §7.2.6)
        write_gpio = 0x0e,              ///< Write the GPIO status (UM0701-02 §7.2.7)
        set_serial_baudrate = 0x10,     ///< Configure serial communication baudrate (only on HSU mode) (UM0701-02 §7.2.8)
        set_parameters = 0x12,          ///< Set internal configuration parameters (UM0701-02 §7.2.9)
        sam_configuration = 0x14,       ///< Configure the sam data-flow (UM0701-02 §7.2.10)
        power_down = 0x16,              ///< Set the PN532 in deep-sleep (UM0701-02 §7.2.11)
        rf_configuration = 0x32,        ///< Configure RF parameters (UM0701-02 §7.3.1)
        rf_regulation_test = 0x58,      ///< Command usefull when doing EMI test (UM0701-02 §7.3.2)
        in_jump_for_dep = 0x56,         ///< Activate the target and setup for a DEP exchange (UM0701-02 §7.3.3)
        in_jump_for_psl = 0x46,         ///< Activate the target and setup for a PSL or DEP exchange (UM0701-02 §7.3.4)
        in_list_passive_target = 0x4a,  ///< Detect all target in rage (MAX 2) in passive mode (UM0701-02 §7.3.5)
        in_atr = 0x50,                  ///< Activate the target (for passive mode) (UM0701-02 §7.3.6)
        in_psl = 0x4e,                  ///< Change the baudrate of a TPE or ISO14443-4 target (UM0701-02 §7.3.7)
        in_data_exchange = 0x40,        ///< Start a data excange with the selected target (UM0701-02 §7.3.8)
        in_communicate_thru = 0x42,     ///< Start a low level data exchange (UM0701-02 §7.3.9)
        in_deselect = 0x44,             ///< Deselect the target, but keep configuration information in memory (UM0701-02 §7.3.10)
        in_release = 0x52,              ///< Terminate communication with the target, and delete all the memorized information (UM0701-02 §7.3.11)
        in_select = 0x54,               ///< Select the target (UM0701-02 §7.3.12)
        in_autopoll = 0x60,             ///< Poll for sepcified targets in range, and inizialize them (UM0701-02 §7.3.13)
        tg_init_as_target = 0x8c,       ///< Configure the PN532 as a target (UM0701-02 §7.3.14)
        tg_set_general_bytes = 0x92,    ///< Set the general bytes to be sent on request, used in combination with tg_init_as_target command (UM0701-02 §7.3.15)
        tg_get_data = 0x86,             ///< Sends data to the initiator when operating as target (UM0701-02 §7.3.16)
        tg_set_data = 0x8e,             ///< Receives data from the initiator when operating as target (UM0701-02 §7.3.17)
        tg_set_metadata = 0x94,         ///< Used to inform the initiator that the data in a DEP exchange, when operating as a target, cannot be transmitted in a single frame (UM0701-02 §7.3.18)
        tg_get_initiator_command = 0x88,///< Get a data packet from the initiator (UM0701-02 §7.3.19)
        tg_response_to_initiator = 0x90,///< Send a response packet to the initiator (UM0701-02 §7.3.20)
        tg_get_target_status = 0x8a     ///< Read the current state of the PN532 (UM0701-02 §7.3.21)
    };

    /**
     * Low current threshold for antenna diagnostic (UM0701-02 §7.2.1).
     * @see pn532::controller::diagnose_self_antenna
     */
    enum struct low_current_thr : std::uint8_t {
        mA_25 = 0b10 << 4,///< 25 mA
        mA_35 = 0b11 << 4 ///< 35 mA
    };

    /**
     * High current threshold for antenna diagnostic (UM0701-02 §7.2.1).
     * @see pn532::controller::diagnose_self_antenna
     */
    enum struct high_current_thr : std::uint8_t {
        mA_45 = 0b000 << 1, ///< 45 mA
        mA_60 = 0b001 << 1, ///< 60 mA
        mA_75 = 0b010 << 1, ///< 75 mA
        mA_90 = 0b011 << 1, ///< 90 mA
        mA_105 = 0b100 << 1,///< 105 mA
        mA_120 = 0b101 << 1,///< 120 mA
        mA_130 = 0b110 << 1,///< 130 mA
        mA_150 = 0b111 << 1 ///< 150 mA
    };

    /**
     * Baudrate to use to communicate with the host via UART (HSU) (UM0701-02 §7.2.8).
     * @see
     *  - pn532::controller::set_serial_baud_rate
     *  - pn532::esp32::hsu_channel
     */
    enum struct serial_baudrate : std::uint8_t {
        baud9_600 = 0x00,   ///< 9.6 KBaud
        baud19_200 = 0x01,  ///< 19.2 KBaud
        baud38_400 = 0x02,  ///< 38.4 KBaud
        baud57_600 = 0x03,  ///< 57.6 KBaud
        baud115_200 = 0x04, ///< 115.2 KBaud
        baud230_400 = 0x05, ///< 230.4 KBaud
        baud460_800 = 0x06, ///< 460.8 KBaud
        baud921_600 = 0x07, ///< 921.6 KBaud
        baud1_288_000 = 0x08///< 1.288 MBaud
    };

    /**
     * RF regulation test mode (UM0701-02 §7.3.2).
     * @see pn532::controller::rf_regulation_test
     */
    enum struct rf_test_mode : std::uint8_t {
        mifare_106kbps = 0b0000000,///< Mifare framing, 106kbps
        mifare_212kbps = 0b0010000,///< Mifare framing, 212kbps
        mifare_424kbps = 0b0100000,///< Mifare framing, 424kbps
        mifare_848kbps = 0b0110000,///< Mifare framing, 848kbps
        felica_106kbps = 0b0000010,///< FeliCa framing, 106kbps
        felica_212kbps = 0b0010010,///< FeliCa framing, 212kbps
        felica_424kbps = 0b0100010,///< FeliCa framing, 424kbps
        felica_848kbps = 0b0110010 ///< FeliCa framing, 848kbps
    };

    /**
     * RF timing configuration, supported timeout values (UM0701-02 §7.3.1).
     * @see pn532::controller::rf_configuration_timings
     */
    enum struct rf_timeout : std::uint8_t {
        none = 0x00,    ///< No timeout
        us_100 = 0x01,  ///< 0.1 ms
        us_200 = 0x02,  ///< 0.2 ms
        us_400 = 0x03,  ///< 0.4 ms
        us_800 = 0x04,  ///< 0.8 ms
        ms_1_6 = 0x05,  ///< 1.6 ms
        ms_3_2 = 0x06,  ///< 3.2 ms
        ms_6_4 = 0x07,  ///< 6.4 ms
        ms_12_8 = 0x08, ///< 12.8 ms
        ms_25_6 = 0x09, ///< 25.6 ms
        ms_51_2 = 0x0a, ///< 51.2 ms
        ms_102_4 = 0x0b,///< 102.4 ms
        ms_204_8 = 0x0c,///< 204.8 ms
        ms_409_6 = 0x0d,///< 409.6 ms
        ms_819_2 = 0x0e,///< 819.2 ms
        s_1_64 = 0x0f,  ///< 1640.0 ms
        s_3_28 = 0x10   ///< 3280.0 ms
    };

    /**
     * Structures related to the internal registries of the PN532.
     */
    namespace reg {

        /**
         * PN532 registry representing RF analog settings for the baudrate 212/424 kbps (UM0701-02 §7.3.1).
         */
        struct ciu_212_424kbps {
            std::uint8_t rf_cfg = 0x69;
            std::uint8_t gs_n_on = 0xff;
            std::uint8_t cw_gs_p = 0x3f;
            std::uint8_t mod_gs_p = 0x11;
            std::uint8_t demod_own_rf_on = 0x41;
            std::uint8_t rx_threshold = 0x85;
            std::uint8_t demod_own_rf_off = 0x61;
            std::uint8_t gs_n_off = 0x6f;
        };

        /**
         * PN532 registry representing RF analog settings for the baudrate 106 kbps type A (UM0701-02 §7.3.1).
         */
        struct ciu_106kbps_typea {
            std::uint8_t rf_cfg = 0x59;
            std::uint8_t gs_n_on = 0xf4;
            std::uint8_t cw_gs_p = 0x3f;
            std::uint8_t mod_gs_p = 0x11;
            std::uint8_t demod_own_rf_on = 0x4d;
            std::uint8_t rx_threshold = 0x85;
            std::uint8_t demod_own_rf_off = 0x61;
            std::uint8_t gs_n_off = 0x6f;
            std::uint8_t mod_width = 0x26;
            std::uint8_t mif_nfc = 0x62;
            std::uint8_t tx_bit_phase = 0x87;
        };

        /**
         * PN532 registry representing RF analog settings for the type B (UM0701-02 §7.3.1).
         */
        struct ciu_typeb {
            std::uint8_t gs_n_on = 0xff;
            std::uint8_t mod_gs_p = 0x17;
            std::uint8_t rx_threshold = 0x85;
        };

        /**
         * PN532 tuple representing RF analog settings for one of the baudrates 212/424/848 kbps with ISO/IEC14443-4 protocol (UM0701-02 §7.3.1).
         */
        struct ciu_iso_iec_14443_4_at_baudrate {
            std::uint8_t rx_threshold;
            std::uint8_t mod_width;
            std::uint8_t mif_nfc;
        };

        /**
         * PN532 registry representing RF analog settings for all baudrates 212/424/848 kbps with ISO/IEC14443-4 protocol (UM0701-02 §7.3.1).
         */
        struct ciu_iso_iec_14443_4 {
            ciu_iso_iec_14443_4_at_baudrate kbps212{0x85, 0x15, 0x8a};
            ciu_iso_iec_14443_4_at_baudrate kbps424{0x85, 0x08, 0xb2};
            ciu_iso_iec_14443_4_at_baudrate kbps848{0x85, 0x01, 0xda};
        };

        /**
         * SFR register types (UM0701-02 §7.2.4).
         * @see
         *  - pn532::controller::read_register
         *  - pn532::controller::write_register
         *  - addr
         */
        enum struct sfr_register : std::uint8_t {
            pcon = 0x87,
            rwl = 0x9a,
            twl = 0x9b,
            fifofs = 0x9c,
            fifoff = 0x9d,
            sff = 0x9e,
            fit = 0x9f,
            fiten = 0xa1,
            fdata = 0xa2,
            fsize = 0xa3,
            ie0 = 0xa8,
            spicontrol = 0xa9,
            spistatus = 0xaa,
            hsu_sta = 0xab,
            hsu_ctr = 0xac,
            hsu_pre = 0xad,
            hsu_cnt = 0xae,
            p3 = 0xb0,
            ip0 = 0xb8,
            ciu_command = 0xd1,
            ien1 = 0xe8,
            p7cfga = 0xf4,
            p7cfgb = 0xf5,
            p7 = 0xf7,
            ip1 = 0xf8,
            p3cfga = 0xfc,
            p3cfgb = 0xfd
        };

        /**
         * @brief Address of one of the @ref sfr_register.
         */
        struct addr : public std::array<std::uint8_t, 2> {
            inline addr(sfr_register sfr_reg);
            explicit inline addr(std::uint16_t xram_mmap_reg);
        };
    }// namespace reg

    /**
     * Baudrate to select when performing a jump for DEP or PSL as an initiator.
     * @see
     *  - pn532::controller::initiator_jump_for_dep_active
     *  - pn532::controller::initiator_jump_for_psl_active
     *  - baudrate_modulation
     *  - baudrate_of
     *  - target_type
     */
    enum struct baudrate : std::uint8_t {
        kbps106 = 0x0,///< 106 kbps
        kbps212 = 0x1,///< 212 kbps
        kbps424 = 0x2 ///< 424 kbps
    };

    /**
     * Supported NFC modulations.
     * @see
     *  - pn532::target_status
     *  - baudrate_modulation
     *  - modulation_of
     *  - target_type
     */
    enum struct modulation : std::uint8_t {
        mifare_iso_iec_14443_3_type_ab_iso_iec_18092_passive_kbps106 = 0x00, /**< All passive 106 kbps modulations.
                                                                              * This includes Mifare cards, ISO/IEC 14443.3 Type A and Type B, as well as ISO/IEC 18092.
                                                                              */
        felica_iso_iec_18092_kbps212_424 = 0x10,                             ///< Passive FeliCa modulation, 212 or 424 kbps, compliant to ISO/IEC 18092
        iso_iec_18092_active = 0x01,                                         ///< Active ISO/IEC 18092 modulation.
        innovision_jewel_tag = 0x02                                          ///< Innovision Jewel tag modulation.
    };

    /**
     * @brief Operating mode of the (optional) companion SAM chip (UM0701-02 §7.2.10).
     * @note Normally PN532 do not come with a SAM chip, it seems that even the list of supported SAMs is under NDA,
     *  therefore unless you have actively signed an NDA, selected a chip and connected it to your PN532, the mode
     *  you want to use is @ref sam_mode::normal.
     * @see pn532::controller::sam_configuration
     */
    enum struct sam_mode : std::uint8_t {
        normal = 0x01,      ///< Normal mode, no SAM chip.
        virtual_card = 0x02,///< PN532+SAM is seen as a unique virtual card from the outside world.
        wired_card = 0x03,  ///< The host can access the SAM chip through the PN532.
        dual_card = 0x04    ///< The host can communicate with both the PN532 and the SAM chip, distinctly.
    };

    /**
     * @brief When in standby mode, specifies which source can wake the PN532 up (UM0701-02 §7.2.11).
     * @see pn532::controller::power_down
     */
    enum struct wakeup_source : std::uint8_t {
        i2c = 1 << 7, ///< Wake up through I2C channel (UM0701-02 §7.2.11).
        gpio = 1 << 6,///< Wake up when any GPIO changes state (UM0701-02 §3.1.3.9)
        spi = 1 << 5, ///< Wake up through SPI channel (UM0701-02 §7.2.11).
        hsu = 1 << 4, ///< Wake up through HSU channel (UM0701-02 §7.2.11).
        rf = 1 << 3,  ///< Wake up when the RF reaches a certain level (UM0701-02 §7.2.11).
        int1 = 1 << 1,///< INT1 GPIO (which is however used to control the communication mode).
        int0 = 1 << 0 ///< INT0 GPIO (which is however used to control the communication mode).
    };

    /**
     * Activation status of the PN532, as a target (UM0701-02 §7.3.21).
     * @see pn532::controller::target_get_target_status
     */
    enum struct nfcip1_picc_status : std::uint8_t {
        nfcip1_idle = 0x00,      ///< The PN532 (acting as NFCIP-1 target) waits for an initiator or has been released by its initiator.
        nfcip1_activated = 0x01, ///< The PN532 is activated as NFCIP-1 target.
        nfcip1_deselected = 0x02,///< The PN532 (acting as NFCIP-1 target) has been de-selected by its initiator.
        picc_released = 0x80,    ///< The PN532 (acting as ISO/IEC14443-4 PICC) has been released by its PCD (no more RF field is detected).
        picc_activated = 0x81,   ///< The PN532 is activated as ISO/IEC14443-4 PICC.
        picc_deselected = 0x82   ///< The PN532 (acting as ISO/IEC14443-4 PICC) has been de-selected by its PDC.
    };

    /**
     * PN532 error codes (UM0701-02 §7.1).
     * @note This differs from @ref channel_error, which is the main set of error codes produced by
     *  PN532 commands. In fact, these error codes can only be obtained by querying the @ref general_status or @ref rf_status.
     * @see channel_error
     */
    enum struct internal_error_code : std::uint8_t {
        none = 0x00,                            ///< No error.
        timeout = 0x01,                         ///< Time out, the target has not answered.
        crc_error = 0x02,                       ///< A CRC error has been detected by the CIU.
        parity_error = 0x3,                     ///< A parity error has been detected by the CIU.
        erroneous_bit_count = 0x04,             ///< During an anticollision operation, an erroneous bit count has been detected.
        framing_error = 0x05,                   ///< Framing error during Mifare operation.
        bit_collision = 0x06,                   ///< An abnormal bit-collision has been detected during bit wise anticollision at 106 kbsp.
        buffer_size_insufficient = 0x07,        ///< Communication buffer size insufficient.
        rf_buffer_overflow = 0x09,              ///< RF buffer overflow has been detected by the CIU.
        counterpart_rf_off = 0x0a,              ///< In active communication mode, the RF field has not been switched on in time by the counterpart.
        rf_protocol_error = 0x0b,               ///< RF Protocol error.
        temperature_error = 0x0d,               ///< Antenna drivers were switched off due to overheating.
        buffer_overflow = 0x0e,                 ///< Internal buffer overflow.
        invalid_parameter = 0x10,               ///< Invalid parameter.
        dep_unsupported_command = 0x12,         ///< PN532 in DEP mode received an unsupported command from the initiator (i.e. none of ATR_REQ, WUP_REQ, PSL_REQ, DEP_REQ, DSL_REQ, RLS_REQ).
        specification_mismatch = 0x13,          ///< DEP Protocol, Mifare or ISO/IEC14443-4: the data format does not match to the specification.
        mifare_auth_error = 0x14,               ///< Mifare authentication error.
        wrong_uid_check_byte = 0x23,            ///< ISO/IEC14443-3: UID Check byte is wrong.
        dep_invalid_device_state = 0x25,        ///< DEP protocol: the device is in a state that does not allow this command.
        operation_not_allowed = 0x26,           ///< Host -> controller operation not allowed in this configuration.
        command_not_acceptable = 0x27,          ///< The current state of the PN532 or its target disallows this command.
        released_by_initiator = 0x29,           ///< PN532 as target has been released by the initiator.
        card_exchanged = 0x2a,                  ///< PN532 and ISO/IEC14443-3B only: the ID of the card does not match, meaning that the expected card has been exchanged with another one.
        card_disappeared = 0x2b,                ///< PN532 and ISO/IEC14443-3B only: the card previously activated has disappeared..
        nfcid3_initiator_target_mismatch = 0x2c,///< Mismatch between the NFCID3 initiator and the NFCID3 target in DEP 212/424 kbps passive..
        overcurrent = 0x2d,                     ///< Over-current event detected.
        nad_missing_in_dep_frame = 0x2e         ///< NAD missing in DEP frame.
    };

    /**
     * Polling method to use when searching for 106kbps passive type B targets (ISO/IEC14443-3B).
     * @see pn532::controller::initiator_list_passive_kbps106_typeb
     */
    enum struct polling_method : std::uint8_t {
        timeslot = 0x00,    ///< Default timeslot approach.
        probabilistic = 0x01///< Probabilistic approach.
    };
    /**
     * Supported combinations of @ref baudrate and @ref modulation.
     * @note These correspond to the lowest 3 bits of @ref target_type, which you can extract with @ref baudrate_modulation_of.
     * @see
     *  - baudrate
     *  - modulation
     *  - target_type
     *  - baudrate_modulation_of
     */
    enum struct baudrate_modulation : std::uint8_t {
        kbps106_iso_iec_14443_typea = 0x00,  ///< 106 kbps ISO/IEC 14443 type A
        kbps212_felica = 0x01,               ///< 212 kbps FeliCa modulation
        kbps424_felica = 0x02,               ///< 424 kbps FeliCa modulation
        kbps106_iso_iec_14443_3_typeb = 0x03,///< 106 kbps ISO/IEC 14443-3 type B
        kbps106_innovision_jewel_tag = 0x04  ///< 106 kbps Innovision Jewel tag
    };

    /**
     * Polling period to use when detecting targets of a specific type (UM0701-02 §7.3.13).
     * @see pn532::controller::initiator_auto_poll
     */
    enum struct poll_period : std::uint8_t {
        ms_150 = 0x1, ///< 150 ms (default)
        ms_300 = 0x2, ///< 300 ms
        ms_450 = 0x3, ///< 450 ms
        ms_600 = 0x4, ///< 600 ms
        ms_750 = 0x5, ///< 750 ms
        ms_900 = 0x6, ///< 900 ms
        ms_1050 = 0x7,///< 105 0ms
        ms_1200 = 0x8,///< 1200 ms
        ms_1350 = 0x9,///< 1350 ms
        ms_1500 = 0xa,///< 1500 ms
        ms_1650 = 0xb,///< 1650 ms
        ms_1800 = 0xc,///< 1800 ms
        ms_1950 = 0xd,///< 1950 ms
        ms_2100 = 0xe,///< 2100 ms
        ms_2250 = 0xf ///< 2250 ms
    };

    /**
     * Supported PN532 target types, distinguished by @ref modulation and @ref baudrate (UM0701-02 §7.3.13).
     * @note Modern Mifare Desfire cards do not appear as @ref target_type::mifare_classic_ultralight cards, but
     *  as @ref target_type::passive_106kbps_iso_iec_14443_4_typea targets instead. Note as well that some of these
     *  entries are duplicate, despite having different values. It is not clear based on what the PN532 chooses one
     *  over the other. For your specific application, scan for all targets and then narrow down to the type that is
     *  specific to yours. In some cases, specifying the incorrect scan target might push a card to activate in a
     *  legacy or compatibility mode, e.g. Mifare Desfire cards can activate as Mifare Classic if you are polling
     *  for @ref target_type::mifare_classic_ultralight, which deactivates most of the non-legacy commands.
     * @see
     *  - baudrate
     *  - modulation
     *  - baudrate_modulation
     *  - baudrate_modulation_of
     */
    enum struct target_type : std::uint8_t {
        generic_passive_106kbps = 0x00,                  ///< Generic passive 106 kbps target (ISO/IEC 14443-4A, Mifare, DEP).
        generic_passive_212kbps = 0x01,                  ///< Generic passive 212 kbps target (FeliCa and DEP).
        generic_passive_424kbps = 0x02,                  ///< Generic passive 424 kbps target (FeliCa and DEP).
        passive_106kbps_iso_iec_14443_4_typeb = 0x03,    ///< Passive 106 kbps ISO/IEC14443-4B target.
        innovision_jewel_tag = 0x04,                     ///< Innovision Jewel tag.
        mifare_classic_ultralight = 0x10,                ///< Mifare card, Classic or Ultralight.
        felica_212kbps_card = 0x11,                      ///< FeliCa 212 kbps card.
        felica_424kbps_card = 0x12,                      ///< FeliCa 424 kbps card.
        passive_106kbps_iso_iec_14443_4_typea = 0x20,    ///< Passive 106 kbps ISO/IEC14443-4A (Mifare Desfire).
        passive_106kbps_iso_iec_14443_4_typeb_alt = 0x23,///< Passive 106 kbps ISO/IEC14443-4B.
        dep_passive_106kbps = 0x40,                      ///< DEP passive 106 kbps
        dep_passive_212kbps = 0x41,                      ///< DEP passive 212 kbps
        dep_passive_424kbps = 0x42,                      ///< DEP passive 424 kbps
        dep_active_106kbps = 0x80,                       ///< DEP active 106 kbps
        dep_active_212kbps = 0x81,                       ///< DEP active 212 kbps
        dep_active_424kbps = 0x82                        ///< DEP active 424 kbps
    };

    /**
     * @brief Extract @ref baudrate_modulation of a given PN532 NFC @ref target_type.
     * @param target Target type.
     * @return The modulation and baudrate pair corresponding to @p target.
     */
    [[nodiscard]] constexpr baudrate_modulation baudrate_modulation_of(target_type target);

    /**
     * @brief Extract @ref baudrate of a given PN532 NFC @ref target_type.
     * @param target Target type.
     * @return The baudrate corresponding to @p target.
     */
    [[nodiscard]] constexpr baudrate baudrate_of(target_type target);

    /**
     * @brief Extract @ref modulation of a given PN532 NFC @ref target_type.
     * @param target Target type.
     * @return The modulation corresponding to @p target.
     */
    [[nodiscard]] constexpr modulation modulation_of(target_type target);

    /**
     * @brief Tag to mark NFCID classes.
     * @tparam Length Length of the NFCID.
     * @see
     *  - nfcid_1t
     *  - nfcid_2t
     *  - nfcid_3t
     */
    template <std::size_t Length>
    struct nfcid_cascade_tag {};

    /// @brief 4-bytes cascaded NFCID (NFCID 1t)
    using nfcid_1t = mlab::tagged_array<nfcid_cascade_tag<4>, 4>;

    /// @brief 7-bytes cascaded NFCID (NFCID 2t)
    using nfcid_2t = mlab::tagged_array<nfcid_cascade_tag<7>, 7>;

    /// @brief 10-bytes cascaded NFCID (NFCID 3t)
    using nfcid_3t = mlab::tagged_array<nfcid_cascade_tag<10>, 10>;

    /**
     * Result of an ATR_RES command. This is used when activating a passive target (UM0701-02 §7.3.3)
     * @see
     *  - pn532::controller::initiator_activate_target
     *  - pn532::controller::initiator_auto_poll
     *  - pn532::controller::initiator_jump_for_dep_active
     *  - pn532::controller::initiator_jump_for_dep_passive_106kbps
     *  - pn532::controller::initiator_jump_for_dep_passive_212kbps
     *  - pn532::controller::initiator_jump_for_dep_passive_424kbps
     *  - pn532::controller::initiator_jump_for_psl
     */
    struct atr_res_info {
        /// Identifier of the target.
        nfcid_3t nfcid;
        /// DID byte sent by the target
        std::uint8_t did_t;
        /// Supported send bit rate of the target.
        std::uint8_t b_st;
        /// Supported receive bit rate of the target.
        std::uint8_t b_rt;
        /// Timeout value of the target in transport protocol.
        std::uint8_t to;
        /// Optional parameters of the target (length reduction, NAD usable and general bytes).
        std::uint8_t pp_t;
        /// General information bytes (max 47).
        std::vector<std::uint8_t> g_t;
    };

    /**
     * Framing to use when operating as a target (UM0701-02 §7.3.14).
     * @see
     *  - pn532::controller::target_init_as_target
     *  - activation_as_target
     */
    enum struct framing_as_target : std::uint8_t {
        mifare = 0b00,     ///< Mifare framing.
        active_mode = 0b01,///< PN532 is operating as an active target.
        felica = 0b10      ///< FeliCa framing.
    };

    /**
     * @brief Information associated to a certain target discovery.
    * @warning This template declaration only exists to allow the specializations, it will not be used directly.
     * This comprises of a @ref target_logical_index::logical_index field, which is the logical index by which the PN532
     * refers to the target in the RF field, and the target info data.
     * @see
     *  - pn532::controller::initiator_list_passive_kbps106_typea
     *  - pn532::controller::initiator_list_passive_kbps106_typeb
     *  - pn532::controller::initiator_list_passive_kbps212_felica
     *  - pn532::controller::initiator_list_passive_kbps424_felica
     *  - pn532::controller::initiator_list_passive_kbps106_jewel_tag
     *  - pn532::controller::initiator_auto_poll
     *  - target<baudrate_modulation::kbps106_iso_iec_14443_typea>
     *  - target<baudrate_modulation::kbps212_felica>
     *  - target<baudrate_modulation::kbps424_felica>
     *  - target<baudrate_modulation::kbps106_iso_iec_14443_3_typeb>
     *  - target<baudrate_modulation::kbps106_innovision_jewel_tag>
     */
    template <baudrate_modulation>
    struct target {
    };

    /**
     * Mixin used to add a logical index to any @ref target struct.
     * @see
     *  - target<baudrate_modulation::kbps106_iso_iec_14443_typea>
     *  - target<baudrate_modulation::kbps212_felica>
     *  - target<baudrate_modulation::kbps424_felica>
     *  - target<baudrate_modulation::kbps106_iso_iec_14443_3_typeb>
     *  - target<baudrate_modulation::kbps106_innovision_jewel_tag>
     */
    struct target_logical_index {
        /**
         * @brief Logical index used by @ref controller to identify the target
         * @see
         *  - pn532::controller::initiator_data_exchange
         *  - pn532::controller::initiator_select
         *  - pn532::controller::initiator_deselect
         *  - pn532::controller::initiator_release
         *  - pn532::controller::initiator_activate_target
         */
        std::uint8_t logical_index;
    };

    /**
     * @brief A 106 kbps ISO/IEC 14443 type A passive target, as discovered by a PN532.
     * @see
     *  - pn532::controller::initiator_list_passive_kbps106_typea
     *  - pn532::controller::initiator_auto_poll
     */
    template <>
    struct target<baudrate_modulation::kbps106_iso_iec_14443_typea> : public target_logical_index {
        using target_logical_index::logical_index;
        /// Transmitted SENS_RES result (MSB first).
        std::array<std::uint8_t, 2> sens_res;
        /// Transmitted SEL_RES result.
        std::uint8_t sel_res;
        /**
         * @brief NFC Id. The length could be 4, 8 or 12 bytes long, depending on which id was transmitted
         * NFC Ids 2t and 3t IDs include the cascade byte, thus not 7 or 10 bytes, but 8 or 12.
         */
        std::vector<std::uint8_t> nfcid;
        /// ATS data.
        std::vector<std::uint8_t> ats;
    };

    /**
     * @brief A 212 kbps FeliCa passive target, as discovered by a PN532.
     * Identical to @ref target<baudrate_modulation::kbps424_felica>.
     * This represents part of the POL_RES result.
     * @see
     *  - pn532::controller::initiator_list_passive_kbps212_felica
     *  - pn532::controller::initiator_auto_poll
     */
    template <>
    struct target<baudrate_modulation::kbps212_felica> : public target_logical_index {
        using target_logical_index::logical_index;
        /// NFCID 2t (includes a cascade byte).
        std::array<std::uint8_t, 8> nfcid_2t;
        /// Padding bytes.
        std::array<std::uint8_t, 8> pad;
        /// SYST_CODE.
        std::array<std::uint8_t, 2> syst_code;
    };

    /**
     * @brief A 424 kbps FeliCa passive target, as discovered by a PN532.
     * Identical to @ref target<baudrate_modulation::kbps212_felica>.
     * This represents part of the POL_RES result.
     * @see
     *  - pn532::controller::initiator_list_passive_kbps424_felica
     *  - pn532::controller::initiator_auto_poll
     */
    template <>
    struct target<baudrate_modulation::kbps424_felica> : public target_logical_index {
        using target_logical_index::logical_index;
        /// NFCID 2t (includes a cascade byte).
        std::array<std::uint8_t, 8> nfcid_2t;
        /// Padding bytes.
        std::array<std::uint8_t, 8> pad;
        /// SYST_CODE.
        std::array<std::uint8_t, 2> syst_code;
    };

    /**
     * @brief A 106 kbps ISO/IEC 14443 type B passive target, as discovered by a PN532.
     * @see
     *  - pn532::controller::initiator_list_passive_kbps106_typeb
     *  - pn532::controller::initiator_auto_poll
     */
    template <>
    struct target<baudrate_modulation::kbps106_iso_iec_14443_3_typeb> : public target_logical_index {
        using target_logical_index::logical_index;
        /// ATQB data.
        std::array<std::uint8_t, 12> atqb_response;
        /// ATTRIB_RES data.
        std::vector<std::uint8_t> attrib_res;
    };

    /**
     * @brief A 106 kbps Innovision Jewel tag, as discovered by a PN532.
     * @see
     *  - pn532::controller::initiator_list_passive_kbps106_jewel_tag
     *  - pn532::controller::initiator_auto_poll
     */
    template <>
    struct target<baudrate_modulation::kbps106_innovision_jewel_tag> : public target_logical_index {
        using target_logical_index::logical_index;
        /// Transmitted SENS_RES result (MSB first).
        std::array<std::uint8_t, 2> sens_res;
        /// Jewel ID (4 bytes like a NFCID 1t).
        nfcid_1t jewel_id;
    };

#ifndef DOXYGEN_SHOULD_SKIP_THIS
    namespace bits {

        template <std::uint8_t MinIdx, std::uint8_t MaxIdx>
        static constexpr std::uint8_t bitmask_window = (0xff >> (7 + MinIdx - MaxIdx)) << MinIdx;

        static constexpr std::uint8_t preamble = 0x00;
        static constexpr std::uint8_t postamble = 0x00;

        enum struct transport : std::uint8_t {
            host_to_pn532 = 0xd4,
            pn532_to_host = 0xd5
        };

        static constexpr std::uint8_t specific_app_level_err_code = 0x7f;
        static constexpr std::array<std::uint8_t, 2> start_of_packet_code = {0x00, 0xff};
        static constexpr std::array<std::uint8_t, 2> ack_packet_code = {0x00, 0xff};
        static constexpr std::array<std::uint8_t, 2> nack_packet_code = {0xff, 0x00};
        static constexpr std::array<std::uint8_t, 2> fixed_extended_packet_length = {0xff, 0xff};

        static constexpr std::size_t max_firmware_data_length = 263;

        static constexpr std::uint8_t firmware_iso_iec_14443_typea_mask = 0b0001;
        static constexpr std::uint8_t firmware_iso_iec_14443_typeb_mask = 0b0010;
        static constexpr std::uint8_t firmware_iso_18092_mask = 0b0100;

        static constexpr unsigned echo_back_reply_delay_steps_per_ms = 2;

        enum struct test : std::uint8_t {
            comm_line = 0x0,  ///< Check the communication with PN532 by sending data, and reading it back
            rom = 0x1,        ///< Check the rom content of the PN532 is consistent
            ram = 0x2,        ///< Check the ram of the PN532
            poll_target = 0x4,///< Chck by polling a target and keep count of communication errors
            echo_back = 0x5,
            attention_req_or_card_presence = 0x6,
            self_antenna = 0x7
        };

        static constexpr std::uint8_t reg_andet_control_low_current_mask = bitmask_window<4, 5>;
        static constexpr std::uint8_t reg_andet_control_high_current_mask = bitmask_window<1, 3>;

        static constexpr std::uint8_t reg_andet_control_too_low_power_mask = 1 << 7;
        static constexpr std::uint8_t reg_andet_control_too_high_power_mask = 1 << 6;
        static constexpr std::uint8_t reg_andet_control_antenna_detect_mask = 1 << 0;

        static constexpr std::uint8_t rf_configuration_field_auto_rfca_mask = 0b10;
        static constexpr std::uint8_t rf_configuration_field_auto_rf_on_mask = 0b01;


        enum struct rf_config_item : std::uint8_t {
            rf_field = 0x01,
            timings = 0x02,
            max_rty_com = 0x04,
            max_retries = 0x05,
            analog_106kbps_typea = 0x0a,
            analog_212_424kbps = 0x0b,
            analog_typeb = 0x0c,
            analog_iso_iec_14443_4 = 0x0d
        };

        static constexpr unsigned status_as_target_initiator_speed_shift = 4;
        static constexpr unsigned status_as_target_target_speed_shift = 0;
        static constexpr std::uint8_t baudrate_mask = 0b111;

        static constexpr unsigned sam_timeout_unit_ms = 50;

        static constexpr std::uint8_t status_nad_mask = 0x1 << 7;
        static constexpr std::uint8_t status_more_info_mask = 0x1 << 6;
        static constexpr std::uint8_t status_error_mask = 0b00111111;

        static constexpr std::uint8_t sam_status_neg_pulse_on_clad_line_bit = 1 << 0;
        static constexpr std::uint8_t sam_status_detected_rf_field_off_bit = 1 << 1;
        static constexpr std::uint8_t sam_status_timeout_after_sig_act_irq_bit = 1 << 2;
        static constexpr std::uint8_t sam_status_clad_line_high_bit = 1 << 7;

        static constexpr std::uint8_t parameters_use_nad_data_bit = 1 << 0;
        static constexpr std::uint8_t parameters_use_did_data_bit = 1 << 1;
        static constexpr std::uint8_t parameters_auto_generate_atr_res_bit = 1 << 2;
        static constexpr std::uint8_t parameters_auto_generate_rats_bit = 1 << 4;
        static constexpr std::uint8_t parameters_enable_iso_14443_4_picc_emulation_bit = 1 << 5;
        static constexpr std::uint8_t parameters_remove_pre_post_amble_bit = 1 << 6;

        static constexpr std::uint8_t max_num_targets = 2;


        static constexpr std::uint8_t uid_cascade_tag = 0x88;


        static constexpr unsigned autopoll_max_types = 15;

        static constexpr std::uint8_t target_type_baudrate_modulation_mask = 0b111;

        static constexpr unsigned init_as_target_res_baudrate_shift = 4;
        static constexpr std::uint8_t init_as_target_res_picc_bit = 1 << 3;
        static constexpr std::uint8_t init_as_target_res_dep_bit = 1 << 2;

        static constexpr std::uint8_t framing_mask = 0b11;

        static constexpr std::uint8_t init_as_target_picc_only_bit = 1 << 2;
        static constexpr std::uint8_t init_as_target_dep_only_bit = 1 << 1;
        static constexpr std::uint8_t init_as_target_passive_only_bit = 1 << 0;

        /**
         * @{
         */
        /**
         * These constants seem to be intended for usage in @ref pn532::mifare_params::sel_res
         * and @ref target<baudrate_modulation::kbps106_iso_iec_14443_typea>::sel_res.
         */
        [[maybe_unused]] static constexpr std::uint8_t sel_res_dep_mask = 0x40;
        [[maybe_unused]] static constexpr std::uint8_t sel_res_picc_mask = 0x60;
        /**
         * @}
         */

        static constexpr std::size_t init_as_target_general_info_max_length = 47;
        static constexpr std::size_t init_as_target_historical_bytes_max_length = 48;

        static constexpr std::uint8_t in_atr_nfcid_3t_present_mask = 0b01;
        static constexpr std::uint8_t in_atr_general_info_present_mask = 0b10;

        static constexpr std::uint8_t in_jump_for_dep_passive_init_data_present_mask = 0b001;
        static constexpr std::uint8_t in_jump_for_dep_nfcid_3t_present_mask = 0b010;
        static constexpr std::uint8_t in_jump_for_dep_general_info_present_mask = 0b100;

        static constexpr std::size_t general_info_max_length = 48;

        static constexpr std::uint8_t gpio_p3_pin_mask = bitmask_window<0, 5>;
        static constexpr std::uint8_t gpio_p7_pin_mask = bitmask_window<1, 2>;
        static constexpr std::uint8_t gpio_i0i1_pin_mask = 0x00;// Cannot set i0i1

        static constexpr std::uint8_t gpio_write_validate_max = 1 << 7;

        static constexpr std::uint8_t sfr_registers_high = 0xff;

        /**
         * Parameters for the command "Diagnose" (@ref controller::diagnose_self_antenna) (UM0701-02 §7.2.1)
         * The parameters are described in (PN532/C1 §8.6.9.2)
         */
        struct reg_antenna_detector {
            bool detected_low_pwr;                         //!< Too low power consuption detection flag (must be 0) (PN532/C1 §8.6.9.2)
            bool detected_high_pwr;                        //!< Too high power consuptiond detection flag (must be 0) (PN532/C1 §8.6.9.2)
            pn532::low_current_thr low_current_threshold;  //!< Lower current threshold for low power detection (PN532/C1 §8.6.9.2)
            pn532::high_current_thr high_current_threshold;//!< Higher current threshold for high current detection (PN532/C1 §8.6.9.2)
            bool enable_detection;                         //!< Start antenna selftest (must be 1) (PN532/C1 §8.6.9.2)
        };

    }// namespace bits
#endif
}// namespace pn532


namespace pn532 {
    constexpr baudrate_modulation baudrate_modulation_of(target_type target) {
        return static_cast<baudrate_modulation>(static_cast<std::uint8_t>(target) & bits::target_type_baudrate_modulation_mask);
    }

    constexpr baudrate baudrate_of(target_type target) {
        switch (baudrate_modulation_of(target)) {
            case baudrate_modulation::kbps212_felica:
                return baudrate::kbps212;
            case baudrate_modulation::kbps424_felica:
                return baudrate::kbps424;
            default:
                return baudrate::kbps106;
        }
    }

    constexpr modulation modulation_of(target_type target) {
        switch (baudrate_modulation_of(target)) {
            case baudrate_modulation::kbps106_iso_iec_14443_typea:
                [[fallthrough]];
            case baudrate_modulation::kbps106_iso_iec_14443_3_typeb:
                return modulation::mifare_iso_iec_14443_3_type_ab_iso_iec_18092_passive_kbps106;
            case baudrate_modulation::kbps212_felica:
                [[fallthrough]];
            case baudrate_modulation::kbps424_felica:
                return modulation::felica_iso_iec_18092_kbps212_424;
            case baudrate_modulation::kbps106_innovision_jewel_tag:
                return modulation::innovision_jewel_tag;
        }
        return modulation::iso_iec_18092_active;
    }

    namespace reg {
        addr::addr(reg::sfr_register sfr_reg)
            : std::array<std::uint8_t, 2>{{bits::sfr_registers_high, static_cast<std::uint8_t>(sfr_reg)}} {}

        addr::addr(std::uint16_t xram_mmap_reg)
            : std::array<std::uint8_t, 2>{{std::uint8_t(xram_mmap_reg >> 8),
                                           std::uint8_t(xram_mmap_reg & 0xff)}} {}
    }// namespace reg
}// namespace pn532

#endif//PN532_BITS_HPP
