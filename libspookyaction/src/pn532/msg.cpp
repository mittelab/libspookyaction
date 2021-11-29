//
// Created by Pietro Saccardi on 22/12/2020.
//

#include <pn532/msg.hpp>
#include <pn532/channel.hpp>

namespace pn532 {
    const char *to_string(bits::baudrate s) {
        switch (s) {
            case bits::baudrate::kbps106:
                return "106 kbps";
            case bits::baudrate::kbps212:
                return "212 kbps";
            case bits::baudrate::kbps424:
                return "424 kbps";
        }
        return "UNKNOWN";
    }

    const char *to_string(bits::command c) {
        switch (c) {
            case bits::command::diagnose:
                return "Diagnose";
            case bits::command::get_firmware_version:
                return "GetFirmwareVersion";
            case bits::command::get_general_status:
                return "GetGeneralStatus";
            case bits::command::read_register:
                return "ReadRegister";
            case bits::command::write_register:
                return "WriteRegister";
            case bits::command::read_gpio:
                return "ReadGpio";
            case bits::command::write_gpio:
                return "WriteGpio";
            case bits::command::set_serial_baudrate:
                return "SetSerialBaudrate";
            case bits::command::set_parameters:
                return "SetParameters";
            case bits::command::sam_configuration:
                return "SAMConfiguration";
            case bits::command::power_down:
                return "PowerDown";
            case bits::command::rf_configuration:
                return "RfConfiguration";
            case bits::command::rf_regulation_test:
                return "RfRegulationTest";
            case bits::command::in_jump_for_dep:
                return "InJumpForDep";
            case bits::command::in_jump_for_psl:
                return "InJumpForPsl";
            case bits::command::in_list_passive_target:
                return "InListPassiveTarget";
            case bits::command::in_atr:
                return "InAtr";
            case bits::command::in_psl:
                return "InPsl";
            case bits::command::in_data_exchange:
                return "InDataExchange";
            case bits::command::in_communicate_thru:
                return "InCommunicateThru";
            case bits::command::in_deselect:
                return "InDeselect";
            case bits::command::in_release:
                return "InRelease";
            case bits::command::in_select:
                return "InSelect";
            case bits::command::in_autopoll:
                return "InAutopoll";
            case bits::command::tg_init_as_target:
                return "TgInitAsTarget";
            case bits::command::tg_set_general_bytes:
                return "TgSetGeneralBytes";
            case bits::command::tg_get_data:
                return "TgGetData";
            case bits::command::tg_set_data:
                return "TgSetData";
            case bits::command::tg_set_metadata:
                return "TgSetMetadata";
            case bits::command::tg_get_initiator_command:
                return "TgGetInitiatorCommand";
            case bits::command::tg_response_to_initiator:
                return "TgResponseToInitiator";
            case bits::command::tg_get_target_status:
                return "TgGetTargetStatus";
        }
        return "UNKNOWN";
    }

    const char *to_string(bits::test t) {
        switch (t) {
            case bits::test::comm_line:
                return "communication line";
            case bits::test::rom:
                return "ROM";
            case bits::test::ram:
                return "RAM";
            case bits::test::poll_target:
                return "poll target";
            case bits::test::echo_back:
                return "echo back";
            case bits::test::attention_req_or_card_presence:
                return "attention request/card presence";
            case bits::test::self_antenna:
                return "self antenna";
        }
        return "UNKNOWN";
    }

    const char *to_string(bits::baudrate_modulation bm) {
        switch (bm) {
            case bits::baudrate_modulation::kbps106_iso_iec_14443_typea:
                return "106 kbps ISO/IEC 14443 TypeA";
            case bits::baudrate_modulation::kbps212_felica_polling:
                return "212 kbps FeliCa polling";
            case bits::baudrate_modulation::kbps424_felica_polling:
                return "424 kbps FeliCa polling";
            case bits::baudrate_modulation::kbps106_iso_iec_14443_3_typeb:
                return "106 kbps ISO/IEC 14443-3 TypeB";
            case bits::baudrate_modulation::kbps106_innovision_jewel_tag:
                return "106 kbps Innovision Jewel Tag";
        }
        return "UNKNOWN";
    }

    const char *to_string(bits::target_type t) {
        switch (t) {
            case bits::target_type::generic_passive_106kbps:
                return "Generic passive 106 kbps (ISO/IEC14443-4A, Mifare and DEP)";
            case bits::target_type::generic_passive_212kbps:
                return "Generic passive 212 kbps (FeliCa and DEP)";
            case bits::target_type::generic_passive_424kbps:
                return "Generic passive 424 kbps (FeliCa and DEP)";
            case bits::target_type::passive_106kbps_iso_iec_14443_4_typeb:
                return "Passive 106 kbps ISO/IEC14443-4B";
            case bits::target_type::innovision_jewel_tag:
                return "Innovision Jewel tag";
            case bits::target_type::mifare_card:
                return "Mifare card";
            case bits::target_type::felica_212kbps_card:
                return "FeliCa 212 kbps card";
            case bits::target_type::felica_424kbps_card:
                return "FeliCa 424 kbps card";
            case bits::target_type::passive_106kbps_iso_iec_14443_4_typea:
                return "Passive 106 kbps ISO/IEC14443-4A";
            case bits::target_type::passive_106kbps_iso_iec_14443_4_typeb_alt:
                return "Passive 106 kbps ISO/IEC14443-4B";
            case bits::target_type::dep_passive_106kbps:
                return "DEP passive 106 kbps";
            case bits::target_type::dep_passive_212kbps:
                return "DEP passive 212 kbps";
            case bits::target_type::dep_passive_424kbps:
                return "DEP passive 424 kbps";
            case bits::target_type::dep_active_106kbps:
                return "DEP active 106 kbps";
            case bits::target_type::dep_active_212kbps:
                return "DEP active 212 kbps";
            case bits::target_type::dep_active_424kbps:
                return "DEP active 424 kbps";
        }
        return "UNKNOWN";
    }

    const char *to_string(bits::error e) {
        switch (e) {
            case bits::error::none:
                return "none";
            case bits::error::timeout:
                return "timeout";
            case bits::error::crc_error:
                return "CRC error";
            case bits::error::parity_error:
                return "parity error";
            case bits::error::erroneous_bit_count:
                return "erroneous bit count";
            case bits::error::framing_error:
                return "framing error";
            case bits::error::bit_collision:
                return "bit collision";
            case bits::error::buffer_size_insufficient:
                return "buffer size insufficient";
            case bits::error::rf_buffer_overflow:
                return "RF buffer overflow";
            case bits::error::counterpart_rf_off:
                return "counterpart RF off";
            case bits::error::rf_protocol_error:
                return "RF protocol error";
            case bits::error::temperature_error:
                return "temperature error";
            case bits::error::buffer_overflow:
                return "buffer overflow";
            case bits::error::invalid_parameter:
                return "invalid parameter";
            case bits::error::dep_unsupported_command:
                return "DEP unsupported command";
            case bits::error::dep_specification_mismatch:
                return "DEP specification mismatch";
            case bits::error::mifare_auth_error:
                return "Mifare auth error";
            case bits::error::wrong_uid_check_byte:
                return "wrong uid check byte";
            case bits::error::dep_invalid_device_state:
                return "DEP invalid device state";
            case bits::error::operation_not_allowed:
                return "operation not allowed";
            case bits::error::command_not_acceptable:
                return "command not acceptable";
            case bits::error::released_by_initiator:
                return "released by initiator";
            case bits::error::card_exchanged:
                return "card exchanged";
            case bits::error::card_disappeared:
                return "card disappeared";
            case bits::error::nfcid3_initiator_target_mismatch:
                return "NFCID3 initiator target_mismatch";
            case bits::error::overcurrent:
                return "overcurrent";
            case bits::error::nad_missing_in_dep_frame:
                return "NAD missing in DEP frame";
        }
        return "UNKNOWN";
    }

    const char *to_string(frame_type type) {
        switch (type) {
            case frame_type::ack:
                return "ack";
            case frame_type::nack:
                return "nack";
            case frame_type::error:
                return "error";
            case frame_type::info:
                return "info";
            default:
                return "UNKNOWN";
        }
    }

    const char *to_string(channel::error e) {
        switch (e) {
            case channel::error::comm_malformed:
                return "Malformed or unexpected response";
            case channel::error::comm_error:
                return "Controller returned error instead of ACK";
            case channel::error::failure:
                return "Controller acknowledged but returned error";
            case channel::error::comm_timeout:
                return "Communication reached timeout";
        }
        return "UNKNOWN";
    }
}// namespace pn532