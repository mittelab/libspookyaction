//
// Created by Pietro Saccardi on 22/12/2020.
//

#include <pn532/channel.hpp>
#include <pn532/msg.hpp>

namespace pn532 {
    const char *to_string(baudrate s) {
        switch (s) {
            case baudrate::kbps106:
                return "106 kbps";
            case baudrate::kbps212:
                return "212 kbps";
            case baudrate::kbps424:
                return "424 kbps";
        }
        return "UNKNOWN";
    }

    const char *to_string(command_code c) {
        switch (c) {
            case command_code::diagnose:
                return "Diagnose";
            case command_code::get_firmware_version:
                return "GetFirmwareVersion";
            case command_code::get_general_status:
                return "GetGeneralStatus";
            case command_code::read_register:
                return "ReadRegister";
            case command_code::write_register:
                return "WriteRegister";
            case command_code::read_gpio:
                return "ReadGpio";
            case command_code::write_gpio:
                return "WriteGpio";
            case command_code::set_serial_baudrate:
                return "SetSerialBaudrate";
            case command_code::set_parameters:
                return "SetParameters";
            case command_code::sam_configuration:
                return "SAMConfiguration";
            case command_code::power_down:
                return "PowerDown";
            case command_code::rf_configuration:
                return "RfConfiguration";
            case command_code::rf_regulation_test:
                return "RfRegulationTest";
            case command_code::in_jump_for_dep:
                return "InJumpForDep";
            case command_code::in_jump_for_psl:
                return "InJumpForPsl";
            case command_code::in_list_passive_target:
                return "InListPassiveTarget";
            case command_code::in_atr:
                return "InAtr";
            case command_code::in_psl:
                return "InPsl";
            case command_code::in_data_exchange:
                return "InDataExchange";
            case command_code::in_communicate_thru:
                return "InCommunicateThru";
            case command_code::in_deselect:
                return "InDeselect";
            case command_code::in_release:
                return "InRelease";
            case command_code::in_select:
                return "InSelect";
            case command_code::in_autopoll:
                return "InAutopoll";
            case command_code::tg_init_as_target:
                return "TgInitAsTarget";
            case command_code::tg_set_general_bytes:
                return "TgSetGeneralBytes";
            case command_code::tg_get_data:
                return "TgGetData";
            case command_code::tg_set_data:
                return "TgSetData";
            case command_code::tg_set_metadata:
                return "TgSetMetadata";
            case command_code::tg_get_initiator_command:
                return "TgGetInitiatorCommand";
            case command_code::tg_response_to_initiator:
                return "TgResponseToInitiator";
            case command_code::tg_get_target_status:
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

    const char *to_string(baudrate_modulation bm) {
        switch (bm) {
            case baudrate_modulation::kbps106_iso_iec_14443_typea:
                return "106 kbps ISO/IEC 14443 TypeA";
            case baudrate_modulation::kbps212_felica:
                return "212 kbps FeliCa polling";
            case baudrate_modulation::kbps424_felica:
                return "424 kbps FeliCa polling";
            case baudrate_modulation::kbps106_iso_iec_14443_3_typeb:
                return "106 kbps ISO/IEC 14443-3 TypeB";
            case baudrate_modulation::kbps106_innovision_jewel_tag:
                return "106 kbps Innovision Jewel Tag";
        }
        return "UNKNOWN";
    }

    const char *to_string(target_type t) {
        switch (t) {
            case target_type::generic_passive_106kbps:
                return "Generic passive 106 kbps (ISO/IEC14443-4A, Mifare and DEP)";
            case target_type::generic_passive_212kbps:
                return "Generic passive 212 kbps (FeliCa and DEP)";
            case target_type::generic_passive_424kbps:
                return "Generic passive 424 kbps (FeliCa and DEP)";
            case target_type::passive_106kbps_iso_iec_14443_4_typeb:
                return "Passive 106 kbps ISO/IEC14443-4B";
            case target_type::innovision_jewel_tag:
                return "Innovision Jewel tag";
            case target_type::mifare_classic_ultralight:
                return "Mifare Classic or Ultralight";
            case target_type::felica_212kbps_card:
                return "FeliCa 212 kbps card";
            case target_type::felica_424kbps_card:
                return "FeliCa 424 kbps card";
            case target_type::passive_106kbps_iso_iec_14443_4_typea:
                return "Passive 106 kbps ISO/IEC14443-4A";
            case target_type::passive_106kbps_iso_iec_14443_4_typeb_alt:
                return "Passive 106 kbps ISO/IEC14443-4B";
            case target_type::dep_passive_106kbps:
                return "DEP passive 106 kbps";
            case target_type::dep_passive_212kbps:
                return "DEP passive 212 kbps";
            case target_type::dep_passive_424kbps:
                return "DEP passive 424 kbps";
            case target_type::dep_active_106kbps:
                return "DEP active 106 kbps";
            case target_type::dep_active_212kbps:
                return "DEP active 212 kbps";
            case target_type::dep_active_424kbps:
                return "DEP active 424 kbps";
        }
        return "UNKNOWN";
    }

    const char *to_string(internal_error_code e) {
        switch (e) {
            case internal_error_code::none:
                return "none";
            case internal_error_code::timeout:
                return "timeout";
            case internal_error_code::crc_error:
                return "CRC error";
            case internal_error_code::parity_error:
                return "parity error";
            case internal_error_code::erroneous_bit_count:
                return "erroneous bit count";
            case internal_error_code::framing_error:
                return "framing error";
            case internal_error_code::bit_collision:
                return "bit collision";
            case internal_error_code::buffer_size_insufficient:
                return "buffer size insufficient";
            case internal_error_code::rf_buffer_overflow:
                return "RF buffer overflow";
            case internal_error_code::counterpart_rf_off:
                return "counterpart RF off";
            case internal_error_code::rf_protocol_error:
                return "RF protocol error";
            case internal_error_code::temperature_error:
                return "temperature error";
            case internal_error_code::buffer_overflow:
                return "buffer overflow";
            case internal_error_code::invalid_parameter:
                return "invalid parameter";
            case internal_error_code::dep_unsupported_command:
                return "DEP unsupported command";
            case internal_error_code::specification_mismatch:
                return "DEP specification mismatch";
            case internal_error_code::mifare_auth_error:
                return "Mifare auth error";
            case internal_error_code::wrong_uid_check_byte:
                return "wrong uid check byte";
            case internal_error_code::dep_invalid_device_state:
                return "DEP invalid device state";
            case internal_error_code::operation_not_allowed:
                return "operation not allowed";
            case internal_error_code::command_not_acceptable:
                return "command not acceptable";
            case internal_error_code::released_by_initiator:
                return "released by initiator";
            case internal_error_code::card_exchanged:
                return "card exchanged";
            case internal_error_code::card_disappeared:
                return "card disappeared";
            case internal_error_code::nfcid3_initiator_target_mismatch:
                return "NFCID3 initiator target_mismatch";
            case internal_error_code::overcurrent:
                return "overcurrent";
            case internal_error_code::nad_missing_in_dep_frame:
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

    const char *to_string(channel_error e) {
        switch (e) {
            case channel_error::malformed:
                return "Malformed or unexpected response";
            case channel_error::hw_error:
                return "Controller returned error instead of ACK";
            case channel_error::app_error:
                return "Controller acknowledged but returned error";
            case channel_error::timeout:
                return "Communication reached timeout";
        }
        return "UNKNOWN";
    }
}// namespace pn532