//
// Created by Pietro Saccardi on 22/12/2020.
//

#include "msg.hpp"

namespace pn532 {
    const char *to_string(bits::speed s) {
        switch (s) {
            case bits::speed::kbps106: return "106 kbps";
            case bits::speed::kbps212: return "212 kbps";
            case bits::speed::kbps424: return "424 kbps";
            default: return "UNKNOWN";
        }
    }
    const char *to_string(bits::command c) {
        switch (c) {
            case bits::command::diagnose:                 return "Diagnose";
            case bits::command::get_firmware_version:     return "GetFirmwareVersion";
            case bits::command::get_general_status:       return "GetGeneralStatus";
            case bits::command::read_register:            return "ReadRegister";
            case bits::command::write_register:           return "WriteRegister";
            case bits::command::read_gpio:                return "ReadGpio";
            case bits::command::write_gpio:               return "WriteGpio";
            case bits::command::set_serial_baudrate:      return "SetSerialBaudrate";
            case bits::command::set_parameters:           return "SetParameters";
            case bits::command::sam_configuration:        return "SAMConfiguration";
            case bits::command::power_down:               return "PowerDown";
            case bits::command::rf_configuration:         return "RfConfiguration";
            case bits::command::rf_regulation_test:       return "RfRegulationTest";
            case bits::command::in_jump_for_dep:          return "InJumpForDep";
            case bits::command::in_jump_for_psl:          return "InJumpForPsl";
            case bits::command::in_list_passive_target:   return "InListPassiveTarget";
            case bits::command::in_atr:                   return "InAtr";
            case bits::command::in_psl:                   return "InPsl";
            case bits::command::in_data_exchange:         return "InDataExchange";
            case bits::command::in_communicate_thru:      return "InCommunicateThru";
            case bits::command::in_deselect:              return "InDeselect";
            case bits::command::in_release:               return "InRelease";
            case bits::command::in_select:                return "InSelect";
            case bits::command::in_autopoll:              return "InAutopoll";
            case bits::command::tg_init_as_target:        return "TgInitAsTarget";
            case bits::command::tg_set_general_bytes:     return "TgSetGeneralBytes";
            case bits::command::tg_get_data:              return "TgGetData";
            case bits::command::tg_set_data:              return "TgSetData";
            case bits::command::tg_set_metadata:          return "TgSetMetadata";
            case bits::command::tg_get_initiator_command: return "TgGetInitiatorCommand";
            case bits::command::tg_response_to_initiator: return "TgResponseToInitiator";
            case bits::command::tg_get_target_status:     return "TgGetTargetStatus";
            default: return "UNKNOWN";
        }
    }
    const char *to_string(bits::test t) {
        switch (t) {
            case bits::test::comm_line:                      return "communication line";
            case bits::test::rom:                            return "ROM";
            case bits::test::ram:                            return "RAM";
            case bits::test::poll_target:                    return "poll target";
            case bits::test::echo_back:                      return "echo back";
            case bits::test::attention_req_or_card_presence: return "attention request/card presence";
            case bits::test::self_antenna:                   return "self antenna";
            default: return "UNKNOWN";
        }
    }
}