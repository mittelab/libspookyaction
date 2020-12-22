//
// Created by Pietro Saccardi on 22/12/2020.
//

#include "data.hpp"

namespace pn532 {

    bin_data &operator<<(bin_data &bd, ciu_reg_212_424kbps const &reg) {
        bd.reserve(bd.size() + sizeof(ciu_reg_212_424kbps));
        return bd << reg.rf_cfg << reg.gs_n_on << reg.cw_gs_p << reg.mod_gs_p << reg.demod_own_rf_on
            << reg.rx_threshold << reg.demod_own_rf_off << reg.gs_n_off;
    }

    bin_data &operator<<(bin_data &bd, ciu_reg_106kbps_typea const &reg) {
        bd.reserve(bd.size() + sizeof(ciu_reg_106kbps_typea));
        return bd << reg.rf_cfg << reg.gs_n_on << reg.cw_gs_p << reg.mod_gs_p << reg.demod_own_rf_on << reg.rx_threshold
            << reg.demod_own_rf_off << reg.gs_n_off << reg.mod_width << reg.mif_nfc << reg.tx_bit_phase;
    }

    bin_data &operator<<(bin_data &bd, ciu_reg_typeb const &reg) {
        bd.reserve(bd.size() + sizeof(ciu_reg_typeb));
        return bd << reg.gs_n_on << reg.mod_gs_p << reg.rx_threshold;
    }

    bin_data &operator<<(bin_data &bd, ciu_reg_iso_iec_14443_4_at_baudrate const &reg) {
        bd.reserve(bd.size() + sizeof(ciu_reg_iso_iec_14443_4_at_baudrate));
        return bd << reg.rx_threshold << reg.mod_width << reg.mif_nfc;
    }

    bin_data &operator<<(bin_data &bd, ciu_reg_iso_iec_14443_4 const &reg) {
        bd.reserve(bd.size() + sizeof(ciu_reg_iso_iec_14443_4));
        return bd << reg.kbps212 << reg.kbps424 << reg.kbps848;
    }

}