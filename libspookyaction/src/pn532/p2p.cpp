//
// Created by spak on 1/20/23.
//

#include <pn532/p2p.hpp>

namespace pn532::p2p {

    result<mlab::bin_data> pn532_initiator::communicate(mlab::bin_data const &data, ms timeout) {
        if (_controller == nullptr) {
            return pn532::channel_error::app_error;
        }
        ESP_LOG_BUFFER_HEX_LEVEL(PN532_TAG "-P2P >>", data.data(), data.size(), ESP_LOG_VERBOSE);
        if (auto r = _controller->initiator_data_exchange(_idx, data, timeout); r) {
            ESP_LOG_BUFFER_HEX_LEVEL(PN532_TAG "-P2P <<", r->second.data(), r->second.size(), ESP_LOG_VERBOSE);
            return std::move(r->second);
        } else {
            return r.error();
        }
    }

    [[nodiscard]] result<mlab::bin_data> pn532_target::receive(ms timeout) {
        if (_controller == nullptr) {
            return pn532::channel_error::app_error;
        }
        if (auto r = _controller->target_get_data(timeout); r) {
            ESP_LOG_BUFFER_HEX_LEVEL(PN532_TAG "-P2P <<", r->second.data(), r->second.size(), ESP_LOG_VERBOSE);
            return std::move(r->second);
        } else {
            return r.error();
        }
    }

    [[nodiscard]] result<> pn532_target::send(mlab::bin_data const &data, ms timeout) {
        if (_controller == nullptr) {
            return pn532::channel_error::app_error;
        }
        ESP_LOG_BUFFER_HEX_LEVEL(PN532_TAG " >>", data.data(), data.size(), ESP_LOG_VERBOSE);
        if (const auto r = _controller->target_set_data(data, timeout); not r) {
            return r.error();
        }
        return mlab::result_success;
    }

    pn532_initiator::pn532_initiator(pn532::controller &controller, std::uint8_t logical_index)
        : _controller{&controller}, _idx{logical_index} {}

    pn532_target::pn532_target(pn532::controller &controller)
        : _controller{&controller} {}

    result<pn532::activation_as_target> pn532_target::init_as_dep_target(std::array<std::uint8_t, 5> nfcid_data, ms timeout) {
        if (_controller == nullptr) {
            return pn532::channel_error::app_error;
        }
        // last two 0-padded bytes are required by PN532
        const nfcid_3t nfcid{
                // 0x08 means: randomly generated, 0x88 is the chaining byte
                0x88, 0x08, nfcid_data[0], nfcid_data[1],
                0x88, nfcid_data[2], nfcid_data[3], nfcid_data[4],
                0x00, 0x00};
        const pn532::mifare_params mp{
                .sens_res = {0x04, 0x00},
                .nfcid_1t = {nfcid[1], nfcid[2], nfcid[3]},
                .sel_res = pn532::bits::sel_res_dep_mask};
        const pn532::felica_params fp{
                .nfcid_2t = {nfcid[0], nfcid[1], nfcid[2], nfcid[3], nfcid[4], nfcid[5], nfcid[6], nfcid[7]},
                .pad = {0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7},
                .syst_code = {0xff, 0xff}};
        return _controller->target_init_as_target(false, true, false, mp, fp, nfcid, {}, {}, timeout);
    }

}// namespace pn532::p2p