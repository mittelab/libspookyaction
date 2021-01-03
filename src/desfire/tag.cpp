//
// Created by Pietro Saccardi on 02/01/2021.
//

#include "desfire/bits.hpp"
#include "desfire/data.hpp"
#include "desfire/cipher.hpp"
#include "desfire/tag.hpp"

namespace desfire {

    void tag::clear_authentication() {
        if (_active_cipher != nullptr) {
            LOGI("Releasing authentication.");
            _active_cipher = nullptr;
            _active_key_number = std::numeric_limits<std::uint8_t>::max();
            _active_cipher_type = cipher_type::none;
        }
    }

    tag::r<bin_data> tag::raw_command_response(bin_data const &payload) {
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " >>", payload.data(), payload.size(), ESP_LOG_VERBOSE);
        auto res_cmd = ctrl().communicate(payload);
        if (res_cmd.second) {
            ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " <<", res_cmd.second.data(), res_cmd.second.size(), ESP_LOG_VERBOSE);
            return std::move(res_cmd.first);
        }
        return error::controller_error;
    }

    bool tag::authenticate(const any_key &k) {
        clear_authentication();

    }

    tag::r<bin_data> tag::command_response(bin_data &payload, std::size_t secure_data_offset, cipher &cipher,
                                           cipher::config const &tx_cfg, cipher::config const &rx_cfg,
                                           bool handle_additional_frames)
    {
        cipher.prepare_tx(payload, secure_data_offset, tx_cfg);
        bin_data received{};
        do {
            const auto res = raw_command_response(payload);
            if (not res) {
                return res.error();
            }
            if (res.empty()) {
                LOGE("Received empty payload from card.");
                return error::controller_error;
            }
            // Append data, move status byte at the end
            received.reserve(received.size() + res->size());
            received << res->front() << res->view(1);
            // Check status byte if necessary
            if (handle_additional_frames) {
                const auto sb = static_cast<status>(received.back());
                if (sb == status::additional_frame) {
                    // The "more frames" status is not part of the payload
                    received.pop_back();
                    if (received.size() == res->size()) {
                        // Only one payload was received, clear and insert a single byte asking for more frames
                        payload.clear();
                        payload << bits::command_code::additional_frame;
                    }
                } else {  // Signal stop
                    handle_additional_frames = false;
                }
            }
        } while (handle_additional_frames);
        // Now status byte is at the end. Check for possible errors
        const auto sb = static_cast<status>(received.back());
        if (sb == status::ok or sb == status::no_changes) {
            // Can postprocess using crypto
            if (not cipher.confirm_rx(received, rx_cfg)) {
                LOGW("Crypto failed on payload.");
                /// @todo Log comm mode and log payload
                return error::crypto_error;
            }
            return received;
        }
        // Status are also error codes
        return static_cast<error>(received.back());
    }

}
