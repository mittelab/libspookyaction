//
// Created by Pietro Saccardi on 02/01/2021.
//

#include <esp_system.h>
#include "desfire/bits.hpp"
#include "desfire/data.hpp"
#include "desfire/cipher.hpp"
#include "desfire/crypto_algo.hpp"
#include "desfire/tag.hpp"
#include "desfire/msg.hpp"

namespace desfire {

    void tag::clear_authentication() {
        if (_active_cipher != nullptr) {
            LOGI("Releasing authentication.");
            _active_cipher = nullptr;
            _active_key_number = std::numeric_limits<std::uint8_t>::max();
            _active_cipher_type = cipher_type::none;
        }
    }

    tag::r<bin_data> tag::raw_command_response(bin_data const &payload, bool rotate_status) {
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " >>", payload.data(), payload.size(), ESP_LOG_VERBOSE);
        auto res_cmd = ctrl().communicate(payload);
        if (res_cmd.second) {
            ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " <<", res_cmd.first.data(), res_cmd.first.size(), ESP_LOG_VERBOSE);
            if (rotate_status) {
                // Move status byte at the back of the data
                std::rotate(std::begin(res_cmd.first), std::begin(res_cmd.first) + 1, std::end(res_cmd.first));
            }
            return std::move(res_cmd.first);
        }
        LOGW("Could not send/receive data to/from the PICC (controller transmission failed).");
        return error::controller_error;
    }

    tag::r<> tag::authenticate(const any_key &k) {
        static constexpr cipher::config cfc_plain_nomac{
            .mode = comm_mode::plain,
            .do_mac = false,
            .do_cipher = false,
            .do_crc = false
        };
        static constexpr cipher::config cfg_crypto_nocrc{
            .mode = comm_mode::cipher,
            .do_mac = false,
            .do_cipher = true,
            .do_crc = false
        };

        /// Clear preexisting authentication, check parms

        clear_authentication();
        if (k.type() == cipher_type::none) {
            return error::parameter_error;
        }

        /// Initialize a new cipher of the appropriate type for the key exchange protocol
        auto pcipher = k.make_cipher();

        /// Send the right authentication command for the key type and the key number, get RndB
        bin_data payload = bin_data::chain(prealloc(2), auth_command(k.type()), k.key_number());
        LOGI("Authentication with key %d: initiating.", k.key_number());

        // The authentication is sent in plain test, but we receive it as encrypted data without CRC.
        const auto res_rndb = command_response(payload, 0, *pcipher, cfc_plain_nomac, cfg_crypto_nocrc, true, false);

        if (not res_rndb) {
            LOGW("Authentication: failed.");
            return res_rndb.error();
        } else {
            LOGI("Authentication: received RndB (%ul bytes).", res_rndb->size());
        }

        /// Prepare and send a response: AdditionalFrames || Crypt(RndA || RndB'), RndB' = RndB << 8, obtain RndA >> 8
        const bin_data rnda = bin_data::chain(randbytes(res_rndb->size()));

        payload.clear();
        payload.reserve(res_rndb->size() * 2 + 1);
        payload << command_code::additional_frame
                << rnda
                << res_rndb->view(1) << res_rndb->front();

        LOGI("Authentication: sending RndA || (RndB << 8).");

        // Send and received encrypted, except the status byte
        const auto res_rndap = command_response(payload, 1, *pcipher, cfg_crypto_nocrc, cfg_crypto_nocrc, true, false);

        if (not res_rndap) {
            LOGW("Authentication: failed.");
            return res_rndap.error();
        } else {
            LOGI("Authentication: received RndA >> 8 (%ul bytes).", res_rndap->size());
        }

        /// Verify that the received RndA is correct.
        if (rnda.size() != res_rndap->size()) {
            LOGW("Authentication: RndA mismatch size.");
            return error::crypto_error;
        }
        // This is just a test for equality when shifted
        if (not std::equal(std::begin(rnda) + 1, std::end(rnda), std::begin(*res_rndap))
            or rnda.front() != res_rndap->back())
        {
            LOGW("Authentication: RndA mismatch.");
            ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " RndA orig", rnda.data(), rnda.size(), ESP_LOG_WARN);
            ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " RndA >> 8", res_rndap->data(), res_rndap->size(), ESP_LOG_WARN);
            return error::crypto_error;
        }

        LOGI("Authentication: successful. Deriving session key.");
        pcipher->reinit_with_session_key(bin_data::chain(prealloc(2 * res_rndb->size()), rnda, *res_rndb));

        _active_cipher = std::move(pcipher);
        _active_cipher_type = k.type();
        _active_key_number = k.key_number();

        return result_success;
    }

    tag::r<bin_data> tag::command_response(bin_data &payload, std::size_t secure_data_offset, cipher &cipher,
                                           cipher::config const &tx_cfg, cipher::config const &rx_cfg,
                                           bool strip_status_byte, bool handle_additional_frames)
    {
        cipher.prepare_tx(payload, secure_data_offset, tx_cfg);
        bin_data received{};

        do {
            const auto res = raw_command_response(payload, false);
            if (not res) {
                return res.error();
            }
            if (res.empty()) {
                LOGE("Received empty payload from card.");
                return error::malformed;
            }
            // Append data, move status byte at the end
            received.reserve(received.size() + res->size());
            received << res->view(1) << res->front();
            // Check status byte if necessary
            if (handle_additional_frames) {
                const auto sb = static_cast<status>(received.back());
                if (sb == status::additional_frame) {
                    // The "more frames" status is not part of the payload
                    received.pop_back();
                    if (received.size() == res->size()) {
                        // Only one payload was received, clear and insert a single byte asking for more frames
                        payload.clear();
                        payload << command_code::additional_frame;
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
                LOGW("Invalid data received under comm mode %s, (C)MAC: %d, CRC: %d, cipher: %d.",
                     to_string(rx_cfg.mode), rx_cfg.do_mac, rx_cfg.do_crc, rx_cfg.do_cipher);
                ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG, received.data(), received.size(), ESP_LOG_WARN);
                return error::crypto_error;
            }
            if (strip_status_byte) {
                received.pop_back();
            }
            LOGD("Response received successfully.");
            return received;
        }
        LOGW("Unsuccessful command (%s); the response contains %ul bytes.", to_string(sb), received.size());
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG, received.data(), received.size(), ESP_LOG_WARN);
        // Status are also error codes
        return error_from_status(sb);
    }

}
