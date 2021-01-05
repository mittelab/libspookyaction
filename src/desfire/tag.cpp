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

    void tag::debug_next_raw_exchange(tag::comm_override next_comm) {
        _debug_raw_overrides.push_back(std::move(next_comm));
    }
    void tag::debug_next_plain_exchange(tag::comm_override next_comm) {
        _debug_plain_overrides.push_back(std::move(next_comm));
    }

    void tag::clear_authentication() {
        if (_active_cipher != nullptr) {
            DESFIRE_LOGI("Releasing authentication.");
        }
        _active_cipher = std::unique_ptr<cipher>(new cipher_dummy{});
        _active_cipher_type = cipher_type::none;
        _active_key_number = std::numeric_limits<std::uint8_t>::max();
    }

    tag::r<bin_data> tag::raw_command_response(bin_data const &payload) {
        if (_debug_raw_overrides.empty()) {
            ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " >>", payload.data(), payload.size(), ESP_LOG_VERBOSE);
            auto res_cmd = ctrl().communicate(payload);
            if (res_cmd.second) {
                ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " <<", res_cmd.first.data(), res_cmd.first.size(),
                                         ESP_LOG_VERBOSE);
                return std::move(res_cmd.first);
            }
            DESFIRE_LOGW("Could not send/receive data to/from the PICC (controller transmission failed).");
            return error::controller_error;
        } else {
            /**
             * @note This code is purely for debugging purposes.
             * @{
             */
            comm_override override = std::move(_debug_raw_overrides.front());
            _debug_raw_overrides.pop_front();

            ESP_LOGI(DESFIRE_TAG " RAW OVERRIDE", "Override: an override is in place for this command.");
            if (override.check_tx) {
                if (payload == override.tx) {
                    ESP_LOGI(DESFIRE_TAG " RAW OVERRIDE", "The command begin sent is the same as the expected one.");
                } else {
                    ++_debug_overrides_failed_checks;
                    ESP_LOGW(DESFIRE_TAG " RAW OVERRIDE", "The command begin sent differs from the expected one.");
                    ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " RAW OVERRIDE EXPECTED", override.tx.data(), override.tx.size(),
                                             ESP_LOG_WARN);
                    ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " RAW OVERRIDE ACTUAL  ", payload.data(), payload.size(),
                                             ESP_LOG_WARN);
                }
            }
            ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " >>", override.tx.data(), override.tx.size(), ESP_LOG_VERBOSE);
            if (override.actually_transceive) {
                auto res_cmd = ctrl().communicate(override.tx);
                if (res_cmd.second) {
                    ESP_LOGI(DESFIRE_TAG " RAW OVERRIDE", "Communication successful.");
                    if (override.check_rx) {
                        if (res_cmd.first == override.rx) {
                            ESP_LOGI(DESFIRE_TAG " RAW OVERRIDE", "The response received is the same as the expected one.");
                        } else {
                            ++_debug_overrides_failed_checks;
                            ESP_LOGW(DESFIRE_TAG " RAW OVERRIDE", "The response received differs from the expected one.");
                            ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " RAW OVERRIDE EXPECTED", override.rx.data(),
                                                     override.rx.size(), ESP_LOG_WARN);
                            ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " RAW OVERRIDE ACTUAL  ", res_cmd.first.data(),
                                                     res_cmd.first.size(), ESP_LOG_WARN);
                        }
                    }
                } else {
                    ESP_LOGE(DESFIRE_TAG " RAW OVERRIDE", "Communication failed.");
                }
            } else {
                ESP_LOGI(DESFIRE_TAG " RAW OVERRIDE", "Skipping communication.");
            }
            ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " <<", override.rx.data(), override.rx.size(), ESP_LOG_VERBOSE);
            return std::move(override.rx);
            /**
             * @}
             */
        }
    }

    tag::r<> tag::select_application(std::array<std::uint8_t, 3> const &aid) {
        bin_data payload = bin_data::chain(prealloc(4), command_code::select_application, aid);
        const auto res = command_response(payload, active_cipher(), cipher_cfg_plain, cipher_cfg_plain, 0, false);
        if (res) {
            if (not res->empty()) {
                DESFIRE_LOGW("Select application: got stray data.");
                ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG, res->data(), res->size(), ESP_LOG_WARN);
            }
            return result_success;
        }
        return res.error();
    }

    tag::r<> tag::authenticate(const any_key &k) {
        /// Clear preexisting authentication, check parms

        clear_authentication();
        if (k.type() == cipher_type::none) {
            return error::parameter_error;
        }

        /// Initialize a new cipher of the appropriate type for the key exchange protocol
        auto pcipher = k.make_cipher();

        /// Immediately switch also legacy ciphers to global IV mode: this whole exchange uses one IV
        iv_session session{*pcipher, cipher_iv::global};

        /// Send the right authentication command for the key type and the key number, get RndB
        bin_data payload = bin_data::chain(prealloc(2), auth_command(k.type()), k.key_number());
        DESFIRE_LOGI("Authentication with key %d: initiating.", k.key_number());

        // The authentication is sent in plain test, but we receive it as encrypted data without CRC.
        // Also, do not parse the status into an error, because this packet will have an "additional frame" status,
        // which we need to handle in a custom way (sending our own payload). We will later assess and return if the
        // returned status is not "additional frame".
        const auto res_rndb = command_status_response(payload, *pcipher, cipher_cfg_plain, cipher_cfg_crypto_nocrc, 0, false);

        if (not res_rndb) {
            // This is a controller error because we did not look at the status byte
            DESFIRE_LOGW("Authentication: failed, %s.", to_string(res_rndb.error()));
            return res_rndb.error();
        } else if (res_rndb->first != status::additional_frame) {
            // Our own checking that the frame is as expected
            DESFIRE_LOGW("Authentication: failed, %s.", to_string(res_rndb->first));
            return error_from_status(res_rndb->first);
        }
        bin_data const &rndb = res_rndb->second;
        DESFIRE_LOGI("Authentication: received RndB (%u bytes).", rndb.size());

        /// Prepare and send a response: AdditionalFrames || Crypt(RndA || RndB'), RndB' = RndB << 8, obtain RndA >> 8
        const bin_data rnda = bin_data::chain(randbytes(rndb.size()));

        payload.clear();
        payload.reserve(rndb.size() * 2 + 1);
        payload << command_code::additional_frame
                << rnda
                << rndb.view(1) << rndb.front();

        DESFIRE_LOGI("Authentication: sending RndA || (RndB << 8).");

        // Send and received encrypted; this time parse the status byte because we regularly expect a status::ok.
        const auto res_rndap = command_response(payload, *pcipher, cipher_cfg_crypto_nocrc, cipher_cfg_crypto_nocrc, 1, false);

        if (not res_rndap) {
            DESFIRE_LOGW("Authentication: failed.");
            return res_rndap.error();
        } else {
            DESFIRE_LOGI("Authentication: received RndA >> 8 (%u bytes).", res_rndap->size());
        }

        /// Verify that the received RndA is correct.
        if (rnda.size() != res_rndap->size()) {
            DESFIRE_LOGW("Authentication: RndA mismatch size.");
            return error::crypto_error;
        }
        // This is just a test for equality when shifted
        if (not std::equal(std::begin(rnda) + 1, std::end(rnda), std::begin(*res_rndap))
            or rnda.front() != res_rndap->back())
        {
            DESFIRE_LOGW("Authentication: RndA mismatch.");
            ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " RndA orig", rnda.data(), rnda.size(), ESP_LOG_WARN);
            ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " RndA >> 8", res_rndap->data(), res_rndap->size(), ESP_LOG_WARN);
            return error::crypto_error;
        }

        DESFIRE_LOGI("Authentication: successful. Deriving session key.");
        pcipher->reinit_with_session_key(bin_data::chain(prealloc(2 * rndb.size()), rnda, rndb));

        _active_cipher = std::move(pcipher);
        _active_cipher_type = k.type();
        _active_key_number = k.key_number();

        return result_success;
    }

    tag::r<status, bin_data> tag::command_status_response(bin_data &payload, cipher &cipher,
                                                cipher::config const &tx_cfg, cipher::config const &rx_cfg,
                                                std::size_t secure_data_offset, bool fetch_additional_frames)
    {
        std::unique_ptr<comm_override> override = nullptr;
        if (not _debug_plain_overrides.empty()) {
            override = std::unique_ptr<comm_override>(new comm_override{std::move(_debug_plain_overrides.front())});
            _debug_plain_overrides.pop_front();
        }

        if (override != nullptr) {
            /**
             * @note This code is purely for debugging purposes.
             * @{
             */
            ESP_LOGI(DESFIRE_TAG " OVERRIDE", "Override: an override is in place for this command.");
            if (override->check_tx) {
                if (payload == override->tx) {
                    ESP_LOGI(DESFIRE_TAG " OVERRIDE", "The command begin sent is the same as the expected one.");
                } else {
                    ++_debug_overrides_failed_checks;
                    ESP_LOGW(DESFIRE_TAG " OVERRIDE", "The command begin sent differs from the expected one.");
                    ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " OVERRIDE EXPECTED", override->tx.data(), override->tx.size(),
                                             ESP_LOG_WARN);
                    ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " OVERRIDE ACTUAL  ", payload.data(), payload.size(),
                                             ESP_LOG_WARN);
                }
            }

            payload.clear();
            payload.resize(override->tx.size(), 0x00);
            std::copy(std::begin(override->tx), std::end(override->tx), std::begin(payload));
            /**
             * @}
             */
        }

        cipher.prepare_tx(payload, secure_data_offset, tx_cfg);
        bin_data received{};

        if (override == nullptr or override->actually_transceive) {
            do {
                const auto res = raw_command_response(payload);
                if (not res) {
                    return res.error();
                }
                if (res->empty()) {
                    DESFIRE_LOGE("Received empty payload from card.");
                    return error::malformed;
                }
                // Append data, move status byte at the end
                received.reserve(received.size() + res->size());
                received << res->view(1) << res->front();
                // Check status byte if necessary
                if (fetch_additional_frames) {
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
                        fetch_additional_frames = false;
                    }
                }
            } while (fetch_additional_frames);

            // Can postprocess using crypto
            if (not cipher.confirm_rx(received, rx_cfg)) {
                DESFIRE_LOGW("Invalid data received under comm mode %s, (C)MAC: %d, CRC: %d, cipher: %d.",
                             to_string(rx_cfg.mode), rx_cfg.do_mac, rx_cfg.do_crc, rx_cfg.do_cipher);
                ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG, received.data(), received.size(), ESP_LOG_WARN);
                return error::crypto_error;
            }
        }

        if (override != nullptr) {
            /**
             * @note This code is purely for debugging purposes.
             * @{
             */
            if (override->check_rx) {
                if (received == override->rx) {
                    ESP_LOGI(DESFIRE_TAG " OVERRIDE", "The response received is the same as the expected one.");
                } else {
                    ++_debug_overrides_failed_checks;
                    ESP_LOGW(DESFIRE_TAG " OVERRIDE", "The response received differs from the expected one.");
                    ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " OVERRIDE EXPECTED", override->rx.data(), override->rx.size(),
                                             ESP_LOG_WARN);
                    ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " OVERRIDE ACTUAL  ", received.data(), received.size(),
                                             ESP_LOG_WARN);
                }
            }

            received.clear();
            received.resize(override->rx.size(), 0x00);
            std::copy(std::begin(override->rx), std::end(override->rx), std::begin(received));
            /**
             * @}
             */
        }

        // Now status byte is at the end. Check for possible errors
        const auto sb = static_cast<status>(received.back());
        received.pop_back();
        DESFIRE_LOGD("Response received, %u bytes excluded status (%s).", received.size(), to_string(sb));
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG, received.data(), received.size(), ESP_LOG_DEBUG);

        return {sb, std::move(received)};
    }

    tag::r<bin_data> tag::command_response(bin_data &payload, cipher &cipher,
                                 cipher::config const &tx_cfg, cipher::config const &rx_cfg,
                                 std::size_t secure_data_offset, bool fetch_additional_frames)
    {
        auto res_cmd = command_status_response(payload, cipher, tx_cfg, rx_cfg, secure_data_offset,
                                               fetch_additional_frames);
        if (not res_cmd) {
            return res_cmd.error();
        }
        // Actually parse the status byte into an error code
        if (res_cmd->first == status::ok or res_cmd->first == status::no_changes) {
            return std::move(res_cmd->second);
        }
        DESFIRE_LOGW("Command was unsuccessful (%s); the response contains %u bytes.", to_string(res_cmd->first),
                     res_cmd->second.size());
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG, res_cmd->second.data(), res_cmd->second.size(), ESP_LOG_WARN);
        // Status are also error codes
        return error_from_status(res_cmd->first);
    }

}
