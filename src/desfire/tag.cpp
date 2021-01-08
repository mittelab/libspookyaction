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

    void tag::logout() {
        /// @todo Actually deauth
        _active_cipher = std::unique_ptr<cipher>(new cipher_dummy{});
        _active_cipher_type = cipher_type::none;
        _active_key_number = std::numeric_limits<std::uint8_t>::max();
    }

    tag::r<bin_data> tag::raw_command_response(bin_data const &payload) {
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " >>", payload.data(), payload.size(), ESP_LOG_VERBOSE);
        auto res_cmd = ctrl().communicate(payload);
        if (res_cmd.second) {
            ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " <<", res_cmd.first.data(), res_cmd.first.size(),
                                     ESP_LOG_VERBOSE);
            return std::move(res_cmd.first);
        }
        DESFIRE_LOGW("Could not send/receive data to/from the PICC (controller transmission failed).");
        return error::controller_error;
    }

    tag::r<> tag::select_application(app_id const &app) {
        const auto res_cmd =  command_response(command_code::select_application, bin_data::chain(app), comm_mode::plain);
        if (res_cmd) {
            _active_app = app;
        }
        return res_cmd;
    }

    tag::r<> tag::authenticate(const any_key &k) {
        /// Clear preexisting authentication, check parms
        logout();
        if (k.type() == cipher_type::none) {
            return error::parameter_error;
        }

        /// Initialize a new cipher of the appropriate type for the key exchange protocol and the relative comm modes
        auto pcipher = k.make_cipher();
        const comm_cfg cfg_txrx_cipher_nocrc{cipher_cfg_crypto_nocrc, 1, false, pcipher.get()};

        /// Send the right authentication command for the key type and the key number, get RndB
        DESFIRE_LOGD("Authentication with key %u: sending auth command.", k.key_number());

        // The authentication is all plain, but we receive it as encrypted data without CRC. Just set everything to
        // crypto without CRC and the offset beyond the payload.
        // Also, do not parse the status into an error, because this packet will have an "additional frame" status,
        // which we need to handle in a custom way (sending our own payload). We will later assess and return if the
        // returned status is not "additional frame".
        const auto res_rndb = command_status_response(
                auth_command(k.type()),
                bin_data::chain(k.key_number()),
                cfg_txrx_cipher_nocrc,
                2  // After auth command and payload, i.e. no encryption is performed in TX
        );

        if (not res_rndb) {
            // This is a controller error because we did not look at the status byte
            DESFIRE_LOGW("Authentication with key %u: failed, %s.", k.key_number(), to_string(res_rndb.error()));
            return res_rndb.error();
        } else if (res_rndb->first != status::additional_frame) {
            // Our own checking that the frame is as expected
            DESFIRE_LOGW("Authentication with key %u: failed, %s.", k.key_number(), to_string(res_rndb->first));
            return error_from_status(res_rndb->first);
        }
        bin_data const &rndb = res_rndb->second;
        DESFIRE_LOGD("Authentication with key %u: received RndB (%u bytes).", k.key_number(), rndb.size());

        /// Prepare and send a response: AdditionalFrames || Crypt(RndA || RndB'), RndB' = RndB << 8, obtain RndA >> 8
        const bin_data rnda = bin_data::chain(randbytes(rndb.size()));

        DESFIRE_LOGD("Authentication: sending RndA || (RndB << 8).");
        // Send and received encrypted; this time parse the status byte because we regularly expect a status::ok.
        const auto res_rndap = command_response(
                command_code::additional_frame,
                bin_data::chain(prealloc(rnda.size() * 2), rnda, rndb.view(1), rndb.front()),
                cfg_txrx_cipher_nocrc
        );

        if (not res_rndap) {
            DESFIRE_LOGW("Authentication with key %u: failed (%s).", k.key_number(), to_string(res_rndap.error()));
            return res_rndap.error();
        }
        DESFIRE_LOGD("Authentication with key %u: received RndA >> 8 (%u bytes).", k.key_number(), res_rndap->size());

        /// Verify that the received RndA is correct.
        if (rnda.size() != res_rndap->size()) {
            DESFIRE_LOGW("Authentication with key %u: RndA mismatch size.", k.key_number());
            return error::crypto_error;
        }
        // This is just a test for equality when shifted
        if (not std::equal(std::begin(rnda) + 1, std::end(rnda), std::begin(*res_rndap))
            or rnda.front() != res_rndap->back())
        {
            DESFIRE_LOGW("Authentication with key %u: RndA mismatch.", k.key_number());
            ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " RndA orig", rnda.data(), rnda.size(), ESP_LOG_WARN);
            ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " RndA >> 8", res_rndap->data(), res_rndap->size(), ESP_LOG_WARN);
            return error::crypto_error;
        }

        DESFIRE_LOGD("Authentication with key %u: deriving session key...", k.key_number());
        pcipher->reinit_with_session_key(bin_data::chain(prealloc(2 * rndb.size()), rnda, rndb));
        DESFIRE_LOGI("Authentication with key %u: successful.", k.key_number());

        _active_cipher = std::move(pcipher);
        _active_cipher_type = k.type();
        _active_key_number = k.key_number();

        return result_success;
    }

    tag::r<status, bin_data> tag::command_status_response(bin_data &payload, tag::comm_cfg const &cfg) {
        if (_active_cipher == nullptr and cfg.override_cipher == nullptr) {
            DESFIRE_LOGE("No active cipher and no override cipher: 'tag' was put in an invalid state. This is a coding "
                         "mistake.");
            return error::crypto_error;
        }
        DESFIRE_LOGD("TX mode: %s, (C)MAC: %d, CRC: %d, cipher: %d, ofs: %u/%u", to_string(cfg.tx.mode), cfg.tx.do_mac,
                     cfg.tx.do_crc, cfg.tx.do_cipher, cfg.tx_secure_data_offset, payload.size());
        DESFIRE_LOGD("RX mode: %s, (C)MAC: %d, CRC: %d, cipher: %d, additional frames: %u", to_string(cfg.rx.mode),
                     cfg.rx.do_mac, cfg.rx.do_crc, cfg.rx.do_cipher, cfg.rx_auto_fetch_additional_frames);
        // Select the cipher
        cipher &c = cfg.override_cipher == nullptr ? *_active_cipher : *cfg.override_cipher;
        bin_data received{};
        bool additional_frames = cfg.rx_auto_fetch_additional_frames;

        c.prepare_tx(payload, cfg.tx_secure_data_offset, cfg.tx);

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
            if (additional_frames) {
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
                    additional_frames = false;
                }
            }
        } while (additional_frames);

        // Can postprocess using crypto
        if (not c.confirm_rx(received, cfg.rx)) {
            DESFIRE_LOGW("Invalid data received (see debug log for furhter information):");
            ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG, received.data(), received.size(), ESP_LOG_WARN);
            return error::crypto_error;
        }

        // Now status byte is at the end. Check for possible errors
        const auto sb = static_cast<status>(received.back());
        received.pop_back();
        DESFIRE_LOGD("Response received, %u bytes excluded status (%s).", received.size(), to_string(sb));
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG, received.data(), received.size(), ESP_LOG_DEBUG);

        return {sb, std::move(received)};
    }

    tag::r<status, bin_data> tag::command_status_response(
            command_code cmd, bin_data const &payload, tag::comm_cfg const &base_cfg,
            std::size_t secure_offset,
            bool fetch_additional_frames)
    {
        static bin_data buffer{};
        buffer.clear();
        buffer.reserve(payload.size() + 1);
        // Add the command
        buffer << cmd << payload;

        // Override the config
        const comm_cfg cmd_comm_cfg = base_cfg.with(secure_offset, fetch_additional_frames);
        DESFIRE_LOGD("%s: sending command.", to_string(cmd));
        return command_status_response(buffer, cmd_comm_cfg);
    }

    tag::r<bin_data> tag::command_response(
            command_code cmd, const bin_data &payload, const tag::comm_cfg &base_cfg, std::size_t secure_offset)
    {
        auto res_cmd = command_status_response(cmd, payload, base_cfg, secure_offset, true);
        if (not res_cmd) {
            return res_cmd.error();
        }
        // Actually parse the status byte into an error code
        if (res_cmd->first == status::ok or res_cmd->first == status::no_changes) {
            return std::move(res_cmd->second);
        }
        DESFIRE_LOGW("%s: unsuccessful (%s); the response contains %u bytes.", to_string(cmd),
                     to_string(res_cmd->first), res_cmd->second.size());
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG, res_cmd->second.data(), res_cmd->second.size(), ESP_LOG_WARN);
        // Status are also error codes
        return error_from_status(res_cmd->first);
    }

    tag::r<key_settings> tag::get_key_settings() {
        return command_parse_response<key_settings>(command_code::get_key_settings, bin_data{}, comm_mode::plain);
    }

    tag::r<std::uint8_t> tag::get_key_version(std::uint8_t key_num) {
        if (key_num >= bits::max_keys_per_app) {
            DESFIRE_LOGE("%s: invalid key num %u (max %u).", to_string(command_code::get_key_version), key_num, bits::max_keys_per_app);
            return error::parameter_error;
        }
        return command_parse_response<std::uint8_t>(command_code::get_key_version, bin_data::chain(key_num),
                                                    comm_mode::plain);
    }

    tag::r<> tag::create_application(app_id const &new_app_id, key_settings settings) {
        if (settings.max_num_keys == 0 or settings.max_num_keys > bits::max_keys_per_app) {
            DESFIRE_LOGW("%s: attempt to create an app with a maximum number of keys of %u, will be clamped in the "
                         "range 1..%u.", to_string(command_code::create_application), settings.max_num_keys,
                         bits::max_keys_per_app);
            settings.max_num_keys = std::min(std::max(settings.max_num_keys, std::uint8_t(1)), bits::max_keys_per_app);
        }
        if (settings.rights.allowed_to_change_keys == no_key and not settings.rights.config_changeable) {
            DESFIRE_LOGW("%s: attempt to create an app where keys and settings cannot be changed; this is probably a "
                         "mistake.", to_string(command_code::create_application));
        }
        return command_response(command_code::create_application,
                                bin_data::chain(prealloc(5), new_app_id, settings),
                                comm_mode::plain);
    }

    tag::r<> tag::change_key_settings(key_rights new_rights) {
        if (active_app() == root_app) {
            if (new_rights.allowed_to_change_keys != 0) {
                DESFIRE_LOGW("%s: only the unique master key can have the right to change keys in the root app.",
                             to_string(command_code::change_key_settings));
                new_rights.allowed_to_change_keys = 0;
            }
        }
        if (active_cipher_type() == cipher_type::none) {
            DESFIRE_LOGW("%s: not authenticated, likely to fail.", to_string(command_code::change_key_settings));
        }
        return command_response(command_code::change_key_settings,
                                bin_data::chain(new_rights),
                                {cipher_cfg_crypto, cipher_cfg_plain});
    }

    tag::r<> tag::delete_application(app_id const &app) {
        return command_response(command_code::delete_application,
                                bin_data::chain(app),
                                comm_mode::plain);
    }

    tag::r<std::vector<app_id>> tag::get_application_ids() {
        return command_parse_response<std::vector<app_id>>(command_code::get_application_ids, {}, comm_mode::plain);
    }

    tag::r<> tag::format_picc() {
        return command_response(command_code::format_picc, bin_data{}, comm_mode::plain);
    }

}
