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

    struct lsb_uint24 {
        std::uint32_t n;
    };
}

namespace mlab {
    bin_stream &operator>>(bin_stream &s, desfire::lsb_uint24 &n) {
        return s >> lsb24 >> n.n;
    }
}

namespace desfire {

    namespace {

        using mlab::prealloc;
        using mlab::result_success;
        using mlab::lsb16;
        using mlab::lsb24;

        template <class T, class = typename std::enable_if<std::is_unsigned<T>::value>::type>
        T saturate_sub(T a, T b) {
            return std::max(a, b) - b;
        }

        namespace impl {
            template<class> struct larger_signed {};
            template <> struct larger_signed<unsigned int> {
                using type = long;
            };
        }

        template <class T>
        T div_round_up(T n, T divisor) {
            using larger_signed = typename impl::larger_signed<T>::type;
            const auto div_result = std::div(larger_signed(n), larger_signed(divisor));
            return T(div_result.quot) + (div_result.rem == 0 ? 0 : 1);
        }
    }

    tag::r<> tag::safe_drop_payload(command_code cmd, tag::r<bin_data> const &result) {
        if (result) {
            if (not result->empty()) {
                tag::log_not_empty(cmd, result->view());
            }
            return result_success;
        }
        return result.error();
    }

    void tag::log_not_empty(command_code cmd, range<bin_data::const_iterator> const &data) {
        DESFIRE_LOGW("%s: stray data (%d bytes) in response.", to_string(cmd), data.size());
        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG, data.data(), data.size(), ESP_LOG_DEBUG);
    }


    struct tag::auto_logout {
        tag &owner;
        bool assume_success;

        ~auto_logout() {
            if (not assume_success) {
                owner.logout(true);
            }
        }
    };

    tag::comm_cfg const &tag::cipher_default() const {
        if (active_cipher_type() == cipher_type::none or cipher::is_legacy(active_cipher_type())) {
            static const comm_cfg _legacy_plain{cipher_mode::plain};
            return _legacy_plain;
        } else {
            static const comm_cfg _plain_tx_mac_rx{cipher_mode::plain, cipher_mode::maced};
            return _plain_tx_mac_rx;
        }
    }

    void tag::logout(bool due_to_error) {
        if (due_to_error and active_cipher_type() != cipher_type::none) {
            DESFIRE_LOGE("Authentication will have to be performed again.");
        }
        _active_cipher = std::unique_ptr<cipher>(new cipher_dummy{});
        _active_cipher_type = cipher_type::none;
        _active_key_number = std::numeric_limits<std::uint8_t>::max();
    }

    tag::r<bin_data> tag::raw_command_response(bin_stream &tx_data, bool rx_fetch_additional_frames) {
        static constexpr auto chunk_size = bits::max_packet_length;
        static bin_data tx_chunk{prealloc(chunk_size)};
        const auto num_tx_chunks = 1 + div_round_up(saturate_sub(tx_data.remaining(), chunk_size), chunk_size - 1);

        tx_chunk.clear();
        status last_status = status::additional_frame;
        bin_data rx_data;

        for (std::size_t chunk_idx = 0; last_status == status::additional_frame; ++chunk_idx, tx_chunk.clear()) {
            assert(tx_chunk.empty());
            // Prepare packet to send: DATA for the first, AF + DATA afterwards.
            if (chunk_idx == 0) {
                tx_chunk << tx_data.read(std::min(tx_data.remaining(), chunk_size));
            } else {
                tx_chunk << command_code::additional_frame << tx_data.read(std::min(tx_data.remaining(), chunk_size - 1));
            }
            if (chunk_idx < num_tx_chunks) {
                DESFIRE_LOGD("Exchanging chunk %d (command data %d/%d).", chunk_idx + 1, chunk_idx + 1, num_tx_chunks);
            } else {
                DESFIRE_LOGD("Exchanging chunk %d (additional response frame).", chunk_idx + 1);
                assert(tx_data.eof());
            }

            // Actual transmission
            ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " RAW >>", tx_chunk.data(), tx_chunk.size(), ESP_LOG_DEBUG);
            const auto rx_data_success = ctrl().communicate(tx_chunk);
            if (not rx_data_success.second) {
                return error::controller_error;
            }
            bin_data const &rx_chunk = rx_data_success.first;
            ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " RAW <<", rx_chunk.data(), rx_chunk.size(), ESP_LOG_DEBUG);

            // Make sure there was an actual response
            if (rx_chunk.empty()) {
                DESFIRE_LOGE("PICC sent an empty answer.");
                return error::malformed;
            }

            // Collect data. The status byte will only be appended later, for now we store it
            rx_data << prealloc(rx_chunk.size()) << rx_chunk.view(1);
            last_status = static_cast<status>(rx_chunk.front());

            // If tx_data is done and we do not fetch additional frames, we abort the loop no matter what the status is
            if (tx_data.eof() and not rx_fetch_additional_frames) {
                break;
            }
        }

        // The card may have aborted early
        if (not tx_data.eof()) {
            DESFIRE_LOGE("The card interrupted the transmission with status %s", to_string(last_status));
            return error::malformed;
        }

        // Reappend status byte
        rx_data << last_status;

        return std::move(rx_data);
    }

    tag::r<status, bin_data> tag::command_status_response(command_code cmd, bin_data const &data, comm_cfg const &cfg, cipher *override_cipher)
    {
        if (_active_cipher == nullptr and override_cipher == nullptr) {
            DESFIRE_LOGE("No active cipher and no override cipher: 'tag' is in an invalid state (coding mistake).");
            return error::crypto_error;
        }
        DESFIRE_LOGD("%s: TX mode: %s, ofs: %u", to_string(cmd),
                     to_string(cfg.tx), cfg.tx_secure_data_offset);
        DESFIRE_LOGD("%s: RX mode: %s, fetch AF: %u", to_string(cmd),
                     to_string(cfg.rx), cfg.rx_auto_fetch_additional_frames);

        // If we exit prematurely, and we are using the cipher of this tag, trigger a logout by error.
        auto_logout logout_on_error{*this, override_cipher != nullptr};

        // Select the right cipher and prepare the buffers
        cipher &c = override_cipher == nullptr ? *_active_cipher : *override_cipher;

        // Assemble data to transmit and preprocess
        static bin_data tx_data;
        tx_data.clear();
        tx_data << prealloc(data.size() + 1) << cmd << data;

        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " >>", tx_data.data(), tx_data.size(), ESP_LOG_DEBUG);

        c.prepare_tx(tx_data, cfg.tx_secure_data_offset, cfg.tx);

        bin_stream tx_stream{tx_data};
        auto res_cmd = raw_command_response(tx_stream, cfg.rx_auto_fetch_additional_frames);
        if (not res_cmd) {
            DESFIRE_LOGE("%s: failed, %s", to_string(cmd), to_string(res_cmd.error()));
            return res_cmd.error();
        }

        bin_data &rx_data = *res_cmd;

        // Postprocessing requires to know the status byte
        if (not c.confirm_rx(rx_data, cfg.rx)) {
            DESFIRE_LOGE("%s: failed, received data did not pass validation.", to_string(cmd));
            return error::crypto_error;
        }
        assert(not rx_data.empty());

        ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " <<", rx_data.data(), rx_data.size(), ESP_LOG_DEBUG);

        // Extract status byte
        const auto cmd_status = static_cast<status>(rx_data.back());
        rx_data.pop_back();

        DESFIRE_LOGD("%s: completed with status %s", to_string(cmd), to_string(cmd_status));

        // Passthrough the status byte, the caller decides if that is an error.
        logout_on_error.assume_success = true;
        return {cmd_status, std::move(rx_data)};
    }

    tag::r<bin_data> tag::command_response(command_code cmd, const bin_data &payload, const tag::comm_cfg &cfg, cipher *override_cipher)
    {
        auto_logout logout_on_error{*this, override_cipher != nullptr};

        auto res_status_cmd = command_status_response(cmd, payload, cfg, override_cipher);
        if (not res_status_cmd) {
            return res_status_cmd.error();
        }

        // Check the returned status. This is the only error condition handled by this method
        const auto cmd_status = res_status_cmd->first;
        if (cmd_status != status::ok and cmd_status != status::no_changes) {
            DESFIRE_LOGE("%s: failed with status %s.", to_string(cmd), to_string(cmd_status));
            return error_from_status(cmd_status);
        }

        logout_on_error.assume_success = true;
        return std::move(res_status_cmd->second);
    }

    tag::r<> tag::select_application(app_id const &app) {
        /**
         * @bug Test if it has to be CMAC RX for modern ciphers
         */
        const auto res_cmd =  command_response(command_code::select_application, bin_data::chain(app), cipher_mode::plain);
        if (res_cmd) {
            DESFIRE_LOGD("Selected application %02x %02x %02x.", app[0], app[1], app[2]);
            logout(false);
            _active_app = app;
        }
        return safe_drop_payload(command_code::select_application, res_cmd);
    }

    tag::r<> tag::authenticate(const any_key &k) {
        /// Clear preexisting authentication, check parms
        logout(false);
        if (k.type() == cipher_type::none) {
            return error::parameter_error;
        }

        /// Initialize a new cipher of the appropriate type for the key exchange protocol and the relative comm modes
        auto pcipher = k.make_cipher();

        /// Send the right authentication command for the key type and the key number, get RndB
        DESFIRE_LOGD("Authentication with key %u (%s): sending auth command.", k.key_number(), to_string(k.type()));

        // Do not parse the status into an error, because this packet will have an "additional frame" status,
        // which we need to handle in a custom way (sending our own payload). We will later assess and return if the
        // returned status is not "additional frame".
        const auto res_rndb = command_status_response(
                auth_command(k.type()),
                bin_data::chain(k.key_number()),
                comm_cfg{cipher_mode::plain, cipher_mode::ciphered_no_crc},
                pcipher.get()
        );

        if (not res_rndb) {
            // This is a controller error because we did not look at the status byte
            DESFIRE_LOGW("Authentication with key %u (%s): failed, %s.", k.key_number(), to_string(k.type()), to_string(res_rndb.error()));
            return res_rndb.error();
        } else if (res_rndb->first != status::additional_frame) {
            // Our own checking that the frame is as expected
            DESFIRE_LOGW("Authentication with key %u (%s): failed, %s.", k.key_number(), to_string(k.type()), to_string(res_rndb->first));
            return error_from_status(res_rndb->first);
        }
        bin_data const &rndb = res_rndb->second;
        DESFIRE_LOGD("Authentication: received RndB (%u bytes).", rndb.size());

        /// Prepare and send a response: AdditionalFrames || Crypt(RndA || RndB'), RndB' = RndB << 8, obtain RndA >> 8
        const bin_data rnda = bin_data::chain(randbytes(rndb.size()));

        DESFIRE_LOGD("Authentication: sending RndA || (RndB << 8).");
        // Send and received encrypted; this time parse the status byte because we regularly expect a status::ok.
        const auto res_rndap = command_response(
                command_code::additional_frame,
                bin_data::chain(prealloc(rnda.size() * 2), rnda, rndb.view(1), rndb.front()),
                cipher_mode::ciphered_no_crc,
                pcipher.get()
        );

        if (not res_rndap) {
            DESFIRE_LOGW("Authentication with key %u (%s): failed (%s).", k.key_number(), to_string(k.type()), to_string(res_rndap.error()));
            return res_rndap.error();
        }
        DESFIRE_LOGD("Authentication: received RndA >> 8 (%u bytes).", res_rndap->size());

        /// Verify that the received RndA is correct.
        if (rnda.size() != res_rndap->size()) {
            DESFIRE_LOGW("Authentication with key %u (%s): RndA mismatch size.", k.key_number(), to_string(k.type()));
            return error::crypto_error;
        }
        // This is just a test for equality when shifted
        if (not std::equal(std::begin(rnda) + 1, std::end(rnda), std::begin(*res_rndap))
            or rnda.front() != res_rndap->back())
        {
            DESFIRE_LOGW("Authentication with key %u (%s): RndA mismatch.", k.key_number(), to_string(k.type()));
            ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " RndA orig", rnda.data(), rnda.size(), ESP_LOG_WARN);
            ESP_LOG_BUFFER_HEX_LEVEL(DESFIRE_TAG " RndA >> 8", res_rndap->data(), res_rndap->size(), ESP_LOG_WARN);
            return error::crypto_error;
        }

        DESFIRE_LOGD("Authentication: deriving session key...");
        pcipher->reinit_with_session_key(bin_data::chain(prealloc(2 * rndb.size()), rnda, rndb));
        DESFIRE_LOGD("Authenticated with key %u (%s).", k.key_number(), to_string(k.type()));

        _active_cipher = std::move(pcipher);
        _active_cipher_type = k.type();
        _active_key_number = k.key_number();

        return result_success;
    }

    tag::r<app_settings> tag::get_app_settings() {
        return command_parse_response<app_settings>(command_code::get_key_settings, bin_data{}, cipher_default());
    }

    tag::r<std::uint8_t> tag::get_key_version(std::uint8_t key_num) {
        if (key_num >= bits::max_keys_per_app) {
            DESFIRE_LOGE("%s: invalid key num %u (max %u).", to_string(command_code::get_key_version), key_num, bits::max_keys_per_app);
            return error::parameter_error;
        }
        return command_parse_response<std::uint8_t>(command_code::get_key_version, bin_data::chain(key_num),
                                                    cipher_default());
    }

    tag::r<> tag::create_application(app_id const &new_app_id, app_settings settings) {
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
        /**
         * @bug Test if it has to be CMAC RX for modern ciphers
         */
        return safe_drop_payload(command_code::create_application, command_response(
                command_code::create_application,
                bin_data::chain(prealloc(5), new_app_id, settings),
                cipher_mode::plain));
    }

    tag::r<> tag::change_app_settings(key_rights new_rights) {
        if (active_app() == root_app) {
            if (new_rights.allowed_to_change_keys != 0) {
                DESFIRE_LOGW("%s: only the unique master key can have the right to change keys in the root app.",
                             to_string(command_code::change_key_settings));
                new_rights.allowed_to_change_keys = 0;
            }
        }
        if (active_key_no() >= bits::max_keys_per_app) {
            DESFIRE_LOGW("%s: not authenticated, likely to fail.", to_string(command_code::change_key_settings));
        }
        return safe_drop_payload(command_code::change_key_settings, command_response(
                command_code::change_key_settings,
                bin_data::chain(new_rights),
                {cipher_mode::ciphered, cipher_default().rx}));
    }

    tag::r<> tag::delete_application(app_id const &app) {
        /**
         * @bug Test if it has to be CMAC RX for modern ciphers
         */
        return command_response(command_code::delete_application,
                                bin_data::chain(app),
                                cipher_mode::plain);
    }

    tag::r<std::vector<app_id>> tag::get_application_ids() {
        /**
         * @bug Test if it has to be CMAC RX for modern ciphers
         */
        return command_parse_response<std::vector<app_id>>(command_code::get_application_ids, {}, cipher_mode::plain);
    }

    tag::r<manufacturing_info> tag::get_info() {
        return command_parse_response<manufacturing_info>(command_code::get_version, bin_data{}, cipher_default());
    }

    tag::r<> tag::format_picc() {
        /**
         * @bug Test if it has to be CMAC RX for modern ciphers
         */
        const auto res_cmd = command_response(command_code::format_picc, bin_data{}, cipher_mode::plain);
        if (res_cmd) {
            logout(false);
            _active_app = root_app;
        }
        return safe_drop_payload(command_code::format_picc, res_cmd);
    }

    tag::r<> tag::change_key(any_key const &new_key)
    {
        if (active_key_no() >= bits::max_keys_per_app) {
            DESFIRE_LOGE("%s: not authenticated.", to_string(command_code::change_key));
            return error::authentication_error;
        }
        // Make sure that they are compatible. The root app makes exception
        if (active_app() != root_app and
            app_crypto_from_cipher(active_cipher_type()) != app_crypto_from_cipher(new_key.type()))
        {
            DESFIRE_LOGE("%s: cannot change a %s key into a %s key.", to_string(command_code::change_key),
                         to_string(active_cipher_type()), to_string(new_key.type()));
            return error::parameter_error;
        }
        return change_key_internal(nullptr, active_key_no(), new_key);
    }

    tag::r<> tag::change_key(any_key const &current_key, std::uint8_t key_no_to_change, any_key const &new_key)
    {
        if (key_no_to_change >= bits::max_keys_per_app) {
            DESFIRE_LOGE("%s: invalid key num %u (max %u).", to_string(command_code::change_key), key_no_to_change, bits::max_keys_per_app);
            return error::parameter_error;
        }
        // Make sure that the keys are compatible. The root app makes exception
        if (active_app() != root_app and
            app_crypto_from_cipher(current_key.type()) != app_crypto_from_cipher(new_key.type()))
        {
            DESFIRE_LOGE("%s: cannot change a key to %s, using a %s key.", to_string(command_code::change_key),
                         to_string(new_key.type()), to_string(current_key.type()));
            return error::parameter_error;
        }
        if (active_cipher_type() == cipher_type::none) {
            DESFIRE_LOGE("%s: not authenticated.", to_string(command_code::change_key));
            return error::authentication_error;
        }
        return change_key_internal(&current_key, key_no_to_change, new_key);
    }

    tag::r<> tag::change_key_internal(any_key const *current_key, std::uint8_t key_no_to_change, any_key const &new_key)
    {
        // Tweak the key number to allow change type of key on the root app (since cipher type must be set at creation).
        const std::uint8_t key_no_flag = (active_app() == root_app
                ? key_no_to_change | static_cast<std::uint8_t>(app_crypto_from_cipher(new_key.type()))
                : key_no_to_change);
        bin_data payload{prealloc(33)};
        payload << key_no_flag;
        // Changing from a different key requires to xor it with that other key
        if (current_key != nullptr) {
            payload << new_key.xored_with(*current_key);
        } else {
            payload << new_key;
        }


        // Now we need to compute CRCs, here we need to make distinction depending on legacy/non-legacy protocol.
        // There is no way to fit this business into the cipher model.
        if (cipher::is_legacy(active_cipher_type())) {
            // CRC on (maybe xored data). However, skip the key number
            payload << lsb16 << compute_crc16(payload.view(1));
            if (current_key != nullptr) {
                // Extra CRC on new key
                payload << lsb16 << compute_crc16(new_key.get_packed_key_body());
            }
        } else {
            // Precomputed CRC32 on the single command code byte
            static constexpr std::uint32_t crc32_init_with_chgkey = 0xb1f416db;
            static_assert(crc32_init == 0xffffffff and static_cast<std::uint8_t>(command_code::change_key) == 0xc4,
                          "If these conditions are not respected, the precomputed value above is wrong.");
            // CRC on command code, key number, (maybe xored data). Note that the command code is added by the
            // command_response method, so we precomputed a different init value that accounts for it.
            payload << lsb32 << compute_crc32(payload, crc32_init_with_chgkey);
            if (current_key != nullptr) {
                // Extra CRC on new key
                payload << lsb32 << compute_crc32(new_key.get_packed_key_body());
            }
        }

        const auto res_cmd =  command_response(
                command_code::change_key,
                payload,                     // command code and key number are not encrypted -vv
                comm_cfg{cipher_mode::ciphered_no_crc, cipher_mode::plain, 2}
        );
        if (res_cmd) {
            DESFIRE_LOGD("Key %d (%s) was changed.", new_key.key_number(), to_string(new_key.type()));
        } else {
            DESFIRE_LOGW("Could not change key %d (%s): %s.", new_key.key_number(), to_string(new_key.type()), to_string(res_cmd.error()));
        }
        return safe_drop_payload(command_code::change_key, res_cmd);
    }

    tag::r<std::vector<file_id>> tag::get_file_ids() {
        auto res_cmd = command_response(command_code::get_file_ids, {}, cipher_default());
        if (res_cmd) {
            return std::move(*res_cmd);
        }
        return res_cmd.error();
    }

    tag::r<any_file_settings> tag::get_file_settings(file_id fid) {
        return command_parse_response<any_file_settings>(
                command_code::get_file_settings, bin_data::chain(fid), cipher_default());
    }

    file_security tag::determine_file_security(file_access access, any_file_settings const &settings) const {
        // Send in plain mode if the specific operation is "free".
        if (settings.generic_settings().rights.is_free(access, active_key_no())) {
            return file_security::none;
        }
        return settings.generic_settings().security;
    }

    tag::r<file_security> tag::determine_file_security(file_id fid, file_access access) {
        const auto res_get_settings = get_file_settings(fid);
        if (not res_get_settings) {
            return res_get_settings.error();
        }
        return determine_file_security(access, *res_get_settings);
    }

    tag::r<> tag::change_file_settings(file_id fid, generic_file_settings const &settings) {
        const auto res_sec = determine_file_security(fid, file_access::change);
        if (not res_sec) {
            return res_sec.error();
        }
        return change_file_settings(fid, settings, *res_sec);
    }

    tag::r<> tag::change_file_settings(file_id fid, generic_file_settings const &settings, file_security security) {
        if (security == file_security::authenticated) {
            // We do not use MAC res_sec for this command, upgrade it
            security = file_security::encrypted;
        }
        const comm_cfg cfg{cipher_mode_from_security(security), 2 /* After command code and file id */};
        return safe_drop_payload(command_code::change_file_settings, command_response(
                command_code::change_file_settings,
                bin_data::chain(fid, settings),
                cfg
        ));
    }

    tag::r<bin_data> tag::read_data(file_id fid, std::uint32_t offset, std::uint32_t length) {
        const auto res_sec = determine_file_security(fid, file_access::read);
        if (not res_sec) {
            return res_sec.error();
        }
        return read_data(fid, offset, length, *res_sec);
    }

    tag::r<bin_data> tag::read_data(file_id fid, std::uint32_t offset, std::uint32_t length, file_security security) {
        if (fid > bits::max_backup_data_file_id or fid > bits::max_standard_data_file_id) {
            DESFIRE_LOGW("%s: invalid file id %d for data or backup file.", to_string(command_code::read_data), fid);
            return error::parameter_error;
        }
        if ((offset & 0xffffff) != offset) {
            DESFIRE_LOGW("%s: offset can be at most 24 bits, %d is an invalid value.",
                         to_string(command_code::read_data), offset);
            return error::parameter_error;
        }
        if ((length & 0xffffff) != length) {
            DESFIRE_LOGW("%s: length can be at most 24 bits, %d is an invalid value.",
                         to_string(command_code::read_data), length);
            return error::parameter_error;
        }
        // RX happens with the chosen file protection, except on nonlegacy ciphers where plain becomes maced
        const auto rx_cipher_mode = cipher_mode_most_secure(cipher_mode_from_security(security), cipher_default().rx);
        bin_data payload{prealloc(7)};
        payload << fid << lsb24 << offset << lsb24 << length;
        return command_response(command_code::read_data, payload, comm_cfg{cipher_default().tx, rx_cipher_mode});
    }

    tag::r<> tag::write_data(file_id fid, std::uint32_t offset, bin_data const &data) {
        const auto res_sec = determine_file_security(fid, file_access::write);
        if (not res_sec) {
            return res_sec.error();
        }
        return write_data(fid, offset, data, *res_sec);
    }

    tag::r<> tag::write_data(file_id fid, std::uint32_t offset, bin_data const &data, file_security security) {
        if (fid > bits::max_backup_data_file_id or fid > bits::max_standard_data_file_id) {
            DESFIRE_LOGW("%s: invalid file id %d for data or backup file.", to_string(command_code::write_data), fid);
            return error::parameter_error;
        }
        if ((offset & 0xffffff) != offset) {
            DESFIRE_LOGW("%s: offset can be at most 24 bits, %d is an invalid value.",
                         to_string(command_code::write_data), offset);
            return error::parameter_error;
        }
        if ((data.size() & 0xffffff) != data.size()) {
            DESFIRE_LOGW("%s: data size can be at most 24 bits, %d is an invalid value.",
                         to_string(command_code::write_data), data.size());
            return error::parameter_error;
        }
        const comm_cfg cfg{cipher_mode_from_security(security), cipher_default().rx,
                           8 /* secure with legacy MAC only data */};

        bin_data payload{prealloc(data.size() + 7)};
        payload << fid << lsb24 << offset << lsb24 << data.size() << data;

        return safe_drop_payload(command_code::write_data, command_response(command_code::write_data, payload, cfg));
    }


    tag::r<std::int32_t> tag::get_value(file_id fid) {
        const auto res_sec = determine_file_security(fid, file_access::read);
        if (not res_sec) {
            return res_sec.error();
        }
        return get_value(fid, *res_sec);
    }

    tag::r<std::int32_t> tag::get_value(file_id fid, file_security security) {
        if (fid > bits::max_value_file_id) {
            DESFIRE_LOGW("%s: invalid file id %d for a value file.", to_string(command_code::get_value), fid);
            return error::parameter_error;
        }
        // RX happens with the chosen file protection, except on nonlegacy ciphers where plain becomes maced
        const auto rx_cipher_mode = cipher_mode_most_secure(cipher_mode_from_security(security), cipher_default().rx);
        return command_parse_response<std::int32_t>(
                command_code::get_value,
                bin_data::chain(prealloc(1), fid),
                comm_cfg{cipher_default().tx, rx_cipher_mode});
    }

    tag::r<> tag::write_value(command_code cmd, file_id fid, std::int32_t amount, file_security security) {
        if (cmd != command_code::credit and cmd != command_code::debit and cmd != command_code::limited_credit) {
            DESFIRE_LOGE("write_value command used with invalid command code %s.", to_string(cmd));
            return error::parameter_error;
        }
        if (fid > bits::max_value_file_id) {
            DESFIRE_LOGW("%s: invalid file id %d for a value file.", to_string(cmd), fid);
            return error::parameter_error;
        }
        if (amount < 0) {
            return error::parameter_error;
        }
        const comm_cfg cfg{cipher_mode_from_security(security), cipher_default().rx, 2 /* after FID */};
        bin_data payload{prealloc(5)};
        payload << fid << lsb32 << amount;
        return safe_drop_payload(cmd, command_response(cmd, payload, cfg));
    }

    tag::r<> tag::credit(file_id fid, std::int32_t amount) {
        const auto res_sec = determine_file_security(fid, file_access::write);
        if (not res_sec) {
            return res_sec.error();
        }
        return write_value(command_code::credit, fid, amount, *res_sec);
    }

    tag::r<> tag::limited_credit(file_id fid, std::int32_t amount) {
        const auto res_sec = determine_file_security(fid, file_access::write);
        if (not res_sec) {
            return res_sec.error();
        }
        return write_value(command_code::limited_credit, fid, amount, *res_sec);
    }

    tag::r<> tag::debit(file_id fid, std::int32_t amount) {
        const auto res_sec = determine_file_security(fid, file_access::write);
        if (not res_sec) {
            return res_sec.error();
        }
        return write_value(command_code::debit,  fid, amount, *res_sec);
    }

    tag::r<> tag::credit(file_id fid, std::int32_t amount, file_security security) {
        return write_value(command_code::credit, fid, amount, security);
    }

    tag::r<> tag::limited_credit(file_id fid, std::int32_t amount, file_security security) {
        return write_value(command_code::limited_credit, fid, amount, security);
    }

    tag::r<> tag::debit(file_id fid, std::int32_t amount, file_security security) {
        return write_value(command_code::debit,  fid,amount, security);
    }

    tag::r<> tag::write_record(file_id fid, std::uint32_t offset, bin_data const &data) {
        const auto res_sec = determine_file_security(fid, file_access::write);
        if (not res_sec) {
            return res_sec.error();
        }
        return write_record(fid, offset, data, *res_sec);
    }

    tag::r<> tag::write_record(file_id fid, std::uint32_t offset, bin_data const &data, file_security security) {
        if (fid > bits::max_record_file_id) {
            DESFIRE_LOGW("%s: invalid file id %d for a record file.", to_string(command_code::write_record), fid);
            return error::parameter_error;
        }
        if ((offset & 0xffffff) != offset) {
            DESFIRE_LOGW("%s: offset can be at most 24 bits, %d is an invalid value.",
                         to_string(command_code::write_record), offset);
            return error::parameter_error;
        }
        if ((data.size() & 0xffffff) != data.size()) {
            DESFIRE_LOGW("%s: data size can be at most 24 bits, %d is an invalid value.",
                         to_string(command_code::write_record), data.size());
            return error::parameter_error;
        }
        const comm_cfg cfg{cipher_mode_from_security(security), cipher_default().rx,
                           8 /* secure with legacy MAC only data */};

        bin_data payload{prealloc(data.size() + 7)};
        payload << fid << lsb24 << offset << lsb24 << data.size() << data;

        return safe_drop_payload(command_code::write_record,
                                 command_response(command_code::write_record, payload, cfg));
    }

    tag::r<bin_data> tag::read_records(file_id fid, std::uint32_t record_index, std::uint32_t record_count) {
        const auto res_sec = determine_file_security(fid, file_access::write);
        if (not res_sec) {
            return res_sec.error();
        }
        return read_records(fid, record_index, record_count, *res_sec);
    }

    tag::r<bin_data> tag::read_records(file_id fid, std::uint32_t record_index, std::uint32_t record_count, file_security security) {
        if (fid > bits::max_record_file_id) {
            DESFIRE_LOGW("%s: invalid file id %d for a record file.", to_string(command_code::write_record), fid);
            return error::parameter_error;
        }
        if ((record_index & 0xffffff) != record_index) {
            DESFIRE_LOGW("%s: record index can be at most 24 bits, %d is an invalid value.",
                         to_string(command_code::read_records), record_index);
            return error::parameter_error;
        }
        if ((record_count & 0xffffff) != record_count) {
            DESFIRE_LOGW("%s: record count can be at most 24 bits, %d is an invalid value.",
                         to_string(command_code::read_records), record_count);
            return error::parameter_error;
        }
        // RX happens with the chosen file protection, except on nonlegacy ciphers where plain becomes maced
        const auto rx_cipher_mode = cipher_mode_most_secure(cipher_mode_from_security(security), cipher_default().rx);
        bin_data payload{prealloc(record_count + 7)};
        payload << fid << lsb24 << record_index << lsb24 << record_count;

        return command_response(command_code::read_records, payload, comm_cfg{cipher_default().tx, rx_cipher_mode});
    }


    tag::r<> tag::create_file(file_id fid, any_file_settings const &settings) {
        switch (settings.type()) {
            case file_type::standard:      return create_file(fid, settings.get<file_type::standard>());
            case file_type::backup:        return create_file(fid, settings.get<file_type::backup>());
            case file_type::value:         return create_file(fid, settings.get<file_type::value>());
            case file_type::linear_record: return create_file(fid, settings.get<file_type::linear_record>());
            case file_type::cyclic_record: return create_file(fid, settings.get<file_type::cyclic_record>());
            default:
                DESFIRE_LOGE("create_file: unhandled file type %s.", to_string(settings.type()));
                return error::parameter_error;
        }
    }

    tag::r<> tag::create_file(file_id fid, file_settings<file_type::standard> const &settings) {
        if (fid > bits::max_standard_data_file_id) {
            DESFIRE_LOGW("%s: invalid file id %d for a data file.", to_string(command_code::create_std_data_file), fid);
            return error::parameter_error;
        }
        return safe_drop_payload(command_code::create_std_data_file, command_response(
                command_code::create_std_data_file, bin_data::chain(fid, settings), cipher_default()));
    }

    tag::r<> tag::create_file(file_id fid, file_settings<file_type::backup> const &settings) {
        if (fid > bits::max_backup_data_file_id) {
            DESFIRE_LOGW("%s: invalid file id %d for a backup file.", to_string(command_code::create_backup_data_file), fid);
            return error::parameter_error;
        }
        return safe_drop_payload(command_code::create_backup_data_file, command_response(
                command_code::create_backup_data_file, bin_data::chain(fid, settings), cipher_default()));
    }

    tag::r<> tag::create_file(file_id fid, file_settings<file_type::value> const &settings) {
        if (fid > bits::max_value_file_id) {
            return error::parameter_error;
        }
        if (settings.upper_limit < settings.lower_limit) {
            return error::parameter_error;
        }
        return safe_drop_payload(command_code::create_value_file, command_response(
                command_code::create_value_file, bin_data::chain(fid, settings), cipher_default()));
    }

    tag::r<> tag::create_file(file_id fid, file_settings<file_type::linear_record> const &settings) {
        if (fid > bits::max_record_file_id) {
            DESFIRE_LOGW("%s: invalid file id %d for a record file.", to_string(command_code::create_linear_record_file), fid);
            return error::parameter_error;
        }
        if (settings.record_size < 1) {
            return error::parameter_error;
        }
        return safe_drop_payload(command_code::create_linear_record_file, command_response(
                command_code::create_linear_record_file, bin_data::chain(fid, settings), cipher_default()));
    }

    tag::r<> tag::create_file(file_id fid, file_settings<file_type::cyclic_record> const &settings) {
        if (fid > bits::max_record_file_id) {
            DESFIRE_LOGW("%s: invalid file id %d for a record file.", to_string(command_code::create_cyclic_record_file), fid);
            return error::parameter_error;
        }
        if (settings.record_size < 1) {
            return error::parameter_error;
        }
        if (settings.max_record_count < 2) {
            return error::parameter_error;
        }
        return safe_drop_payload(command_code::create_cyclic_record_file, command_response(
                command_code::create_cyclic_record_file, bin_data::chain(fid, settings), cipher_default()));
    }

    tag::r<> tag::delete_file(file_id fid) {
        return safe_drop_payload(command_code::delete_file, command_response(
                command_code::delete_file, bin_data::chain(fid), cipher_default()));
    }

    tag::r<> tag::clear_record_file(file_id fid) {
        if (fid > bits::max_record_file_id) {
            DESFIRE_LOGW("%s: invalid file id %d for a record file.", to_string(command_code::clear_record_file), fid);
            return error::parameter_error;
        }
        return safe_drop_payload(command_code::clear_record_file, command_response(
                command_code::clear_record_file, bin_data::chain(fid), cipher_default()));
    }


    tag::r<> tag::commit_transaction() {
        return safe_drop_payload(command_code::commit_transaction, command_response(
                command_code::commit_transaction, bin_data{}, cipher_default()));
    }

    tag::r<> tag::abort_transaction() {
        return safe_drop_payload(command_code::abort_transaction, command_response(
                command_code::abort_transaction, bin_data{}, cipher_default()));
    }

    tag::r<std::array<std::uint8_t, 7>> tag::get_card_uid() {
        if (active_cipher_type() == cipher_type::none) {
            DESFIRE_LOGW("%s: did not authenticate, likely to fail.", to_string(command_code::get_card_uid));
        }
        return command_parse_response<std::array<std::uint8_t, 7>>(
                command_code::get_card_uid,
                bin_data{},
                comm_cfg{cipher_default().tx, cipher_mode::ciphered});
    }

    tag::r<std::uint32_t> tag::get_free_mem() {
        const auto res_free_mem = command_parse_response<lsb_uint24>(command_code::free_mem, bin_data{}, cipher_default());
        if (not res_free_mem) {
            return res_free_mem.error();
        }
        return res_free_mem->n;
    }


    tag::r<> tag::set_configuration(bool allow_format, bool enable_random_id) {
        if (active_cipher_type() == cipher_type::none) {
            DESFIRE_LOGW("%s: did not authenticate, likely to fail.", to_string(command_code::set_configuration));
        }
        DESFIRE_LOGW("%s: allow format: %d; enable_random_id: %d.", to_string(command_code::set_configuration),
                     allow_format, enable_random_id);
        std::uint8_t flag = 0x00;
        if (not allow_format) {
            flag |= bits::config_flag_disable_format;
        }
        if (enable_random_id) {
            flag |= bits::config_flag_enable_random_uid;
        }
        const comm_cfg cfg{cipher_mode::ciphered, cipher_default().rx, 2};
        return safe_drop_payload(command_code::set_configuration, command_response(
                command_code::set_configuration,
                bin_data::chain(prealloc(2), active_key_no(), flag),
                cfg));
    }
}
