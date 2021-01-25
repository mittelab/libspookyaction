//
// Created by Pietro Saccardi on 06/01/2021.
//

#include "desfire/data.hpp"
#include "desfire/msg.hpp"
#include "desfire/crypto_algo.hpp"

namespace desfire {

    std::uint8_t any_key::key_number() const {
        switch (type()) {
            case cipher_type::none:
                return std::numeric_limits<std::uint8_t>::max();
            case cipher_type::des:
                return get_key<cipher_type::des>().key_number;
            case cipher_type::des3_2k:
                return get_key<cipher_type::des3_2k>().key_number;
            case cipher_type::des3_3k:
                return get_key<cipher_type::des3_3k>().key_number;
            case cipher_type::aes128:
                return get_key<cipher_type::aes128>().key_number;
            default:
                DESFIRE_LOGE("Unhandled cipher type.");
                return std::numeric_limits<std::uint8_t>::max();
        }
    }

    std::uint8_t any_key::version() const {
        switch (type()) {
            case cipher_type::none:
                return std::numeric_limits<std::uint8_t>::max();
            case cipher_type::des:
                return get_key<cipher_type::des>().version();
            case cipher_type::des3_2k:
                return get_key<cipher_type::des3_2k>().version();
            case cipher_type::des3_3k:
                return get_key<cipher_type::des3_3k>().version();
            case cipher_type::aes128:
                return get_key<cipher_type::aes128>().version();
            default:
                DESFIRE_LOGE("Unhandled cipher type.");
                return std::numeric_limits<std::uint8_t>::max();
        }
    }

    std::size_t any_key::size() const {
        switch (type()) {
            case cipher_type::none:
                return 0;
            case cipher_type::des:
                return key<cipher_type::des>::key_length;
            case cipher_type::des3_2k:
                return key<cipher_type::des3_2k>::key_length;
            case cipher_type::des3_3k:
                return key<cipher_type::des3_3k>::key_length;
            case cipher_type::aes128:
                return key<cipher_type::aes128>::key_length;
            default:
                DESFIRE_LOGE("Unhandled cipher type.");
                return std::numeric_limits<std::uint8_t>::max();
        }
    }

    std::unique_ptr<cipher> any_key::make_cipher() const {
        switch (type()) {
            case cipher_type::none:
                return get_key<cipher_type::none>().make_cipher();
            case cipher_type::des:
                return get_key<cipher_type::des>().make_cipher();
            case cipher_type::des3_2k:
                return get_key<cipher_type::des3_2k>().make_cipher();
            case cipher_type::des3_3k:
                return get_key<cipher_type::des3_3k>().make_cipher();
            case cipher_type::aes128:
                return get_key<cipher_type::aes128>().make_cipher();
            default:
                DESFIRE_LOGE("Unhandled cipher type: %s", to_string(type()));
                return nullptr;
        }
    }

    command_code auth_command(cipher_type t) {
        switch (t) {
            case cipher_type::des3_2k:
                return command_code::authenticate_legacy;
            case cipher_type::des3_3k:
                return command_code::authenticate_iso;
            case cipher_type::des:
                return command_code::authenticate_legacy;
            case cipher_type::aes128:
                return command_code::authenticate_aes;
            default:
                DESFIRE_LOGE("Requesting authentication command for no cipher!");
                return command_code::additional_frame;
        }
    }

    error error_from_status(status s) {
        if (s == status::ok or s == status::no_changes or s == status::additional_frame) {
            return error::malformed;
        }
        return static_cast<error>(s);
    }

    app_crypto app_crypto_from_cipher(cipher_type c) {
        switch (c) {
            case cipher_type::none:
                DESFIRE_LOGE("cipher_type::none cannot be converted to app_crypto!.");
                return app_crypto::legacy_des_2k3des;
            case cipher_type::des:
                // [fallthrough]
            case cipher_type::des3_2k:
                return app_crypto::legacy_des_2k3des;
            case cipher_type::des3_3k:
                return app_crypto::iso_3k3des;
            case cipher_type::aes128:
                return app_crypto::aes_128;
            default:
                DESFIRE_LOGE("Unhandled cipher type: %s", to_string(c));
                return app_crypto::legacy_des_2k3des;
        }
    }

    storage_size::storage_size(std::size_t nbytes) : _flag{0} {
        if (nbytes > 0) {
            const auto log_remainder = log2_remainder(nbytes);
            _flag = (log_remainder.first << bits::storage_size_exponent_shift);
            if (log_remainder.second != 0) {
                _flag |= bits::storage_size_approx_bit;
            }
        }
    }


    mlab::bin_stream &storage_size::operator>>(mlab::bin_stream &s) {
        if (s.remaining() == 0) {
            DESFIRE_LOGE("Cannot parse storage_size, not enough data.");
            s.set_bad();
            return s;
        }
        return s >> _flag;
    }
    mlab::bin_data &storage_size::operator<<(mlab::bin_data &s) const {
        return s << _flag;
    }

    namespace {
        template <std::size_t Size>
        void xor_with(std::array<std::uint8_t, Size> &data, std::vector<std::uint8_t> const &xor_with) {
            for (std::size_t i = 0; i < std::min(data.size(), xor_with.size()); ++i) {
                data[i] |= xor_with[i];
            }
        }
    }

    bool any_key::parity_bits_are_version() const {
        // Extract packed key data from the other key
        switch (type()) {
            case cipher_type::none:
                DESFIRE_LOGE("Cannot decide if parity bits are version on cipher_type::none.");
                return false;
            case cipher_type::des:
                return key<cipher_type::des>::parity_bits_are_version;
            case cipher_type::des3_2k:
                return key<cipher_type::des3_2k>::parity_bits_are_version;
            case cipher_type::des3_3k:
                return key<cipher_type::des3_3k>::parity_bits_are_version;
            case cipher_type::aes128:
                return key<cipher_type::aes128>::parity_bits_are_version;
            default:
                DESFIRE_LOGE("Unhandled cipher type: %s", to_string(type()));
                return false;
        }
    }

    bin_data any_key::get_packed_key_body() const {
        bin_data body{};
        // Extract packed key data from the other key
        switch (type()) {
            case cipher_type::none:
                DESFIRE_LOGE("Cannot extract data payload with a key of type cipher_type::none.");
                break;
            case cipher_type::des:
                /**
                 * @note Special treatment for DES.
                 */
                {
                    auto const &k = get_key<cipher_type::des>().k;
                    body << prealloc(2 * k.size()) << k << k;
                }
                break;
            case cipher_type::des3_2k:
                body << get_key<cipher_type::des3_2k>().k;
                break;
            case cipher_type::des3_3k:
                body << get_key<cipher_type::des3_3k>().k;
                break;
            case cipher_type::aes128:
                body << get_key<cipher_type::aes128>().k;
                break;
            default:
                DESFIRE_LOGE("Unhandled cipher type: %s", to_string(type()));
                break;
        }
        return body;
    }

    bin_data any_key::xored_with(any_key const &key_to_xor_with) const {
        const bin_data their_data = key_to_xor_with.get_packed_key_body();
        if (their_data.empty()) {
            return {};
        }
        bin_data our_data = get_packed_key_body();
        if (our_data.empty()) {
            return {};
        }
        for (std::size_t i = 0; i < std::min(our_data.size(), their_data.size()); ++i) {
            our_data[i] |= their_data[i];
        }
        if (not parity_bits_are_version()) {
            our_data << version();
        }
        return our_data;
    }

    generic_file_settings const &any_file_settings::generic_settings() const {
        if (not _settings.empty()) {
            switch (type()) {
                case file_type::standard:
                    return get_settings<file_type::standard>();
                case file_type::backup:
                    return get_settings<file_type::backup>();
                case file_type::value:
                    return get_settings<file_type::value>();
                case file_type::linear_record:
                    return get_settings<file_type::linear_record>();
                case file_type::cyclic_record:
                    return get_settings<file_type::cyclic_record>();
                default:
                    DESFIRE_LOGE("Unhandled file type: %s", to_string(type()));
                    break;
            }
        }
        static generic_file_settings _dummy{};
        DESFIRE_LOGE("Cannot retrieve file settings from an empty file settings container.");
        _dummy = {};
        return _dummy;
    }


    bool access_rights::is_free(file_access access, std::uint8_t active_key_num) const {
        switch (access) {
            case file_access::read:
                return read != active_key_num and read_write != active_key_num and
                        (read == all_keys or read_write == all_keys);
            case file_access::write:
                return write != active_key_num and read_write != active_key_num and
                        (write == all_keys or read_write == all_keys);
            case file_access::change:
                return change == all_keys;
            default:
                DESFIRE_LOGE("Unhandled access type.");
                return false;
        }
    }

    generic_file_settings &any_file_settings::generic_settings() {
        return const_cast<generic_file_settings &>(static_cast<any_file_settings const *>(this)->generic_settings());
    }


    bin_data &any_key::operator<<(bin_data &bd) const {
        bd << get_packed_key_body();
        if (not parity_bits_are_version()) {
            bd << version();
        }
        return bd;
    }

}

namespace mlab {
    namespace {
        namespace bits = desfire::bits;
    }

    bin_data &operator<<(bin_data &bd, desfire::key_rights const &kr) {
        const std::uint8_t flag = kr.allowed_to_change_keys.get()
                | (kr.config_changeable ? bits::app_change_config_allowed_flag : 0x0)
                | (kr.master_key_changeable ? bits::app_changeable_master_key_flag : 0x0)
                | (kr.create_delete_without_auth ? bits::app_create_delete_without_master_key_flag : 0x0)
                | (kr.dir_access_without_auth ? bits::app_list_without_master_key_flag : 0x0);
        return bd << flag;
    }

    bin_stream &operator>>(bin_stream &s, desfire::key_rights &kr) {
        if (s.remaining() < 1) {
            DESFIRE_LOGE("Cannot parse key_rights, not enough data.");
            s.set_bad();
            return s;
        }
        const std::uint8_t flag = s.pop();
        if (0 != (flag & bits::app_change_keys_right_freeze_flag)) {
            kr.allowed_to_change_keys = desfire::no_key;
        } else if (0 != (flag & bits::app_change_keys_right_same_flag)) {
            kr.allowed_to_change_keys = desfire::same_key;
        } else {
            kr.allowed_to_change_keys = flag >> bits::app_change_keys_right_shift;
        }
        kr.dir_access_without_auth = 0 != (flag & bits::app_list_without_master_key_flag);
        kr.create_delete_without_auth = 0 != (flag & bits::app_create_delete_without_master_key_flag);
        kr.master_key_changeable = 0 != (flag & bits::app_changeable_master_key_flag);
        kr.config_changeable = 0 != (flag & bits::app_change_config_allowed_flag);
        return s;
    }

    bin_stream &operator>>(bin_stream &s, desfire::key_settings &ks) {
        if (s.remaining() < 2) {
            DESFIRE_LOGE("Cannot parse key_settings, not enough data.");
            s.set_bad();
            return s;
        }
        s >> ks.rights;
        const std::uint8_t keys_crypto_flag = s.pop();
        ks.max_num_keys = (keys_crypto_flag & bits::max_keys_mask);
        if (ks.max_num_keys > bits::max_keys_per_app) {
            DESFIRE_LOGW("Error while parsing key_settings: the specified max number of keys exceed the maximum "
                         "number of keys declared: %u > %u.", ks.max_num_keys, bits::max_keys_per_app);
            ks.max_num_keys = bits::max_keys_per_app;
        }
        static_assert(0 == static_cast<std::uint8_t>(bits::app_crypto::legacy_des_2k3des),
                "This code relies on the fact that by default it's legacy, i.e. legacy has no bit set.");
        const bool wants_iso_3k3des = 0 != (keys_crypto_flag & static_cast<std::uint8_t>(bits::app_crypto::iso_3k3des));
        const bool wants_aes_128 = 0 != (keys_crypto_flag & static_cast<std::uint8_t>(bits::app_crypto::aes_128));
        if (not wants_aes_128 and not wants_iso_3k3des) {
            ks.crypto = bits::app_crypto::legacy_des_2k3des;
        } else if (wants_iso_3k3des) {
            ks.crypto = bits::app_crypto::iso_3k3des;
            if (wants_aes_128) {
                DESFIRE_LOGE("Error while parsing key_settings, the selected app has both the AES128 bit and the ISO "
                             "3K3DES bit. Will assume 3K3DES.");
            }
        } else {
            ks.crypto = bits::app_crypto::aes_128;
        }
        return s;
    }

    bin_stream &operator>>(bin_stream &s, std::vector<desfire::app_id> &ids) {
        if (s.remaining() % bits::app_id_length != 0) {
            DESFIRE_LOGE("Cannot parse vector<app_id>, data length is not an integer multiple of the app id size.");
            s.set_bad();
            return s;
        }
        ids.resize(s.remaining() / bits::app_id_length, desfire::app_id{});
        for (auto &aid : ids) {
            s >> aid;
        }
        return s;
    }

    bin_data &operator<<(bin_data &bd, desfire::key_settings const &ks) {
        const std::uint8_t flag = std::min(std::max(ks.max_num_keys, std::uint8_t(1)), bits::max_keys_per_app)
                | static_cast<std::uint8_t>(ks.crypto);
        return bd << prealloc(2) << ks.rights << flag;
    }

    bin_stream &operator>>(bin_stream &s, desfire::ware_info &wi) {
        if (s.remaining() < 7) {
            DESFIRE_LOGE("Cannot parse ware_info: not enough data.");
            s.set_bad();
            return s;
        }
        s >> wi.vendor_id >> wi.type >> wi.subtype >> wi.version_major >> wi.version_minor;
        wi.size.operator>>(s);
        s >> wi.comm_protocol_type;
        return s;
    }

    bin_stream &operator>>(bin_stream &s, desfire::manufacturing_info &mi) {
        if (s.remaining() < 28) {
            DESFIRE_LOGE("Cannot parse manufacturing_info: not enough data.");
            s.set_bad();
            return s;
        }
        s >> mi.hardware >> mi.software >> mi.serial_no >> mi.batch_no >> mi.production_week >> mi.production_year;
        return s;
    }

    bin_data &operator<<(bin_data &bd, desfire::any_key const &k) {
        return k.operator<<(bd);
    }

    bin_stream &operator>>(bin_stream &s, desfire::access_rights &ar) {
        if (s.remaining() < 2) {
            DESFIRE_LOGE("Cannot parse access_rights: not enough data.");
            s.set_bad();
            return s;
        }
        return s >> lsb16 >> ar.value;
    }

    bin_data &operator<<(bin_data &bd, desfire::access_rights const &ar) {
        return bd << lsb16 << ar.value;
    }

    bin_stream &operator>>(bin_stream &s, desfire::generic_file_settings &fs) {
        if (s.remaining() < 3) {
            DESFIRE_LOGE("Cannot parse generic_file_settings: not enough data.");
            s.set_bad();
            return s;
        }
        return s >> fs.mode >> fs.rights;
    }

    bin_data &operator<<(bin_data &bd, desfire::generic_file_settings const &fs) {
        return bd << fs.mode << fs.rights;
    }

    bin_stream &operator>>(bin_stream &s, desfire::data_file_settings &fs) {
        if (s.remaining() < 3) {
            DESFIRE_LOGE("Cannot parse data_file_settings: not enough data.");
            s.set_bad();
            return s;
        }
        return s >> lsb24 >> fs.size;
    }

    bin_data &operator<<(bin_data &bd, desfire::data_file_settings const &fs) {
        return bd << lsb24 << fs.size;
    }

    bin_stream &operator>>(bin_stream &s, desfire::value_file_settings &fs) {
        if (s.remaining() < 13) {
            DESFIRE_LOGE("Cannot parse value_file_settings: not enough data.");
            s.set_bad();
            return s;
        }
        s >> lsb32 >> fs.lower_limit;
        s >> lsb32 >> fs.upper_limit;
        s >> lsb32 >> fs.value;
        fs.limited_credit_enabled = (s.pop() != 0);
        return s;
    }

    bin_data &operator<<(bin_data &bd, desfire::value_file_settings const &fs) {
        bd << lsb32 << fs.lower_limit;
        bd << lsb32 << fs.upper_limit;
        bd << lsb32 << fs.value;
        bd << std::uint8_t(fs.limited_credit_enabled ? 0x1 : 0x00);
        return bd;
    }

    bin_stream &operator>>(bin_stream &s, desfire::record_file_settings &fs) {
        if (s.remaining() < 9) {
            DESFIRE_LOGE("Cannot parse record_file_settings: not enough data.");
            s.set_bad();
            return s;
        }
        s >> lsb24 >> fs.record_size;
        s >> lsb24 >> fs.max_record_count;
        s >> lsb24 >> fs.record_count;
        return s;
    }

    bin_data &operator<<(bin_data &bd, desfire::record_file_settings const &fs) {
        bd << lsb24 << fs.record_size;
        bd << lsb24 << fs.max_record_count;
        if (fs.record_count != 0) {
            DESFIRE_LOGW("Record counts are not trasmitted to the PICC.");
        }
        return bd;
    }

    bin_stream &operator>>(bin_stream &s, desfire::any_file_settings &fs) {
        if (s.remaining() < 1) {
            DESFIRE_LOGE("Cannot parse file_type: not enough data.");
            s.set_bad();
            return s;
        }
        desfire::file_type ft{};
        s >> ft;
        if (not s.bad()) {
            switch (ft) {
                case desfire::file_type::standard: {
                    desfire::file_settings<desfire::file_type::standard> typed_fs{};
                    s >> fs;
                    fs = typed_fs;
                }
                break;
                case desfire::file_type::backup: {
                    desfire::file_settings<desfire::file_type::backup> typed_fs{};
                    s >> fs;
                    fs = typed_fs;
                }
                break;
                case desfire::file_type::value: {
                    desfire::file_settings<desfire::file_type::value> typed_fs{};
                    s >> fs;
                    fs = typed_fs;
                }
                break;
                case desfire::file_type::linear_record: {
                    desfire::file_settings<desfire::file_type::linear_record> typed_fs{};
                    s >> fs;
                    fs = typed_fs;
                }
                break;
                case desfire::file_type::cyclic_record: {
                    desfire::file_settings<desfire::file_type::cyclic_record> typed_fs{};
                    s >> fs;
                    fs = typed_fs;
                }
                break;
                default:
                    DESFIRE_LOGE("Unhandled file type: %s", desfire::to_string(ft));
                    s.set_bad();
                    break;
            }
        }
        return s;
    }

    bin_data &operator<<(bin_data &bd, desfire::any_file_settings const &fs) {
        bd << fs.type();
        switch (fs.type()) {
            case desfire::file_type::standard:
                bd << fs.get_settings<desfire::file_type::standard>();
                break;
            case desfire::file_type::backup:
                bd << fs.get_settings<desfire::file_type::backup>();
                break;
            case desfire::file_type::value:
                bd << fs.get_settings<desfire::file_type::value>();
                break;
            case desfire::file_type::linear_record:
                bd << fs.get_settings<desfire::file_type::linear_record>();
                break;
            case desfire::file_type::cyclic_record:
                bd << fs.get_settings<desfire::file_type::cyclic_record>();
                break;
            default:
                DESFIRE_LOGE("Unhandled file type: %s", desfire::to_string(fs.type()));
                break;
        }
        return bd;
    }


}