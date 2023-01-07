//
// Created by Pietro Saccardi on 06/01/2021.
//

#include <desfire/crypto_algo.hpp>
#include <desfire/data.hpp>
#include <desfire/msg.hpp>

namespace desfire {

    namespace {
        using mlab::prealloc;
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

    storage_size::storage_size(std::size_t nbytes) : _flag{0} {
        if (nbytes > 0) {
            const auto [log, remainder] = log2_remainder(nbytes);
            _flag = (log << bits::storage_size_exponent_shift);
            if (remainder != 0) {
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

    generic_file_settings const &any_file_settings::generic_settings() const {
        switch (type()) {
            case file_type::standard:
                return get<file_type::standard>();
            case file_type::backup:
                return get<file_type::backup>();
            case file_type::value:
                return get<file_type::value>();
            case file_type::linear_record:
                return get<file_type::linear_record>();
            case file_type::cyclic_record:
                return get<file_type::cyclic_record>();
        }
        static generic_file_settings _dummy{};
        DESFIRE_LOGE("Cannot retrieve file settings from an empty file settings container.");
        _dummy = {};
        return _dummy;
    }

    data_file_settings const &any_file_settings::data_settings() const {
        switch (type()) {
            case file_type::standard:
                return get<file_type::standard>();
            case file_type::backup:
                return get<file_type::backup>();
            default:
                DESFIRE_LOGE("Cannot retrieve data settings from a file of type %s", to_string(type()));
                break;
        }
        static data_file_settings _dummy{};
        _dummy = {};
        return _dummy;
    }

    record_file_settings const &any_file_settings::record_settings() const {
        switch (type()) {
            case file_type::linear_record:
                return get<file_type::linear_record>();
            case file_type::cyclic_record:
                return get<file_type::cyclic_record>();
            default:
                DESFIRE_LOGE("Cannot retrieve record settings from a file of type %s", to_string(type()));
                break;
        }
        static record_file_settings _dummy{};
        _dummy = {};
        return _dummy;
    }

    value_file_settings const &any_file_settings::value_settings() const {
        switch (type()) {
            case file_type::value:
                return get<file_type::value>();
            default:
                DESFIRE_LOGE("Cannot retrieve value settings from a file of type %s", to_string(type()));
                break;
        }
        static value_file_settings _dummy{};
        _dummy = {};
        return _dummy;
    }

    bool access_rights::is_free(file_access access) const {
        switch (access) {
            case file_access::read:
                return read == all_keys or read_write == all_keys;
            case file_access::write:
                return write == all_keys or read_write == all_keys;
            case file_access::change:
                return change == all_keys;
        }
        return false;
    }

    generic_file_settings &any_file_settings::generic_settings() {
        return const_cast<generic_file_settings &>(static_cast<any_file_settings const *>(this)->generic_settings());
    }

    data_file_settings &any_file_settings::data_settings() {
        return const_cast<data_file_settings &>(static_cast<any_file_settings const *>(this)->data_settings());
    }

    record_file_settings &any_file_settings::record_settings() {
        return const_cast<record_file_settings &>(static_cast<any_file_settings const *>(this)->record_settings());
    }

    value_file_settings &any_file_settings::value_settings() {
        return const_cast<value_file_settings &>(static_cast<any_file_settings const *>(this)->value_settings());
    }

}// namespace desfire

namespace mlab {
    namespace {
        namespace bits = desfire::bits;
    }

    bin_data &operator<<(bin_data &bd, desfire::key_rights const &kr) {
        const std::uint8_t flag = (kr.allowed_to_change_keys.get_nibble() << bits::app_change_keys_right_shift) |
                                  (kr.config_changeable ? bits::app_change_config_allowed_flag : 0x0) |
                                  (kr.master_key_changeable ? bits::app_changeable_master_key_flag : 0x0) |
                                  (kr.create_delete_without_master_key ? bits::app_create_delete_without_master_key_flag : 0x0) |
                                  (kr.dir_access_without_auth ? bits::app_list_without_master_key_flag : 0x0);
        return bd << flag;
    }

    bin_stream &operator>>(bin_stream &s, desfire::key_rights &kr) {
        if (s.remaining() < 1) {
            DESFIRE_LOGE("Cannot parse key_rights, not enough data.");
            s.set_bad();
            return s;
        }
        std::uint8_t flag = s.pop();
        kr.dir_access_without_auth = 0 != (flag & bits::app_list_without_master_key_flag);
        kr.create_delete_without_master_key = 0 != (flag & bits::app_create_delete_without_master_key_flag);
        kr.master_key_changeable = 0 != (flag & bits::app_changeable_master_key_flag);
        kr.config_changeable = 0 != (flag & bits::app_change_config_allowed_flag);
        flag >>= bits::app_change_keys_right_shift;
        if (flag == bits::app_change_keys_right_none) {
            kr.allowed_to_change_keys = desfire::no_key;
        } else if (flag == bits::app_change_keys_right_same) {
            kr.allowed_to_change_keys = desfire::same_key;
        } else {
            kr.allowed_to_change_keys = flag;
        }
        return s;
    }

    bin_stream &operator>>(bin_stream &s, desfire::app_settings &ks) {
        if (s.remaining() < 2) {
            DESFIRE_LOGE("Cannot parse app_settings, not enough data.");
            s.set_bad();
            return s;
        }
        s >> ks.rights;
        const std::uint8_t keys_crypto_flag = s.pop();
        ks.max_num_keys = (keys_crypto_flag & bits::max_keys_mask);
        if (ks.max_num_keys > bits::max_keys_per_app) {
            DESFIRE_LOGW("Error while parsing app_settings: the specified max number of keys exceed the maximum "
                         "number of keys declared: %u > %u.",
                         ks.max_num_keys, bits::max_keys_per_app);
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
                DESFIRE_LOGE("Error while parsing app_settings, the selected app has both the AES128 bit and the ISO "
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

    bin_data &operator<<(bin_data &bd, desfire::app_settings const &ks) {
        const std::uint8_t flag = std::clamp(ks.max_num_keys, std::uint8_t(1), bits::max_keys_per_app) | static_cast<std::uint8_t>(ks.crypto);
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

    bin_stream &operator>>(bin_stream &s, desfire::access_rights &ar) {
        if (s.remaining() < 2) {
            DESFIRE_LOGE("Cannot parse access_rights: not enough data.");
            s.set_bad();
            return s;
        }
        std::uint16_t word{0};
        s >> lsb16 >> word;
        ar.set_word(word);
        return s;
    }

    bin_data &operator<<(bin_data &bd, desfire::access_rights const &ar) {
        return bd << lsb16 << ar.get_word();
    }

    bin_stream &operator>>(bin_stream &s, desfire::generic_file_settings &fs) {
        if (s.remaining() < 3) {
            DESFIRE_LOGE("Cannot parse generic_file_settings: not enough data.");
            s.set_bad();
            return s;
        }
        return s >> fs.security >> fs.rights;
    }

    bin_data &operator<<(bin_data &bd, desfire::generic_file_settings const &fs) {
        return bd << fs.security << fs.rights;
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
                    s >> typed_fs;
                    fs = typed_fs;
                } break;
                case desfire::file_type::backup: {
                    desfire::file_settings<desfire::file_type::backup> typed_fs{};
                    s >> typed_fs;
                    fs = typed_fs;
                } break;
                case desfire::file_type::value: {
                    desfire::file_settings<desfire::file_type::value> typed_fs{};
                    s >> typed_fs;
                    fs = typed_fs;
                } break;
                case desfire::file_type::linear_record: {
                    desfire::file_settings<desfire::file_type::linear_record> typed_fs{};
                    s >> typed_fs;
                    fs = typed_fs;
                } break;
                case desfire::file_type::cyclic_record: {
                    desfire::file_settings<desfire::file_type::cyclic_record> typed_fs{};
                    s >> typed_fs;
                    fs = typed_fs;
                } break;
                default:
                    DESFIRE_LOGE("operator>>(any_file_settings &): unhandled file type: %s", desfire::to_string(ft));
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
                bd << fs.get<desfire::file_type::standard>();
                break;
            case desfire::file_type::backup:
                bd << fs.get<desfire::file_type::backup>();
                break;
            case desfire::file_type::value:
                bd << fs.get<desfire::file_type::value>();
                break;
            case desfire::file_type::linear_record:
                bd << fs.get<desfire::file_type::linear_record>();
                break;
            case desfire::file_type::cyclic_record:
                bd << fs.get<desfire::file_type::cyclic_record>();
                break;
        }
        return bd;
    }


}// namespace mlab