//
// Created by Pietro Saccardi on 06/01/2021.
//

#include "desfire/data.hpp"

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

    bool any_key::is_legacy_scheme() const {
        switch (type()) {
            case cipher_type::des:
            case cipher_type::des3_2k:
                return true;
            case cipher_type::des3_3k:
            case cipher_type::aes128:
                return false;
            default:
                DESFIRE_LOGE("Requesting whether a cipher is legacy with no cipher!");
                return true;
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
                DESFIRE_LOGE("Unhandled cipher type.");
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


}

namespace mlab {
    namespace {
        namespace bits = desfire::bits;

        std::uint8_t flag_from_master_key_settings(desfire::master_key_settings const &s) {
            return (s.allow_change_config ? bits::app_change_config_allowed_flag : 0x0)
                   | (s.allow_change_master_key ? bits::app_changeable_master_key_flag : 0x0)
                   | (s.allow_create_delete_without_auth ? bits::app_create_delete_without_master_key_flag : 0x0)
                   | (s.allow_dir_access_without_auth ? bits::app_list_without_master_key_flag : 0x0);
        }

        void master_key_settings_from_flag(std::uint8_t flag, desfire::master_key_settings &mks) {
            mks.allow_dir_access_without_auth = 0 != (flag & bits::app_list_without_master_key_flag);
            mks.allow_create_delete_without_auth = 0 != (flag & bits::app_create_delete_without_master_key_flag);
            mks.allow_change_master_key = 0 != (flag & bits::app_changeable_master_key_flag);
            mks.allow_change_config = 0 != (flag & bits::app_change_config_allowed_flag);
        }
    }
    bin_data &operator<<(bin_data &bd, desfire::master_key_settings const &s) {
        return bd << flag_from_master_key_settings(s);
    }

    bin_data &operator<<(bin_data &bd, desfire::app_master_key_settings const &s) {
        const std::uint8_t flag = flag_from_master_key_settings(s) | s.allow_change_keys.bitflag();
        return bd << flag;
    }

    bin_stream &operator>>(bin_stream &s, desfire::master_key_settings &mks) {
        master_key_settings_from_flag(s.pop(), mks);
        return s;
    }

    bin_stream &operator>>(bin_stream &s, desfire::app_master_key_settings &mks) {
        const std::uint8_t flag = s.pop();
        master_key_settings_from_flag(flag, mks);
        if (0 != (flag & bits::app_change_keys_right_freeze_flag)) {
            mks.allow_change_keys = desfire::freeze_keys;
        } else if (0 != (flag & bits::app_change_keys_right_same_flag)) {
            mks.allow_change_keys = desfire::same_key;
        } else {
            mks.allow_change_keys = flag >> bits::app_change_keys_right_shift;
        }
        return s;
    }

}