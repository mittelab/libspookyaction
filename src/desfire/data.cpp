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
    }

    bin_data &operator<<(bin_data &bd, desfire::key_rights const &kr) {
        const std::uint8_t flag = kr.allowed_to_change_keys.bitflag()
                | (kr.config_changeable ? bits::app_change_config_allowed_flag : 0x0)
                | (kr.master_key_changeable ? bits::app_changeable_master_key_flag : 0x0)
                | (kr.create_delete_without_auth ? bits::app_create_delete_without_master_key_flag : 0x0)
                | (kr.dir_access_without_auth ? bits::app_list_without_master_key_flag : 0x0);
        return bd << flag;
    }

    bin_stream &operator>>(bin_stream &s, desfire::key_rights &kr) {
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

}