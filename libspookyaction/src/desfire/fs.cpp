//
// Created by spak on 11/24/22.
//

#include <desfire/fs.hpp>
#include <algorithm>

namespace desfire::fs {

    r<> create_ro_free_plain_value_file(tag &tag, file_id fid, std::int32_t value) {
        // A value file can be directly created with no write access, because it takes an initial value
        const file_settings<file_type::value> ro_settings{
                generic_file_settings{
                        file_security::none,
                        access_rights{no_key, no_key, all_keys, no_key}},
                value_file_settings{value, value, value, false}};
        return tag.create_file(fid, ro_settings);
    }

    r<> create_ro_free_plain_data_file(tag &tag, file_id fid, mlab::bin_data const &value) {
        // A data file must be created with write access, because we have to write on it before locking it.
        const file_settings<file_type::standard> init_settings{
                generic_file_settings{
                        file_security::none,
                        access_rights{no_key, tag.active_key_no(), all_keys, tag.active_key_no()}},
                data_file_settings{value.size()}};
        // Final access rights revoke the write access
        const generic_file_settings final_settings{
                file_security::none,
                access_rights{no_key, no_key, all_keys, no_key}};
        TRY(tag.create_file(fid, init_settings))
        TRY(tag.write_data(fid, value, tag::determine_operation_mode(file_access::write, init_settings)))
        TRY(tag.change_file_settings(fid, final_settings, tag::determine_operation_mode(file_access::change, init_settings)))
        return mlab::result_success;
    }

    r<> create_app(tag &tag, app_id aid, any_key master_key, key_rights const &rights, std::uint8_t extra_keys) {
        // Patch the key number
        if (master_key.key_number() != 0) {
            master_key.set_key_number(0);
        }
        // We need to change at least one key, but we try to recover as many settings as possible from rights.
        // If rights has a setting that allows us to change key, we use that. Otherwise, we switch to master key
        const key_actor<same_key_t> change_key_actor =
                rights.allowed_to_change_keys == master_key.key_number() or rights.allowed_to_change_keys == same_key
                        ? rights.allowed_to_change_keys
                        : master_key.key_number();
        // Allow modifying config and keys initially
        const key_rights inital_rights{change_key_actor, true, rights.dir_access_without_auth, rights.create_delete_without_auth, true};
        const app_settings initial_settings{
                app_crypto_from_cipher(master_key.type()),
                inital_rights,
                std::uint8_t(std::min(unsigned(bits::max_keys_per_app), extra_keys + 1u))};
        TRY(tag.create_application(aid, initial_settings))
        // Enter the application with the default key
        TRY(tag.select_application(aid))
        TRY(tag.authenticate(any_key(master_key.type())))
        // Change the master key
        TRY(tag.change_key(master_key))
        // Authenticate and update the app key rights, if needed
        TRY(tag.authenticate(master_key))
        if (rights != inital_rights) {
            // Only change the rights if there is something different
            TRY(tag.change_app_settings(rights))
        }
        return mlab::result_success;
    }

    r<any_key> create_app_for_ro(tag &tag, cipher_type cipher, app_id aid, random_oracle rng) {
        // Create a random key
        const any_key k{cipher, rng};
        // Settings for an app with one key that can change keys
        TRY(create_app(tag, aid, k, key_rights{k.key_number(), true, true, false, true}))
        return k;
    }

    r<> make_app_ro(tag &tag, bool list_requires_auth) {
        const key_rights ro_rights{
                no_key, false, list_requires_auth, false, false};
        TRY(tag.change_app_settings(ro_rights))
        return mlab::result_success;
    }

    r<bool> does_file_exist(tag &tag, file_id fid) {
        TRY_RESULT(tag.get_file_ids()) {
            return std::find(std::begin(*r), std::end(*r), fid) != std::end(*r);
        }
    }

    r<std::vector<file_id>> which_files_exist(tag &tag, std::vector<file_id> fids) {
        TRY_RESULT(tag.get_file_ids()) {
            std::sort(std::begin(*r), std::end(*r));
            std::sort(std::begin(fids), std::end(fids));
            std::vector<file_id> retval{};
            std::set_intersection(std::begin(fids), std::end(fids), std::begin(*r), std::end(*r), std::back_inserter(retval));
            return retval;
        }
    }

    r<bool> does_app_exist(tag &tag, app_id aid) {
        TRY_RESULT(tag.get_application_ids()) {
            return std::find(std::begin(*r), std::end(*r), aid) != std::end(*r);
        }
    }

    r<> delete_file_if_exists(tag &tag, file_id fid) {
        TRY_RESULT(does_file_exist(tag, fid)) {
            if (*r) {
                TRY(tag.delete_file(fid))
            }
        }
        return mlab::result_success;
    }

    r<> delete_app_if_exists(tag &tag, app_id aid) {
        TRY_RESULT(does_app_exist(tag, aid)) {
            if (*r) {
                TRY(tag.delete_application(aid))
            }
        }
        return mlab::result_success;
    }
}// namespace desfire::fs