//
// Created by spak on 16/9/22.
//
#include <desfire/cipher_provider.hpp>
#include <desfire/crypto_algo.hpp>
#include <desfire/data.hpp>
#include <desfire/kdf.hpp>

namespace desfire {

    std::array<std::uint8_t, 8> kdf_an10922(crypto_des_base &crypto, mlab::bin_data &diversify_input) {
        cmac_keychain keychain{8, bits::crypto_cmac_xor_byte_des};
        keychain.initialize_subkeys(crypto);
        return kdf_an10922<8, 1>(keychain, crypto, diversify_input, bits::kdf_des_const);
    }

    std::array<std::uint8_t, 16> kdf_an10922(crypto_2k3des_base &crypto, mlab::bin_data &diversify_input) {
        cmac_keychain keychain{8, bits::crypto_cmac_xor_byte_2k3des};
        keychain.initialize_subkeys(crypto);
        return kdf_an10922<8, 2>(keychain, crypto, diversify_input, bits::kdf_2k3des_const);
    }

    std::array<std::uint8_t, 24> kdf_an10922(crypto_3k3des_base &crypto, mlab::bin_data &diversify_input) {
        // No need to initialize the subkeys here
        return kdf_an10922<8, 3>(crypto.provider().keychain(), crypto, diversify_input, bits::kdf_3k3des_const);
    }

    std::array<std::uint8_t, 16> kdf_an10922(crypto_aes_base &crypto, mlab::bin_data &diversify_input) {
        // No need to initialize the subkeys here
        return kdf_an10922<16, 1>(crypto.provider().keychain(), crypto, diversify_input, bits::kdf_aes_const);
    }

    std::array<std::uint8_t, 8> kdf_an10922(crypto_des_base &crypto, mlab::bin_data &diversify_input, std::uint8_t key_version) {
        auto div_key = kdf_an10922(crypto, diversify_input);
        set_key_version(div_key, key_version);
        return div_key;
    }
    std::array<std::uint8_t, 16> kdf_an10922(crypto_2k3des_base &crypto, mlab::bin_data &diversify_input, std::uint8_t key_version) {
        auto div_key = kdf_an10922(crypto, diversify_input);
        set_key_version(div_key, key_version);
        return div_key;
    }
    std::array<std::uint8_t, 24> kdf_an10922(crypto_3k3des_base &crypto, mlab::bin_data &diversify_input, std::uint8_t key_version) {
        auto div_key = kdf_an10922(crypto, diversify_input);
        set_key_version(div_key, key_version);
        return div_key;
    }
    key<cipher_type::des> kdf_an10922(key<cipher_type::des> const &key, cipher_provider &provider, mlab::bin_data &diversify_input) {
        auto pcrypto = provider.crypto_from_key(key);
        cmac_keychain keychain{8, bits::crypto_cmac_xor_byte_des};
        keychain.initialize_subkeys(*pcrypto);
        auto div_key = kdf_an10922<8, 1>(keychain, *pcrypto, diversify_input, bits::kdf_des_const);
        return desfire::key<cipher_type::des>{0, div_key, key.version()};
    }
    key<cipher_type::des3_2k> kdf_an10922(key<cipher_type::des3_2k> const &key, cipher_provider &provider, mlab::bin_data &diversify_input) {
        auto pcrypto = provider.crypto_from_key(key);
        cmac_keychain keychain{8, bits::crypto_cmac_xor_byte_2k3des};
        keychain.initialize_subkeys(*pcrypto);
        auto div_key = kdf_an10922<8, 2>(keychain, *pcrypto, diversify_input, bits::kdf_2k3des_const);
        return desfire::key<cipher_type::des3_2k>{0, div_key, key.version()};
    }
    key<cipher_type::des3_3k> kdf_an10922(key<cipher_type::des3_3k> const &key, cipher_provider &provider, mlab::bin_data &diversify_input) {
        auto pcrypto = provider.crypto_from_key(key);
        cmac_keychain keychain{8, bits::crypto_cmac_xor_byte_3k3des};
        keychain.initialize_subkeys(*pcrypto);
        auto div_key = kdf_an10922<8, 3>(keychain, *pcrypto, diversify_input, bits::kdf_3k3des_const);
        return desfire::key<cipher_type::des3_3k>{0, div_key, key.version()};
    }
    key<cipher_type::aes128> kdf_an10922(key<cipher_type::aes128> const &key, cipher_provider &provider, mlab::bin_data &diversify_input) {
        auto pcrypto = provider.crypto_from_key(key);
        cmac_keychain keychain{16, bits::crypto_cmac_xor_byte_aes};
        keychain.initialize_subkeys(*pcrypto);
        auto div_key = kdf_an10922<16, 1>(keychain, *pcrypto, diversify_input, bits::kdf_aes_const);
        return desfire::key<cipher_type::aes128>{0, div_key, key.version()};
    }

    any_key kdf_an10922(any_key const &key, cipher_provider &provider, mlab::bin_data &diversify_input) {
        auto pcrypto = provider.crypto_from_key(key);
        return kdf_an10922(*pcrypto, diversify_input, key.version());
    }

    any_key kdf_an10922(crypto &crypto, mlab::bin_data &diversify_input, std::uint8_t key_version) {
        switch (crypto.cipher_type()) {
            case cipher_type::des: {
                cmac_keychain keychain{8, bits::crypto_cmac_xor_byte_des};
                keychain.initialize_subkeys(crypto);
                auto div_key = kdf_an10922<8, 1>(keychain, crypto, diversify_input, bits::kdf_des_const);
                return key<cipher_type::des>{0, div_key, key_version};
            }
            case cipher_type::des3_2k: {
                cmac_keychain keychain{8, bits::crypto_cmac_xor_byte_2k3des};
                keychain.initialize_subkeys(crypto);
                auto div_key = kdf_an10922<8, 2>(keychain, crypto, diversify_input, bits::kdf_2k3des_const);
                return key<cipher_type::des3_2k>{0, div_key, key_version};
            }
            case cipher_type::des3_3k: {
                cmac_keychain keychain{8, bits::crypto_cmac_xor_byte_3k3des};
                keychain.initialize_subkeys(crypto);
                auto div_key = kdf_an10922<8, 3>(keychain, crypto, diversify_input, bits::kdf_3k3des_const);
                return key<cipher_type::des3_3k>{0, div_key, key_version};
            }
            case cipher_type::aes128: {
                cmac_keychain keychain{16, bits::crypto_cmac_xor_byte_aes};
                keychain.initialize_subkeys(crypto);
                auto div_key = kdf_an10922<16, 1>(keychain, crypto, diversify_input, bits::kdf_aes_const);
                return key<cipher_type::aes128>{0, div_key, key_version};
            }
            case cipher_type::none:
                [[fallthrough]];
            default:
                DESFIRE_LOGE("Cannot diversify a key with cipher none.");
                return any_key{};
        }
    }

}// namespace desfire
