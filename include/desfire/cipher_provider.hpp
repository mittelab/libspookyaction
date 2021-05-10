//
// Created by spak on 5/10/21.
//

#ifndef DESFIRE_CIPHER_PROVIDER_HPP
#define DESFIRE_CIPHER_PROVIDER_HPP

#include <desfire/data.hpp>
#include <desfire/crypto_ciphers.hpp>

namespace desfire {
    namespace {
        using mlab::make_range;
    }

    struct cipher_provider {
        [[nodiscard]] virtual std::unique_ptr<cipher> setup_from_key(any_key const &key) = 0;
        virtual ~cipher_provider() = default;
    };

    template <class CryptoDES, class Crypto2K3DES, class Crypto3K3DES, class CryptoAES>
    struct typed_cipher_provider final : public cipher_provider {
        static_assert(std::is_base_of_v<crypto_des_base, CryptoDES>);
        static_assert(std::is_base_of_v<crypto_2k3des_base, Crypto2K3DES>);
        static_assert(std::is_base_of_v<crypto_3k3des_base, Crypto3K3DES>);
        static_assert(std::is_base_of_v<crypto_aes_base, CryptoAES>);

        [[nodiscard]] std::unique_ptr<cipher> setup_from_key(any_key const &key) override;
    };
}

namespace desfire {

    template <class CryptoDES, class Crypto2K3DES, class Crypto3K3DES, class CryptoAES>
    std::unique_ptr<cipher> typed_cipher_provider<CryptoDES, Crypto2K3DES, Crypto3K3DES, CryptoAES>::setup_from_key(any_key const &key) {
        switch (key.type()) {
            case cipher_type::des: {
                auto crypto = std::make_unique<CryptoDES>();
                crypto->setup_with_key(make_range(key.template get<cipher_type::des>().k));
                return std::make_unique<cipher_legacy>(std::move(crypto));
            }
            case cipher_type::des3_2k: {
                auto crypto = std::make_unique<Crypto2K3DES>();
                crypto->setup_with_key(make_range(key.template get<cipher_type::des3_2k>().k));
                return std::make_unique<cipher_legacy>(std::move(crypto));
            }
            case cipher_type::des3_3k: {
                auto crypto = std::make_unique<Crypto3K3DES>();
                crypto->setup_with_key(make_range(key.template get<cipher_type::des3_3k>().k));
                return std::make_unique<cipher_default>(std::move(crypto));
            }
            case cipher_type::aes128: {
                auto crypto = std::make_unique<CryptoAES>();
                crypto->setup_with_key(make_range(key.template get<cipher_type::aes128>().k));
                return std::make_unique<cipher_default>(std::move(crypto));
            }
            case cipher_type::none:
                return std::make_unique<cipher_dummy>();
        }
    }
}// namespace desfire

#endif//DESFIRE_CIPHER_PROVIDER_HPP
