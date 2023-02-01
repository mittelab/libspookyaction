//
// Created by spak on 5/10/21.
//

#ifndef DESFIRE_CIPHER_PROVIDER_HPP
#define DESFIRE_CIPHER_PROVIDER_HPP

#include <desfire/cipher.hpp>
#include <desfire/data.hpp>
#include <desfire/keys.hpp>

namespace desfire {
    namespace {
        using mlab::make_range;
    }

    struct cipher_provider {
        [[nodiscard]] virtual std::unique_ptr<cipher> cipher_from_key(any_key const &key) = 0;
        [[nodiscard]] virtual std::unique_ptr<crypto> crypto_from_key(any_key const &key) = 0;

        virtual ~cipher_provider() = default;
    };

    template <class CryptoDES, class Crypto2K3DES, class Crypto3K3DES, class CryptoAES,
              class CipherDES = cipher_legacy, class Cipher2K3DES = cipher_legacy,
              class Cipher3K3DES = cipher_default, class CipherAES = cipher_default>
    struct typed_cipher_provider final : public cipher_provider {
        static_assert(std::is_base_of_v<crypto, CryptoDES>);
        static_assert(std::is_base_of_v<crypto, Crypto2K3DES>);
        static_assert(std::is_base_of_v<crypto, Crypto3K3DES>);
        static_assert(std::is_base_of_v<crypto, CryptoAES>);
        static_assert(std::is_base_of_v<cipher, CipherDES>);
        static_assert(std::is_base_of_v<cipher, Cipher2K3DES>);
        static_assert(std::is_base_of_v<cipher, Cipher3K3DES>);
        static_assert(std::is_base_of_v<cipher, CipherAES>);

        using crypto_des = CryptoDES;
        using crypto_2k3des = Crypto2K3DES;
        using crypto_3k3des = Crypto3K3DES;
        using crypto_aes = CryptoAES;

        using cipher_des = CipherDES;
        using cipher_2k3des = Cipher2K3DES;
        using cipher_3k3des = Cipher3K3DES;
        using cipher_aes = CipherAES;

        [[nodiscard]] std::unique_ptr<cipher> cipher_from_key(any_key const &key) override;
        [[nodiscard]] std::unique_ptr<crypto> crypto_from_key(any_key const &key) override;

        [[nodiscard]] crypto_des typed_crypto_from_key(key<cipher_type::des> const &key) const {
            crypto_des retval{};
            retval.setup_with_key(key.as_range());
            return retval;
        }

        [[nodiscard]] cipher_des typed_cipher_from_key(key<cipher_type::des> const &key) const {
            return cipher_des{typed_crypto_from_key(key)};
        }

        [[nodiscard]] crypto_2k3des typed_crypto_from_key(key<cipher_type::des3_2k> const &key) const {
            crypto_2k3des retval{};
            retval.setup_with_key(key.as_range());
            return retval;
        }

        [[nodiscard]] cipher_2k3des typed_cipher_from_key(key<cipher_type::des3_2k> const &key) const {
            return cipher_2k3des{typed_crypto_from_key(key)};
        }

        [[nodiscard]] crypto_3k3des typed_crypto_from_key(key<cipher_type::des3_3k> const &key) const {
            crypto_3k3des retval{};
            retval.setup_with_key(key.as_range());
            return retval;
        }

        [[nodiscard]] cipher_3k3des typed_cipher_from_key(key<cipher_type::des3_3k> const &key) const {
            return cipher_3k3des{typed_crypto_from_key(key)};
        }

        [[nodiscard]] crypto_aes typed_crypto_from_key(key<cipher_type::aes128> const &key) const {
            crypto_aes retval{};
            retval.setup_with_key(key.as_range());
            return retval;
        }

        [[nodiscard]] cipher_aes typed_cipher_from_key(key<cipher_type::aes128> const &key) const {
            return cipher_aes{typed_crypto_from_key(key)};
        }
    };
}// namespace desfire

namespace desfire {

    template <class CryptoDES, class Crypto2K3DES, class Crypto3K3DES, class CryptoAES,
              class CipherDES, class Cipher2K3DES, class Cipher3K3DES, class CipherAES>
    std::unique_ptr<cipher> typed_cipher_provider<CryptoDES, Crypto2K3DES, Crypto3K3DES, CryptoAES,
                                                  CipherDES, Cipher2K3DES, Cipher3K3DES, CipherAES>::cipher_from_key(any_key const &key) {
        switch (key.type()) {
            case cipher_type::des: {
                auto crypto = std::make_unique<CryptoDES>();
                crypto->setup_with_key(key.template get<cipher_type::des>().as_range());
                return std::make_unique<CipherDES>(std::move(crypto));
            }
            case cipher_type::des3_2k: {
                auto crypto = std::make_unique<Crypto2K3DES>();
                crypto->setup_with_key(key.template get<cipher_type::des3_2k>().as_range());
                return std::make_unique<Cipher2K3DES>(std::move(crypto));
            }
            case cipher_type::des3_3k: {
                auto crypto = std::make_unique<Crypto3K3DES>();
                crypto->setup_with_key(key.template get<cipher_type::des3_3k>().as_range());
                return std::make_unique<Cipher3K3DES>(std::move(crypto));
            }
            case cipher_type::aes128: {
                auto crypto = std::make_unique<CryptoAES>();
                crypto->setup_with_key(key.template get<cipher_type::aes128>().as_range());
                return std::make_unique<CipherAES>(std::move(crypto));
            }
            case cipher_type::none:
                [[fallthrough]];
            default:
                return std::make_unique<cipher_dummy>();
        }
    }
    template <class CryptoDES, class Crypto2K3DES, class Crypto3K3DES, class CryptoAES,
              class CipherDES, class Cipher2K3DES, class Cipher3K3DES, class CipherAES>
    std::unique_ptr<crypto> typed_cipher_provider<CryptoDES, Crypto2K3DES, Crypto3K3DES, CryptoAES,
                                                  CipherDES, Cipher2K3DES, Cipher3K3DES, CipherAES>::crypto_from_key(any_key const &key) {
        switch (key.type()) {
            case cipher_type::des: {
                auto crypto = std::make_unique<CryptoDES>();
                crypto->setup_with_key(key.template get<cipher_type::des>().as_range());
                return crypto;
            }
            case cipher_type::des3_2k: {
                auto crypto = std::make_unique<Crypto2K3DES>();
                crypto->setup_with_key(key.template get<cipher_type::des3_2k>().as_range());
                return crypto;
            }
            case cipher_type::des3_3k: {
                auto crypto = std::make_unique<Crypto3K3DES>();
                crypto->setup_with_key(key.template get<cipher_type::des3_3k>().as_range());
                return crypto;
            }
            case cipher_type::aes128: {
                auto crypto = std::make_unique<CryptoAES>();
                crypto->setup_with_key(key.template get<cipher_type::aes128>().as_range());
                return crypto;
            }
            case cipher_type::none:
                [[fallthrough]];
            default:
                return nullptr;
        }
    }
}// namespace desfire

#endif//DESFIRE_CIPHER_PROVIDER_HPP
