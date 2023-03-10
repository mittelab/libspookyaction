//
// Created by spak on 5/10/21.
//

#ifndef DESFIRE_CIPHER_PROVIDER_HPP
#define DESFIRE_CIPHER_PROVIDER_HPP

#include <desfire/data.hpp>
#include <desfire/keys.hpp>
#include <desfire/protocol.hpp>

namespace desfire {
    /**
     * @brief Class that abstracts providing a @ref protocol and a @ref crypto for a @p key.
     * This is used to erase or hide the implementation from the user, so that we can have multiple architectures
     * or multiple backend crypto libraries.
     * It is meant to be used through @ref typed_cipher_provider.
     */
    struct cipher_provider {
        /**
         * Create the @ref protocol associated to the given @p key.
         * @param key Any key.
         * @return A unique pointer to a @ref protocol which is setup with @p key.
         */
        [[nodiscard]] virtual std::unique_ptr<protocol> protocol_from_key(any_key const &key) = 0;

        /**
         * Create the @ref crypto object associated to the given @p key
         * @param key Any key.
         * @return A unique pointer to a @ref crypto object on which @ref crypto::setup_with_key has been called.
         */
        [[nodiscard]] virtual std::unique_ptr<crypto> crypto_from_key(any_key const &key) = 0;

        virtual ~cipher_provider() = default;
    };

    /**
     * @brief Subclass which maps a set of @ref crypto classes and @ref protocol classes onto the given @ref cipher_type.
     * This completes type erasure.
     * @tparam CryptoDES Crypto class to be used with DES keys.
     * @tparam Crypto2K3DES Crypto class to be used with 2K3DES keys.
     * @tparam Crypto3K3DES Crypto class to be used with 3K3DES keys.
     * @tparam CryptoAES Crypto class to be used with AES keys.
     * @tparam ProtocolDES Protocol to be used with DES keys (default @ref protocol_legacy).
     * @tparam Protocol2K3DES Protocol to be used with 2K3DES keys (default @ref protocol_default).
     * @tparam Protocol3K3DES Protocol to be used with 3K3DES keys (default @ref protocol_default).
     * @tparam ProtocolAES Protocol to be used with AES keys (default @ref protocol_default).
     */
    template <class CryptoDES, class Crypto2K3DES, class Crypto3K3DES, class CryptoAES,
              class ProtocolDES = protocol_legacy, class Protocol2K3DES = protocol_legacy,
              class Protocol3K3DES = protocol_default, class ProtocolAES = protocol_default>
    struct typed_cipher_provider final : public cipher_provider {
        static_assert(std::is_base_of_v<crypto, CryptoDES>);
        static_assert(std::is_base_of_v<crypto, Crypto2K3DES>);
        static_assert(std::is_base_of_v<crypto, Crypto3K3DES>);
        static_assert(std::is_base_of_v<crypto, CryptoAES>);
        static_assert(std::is_base_of_v<protocol, ProtocolDES>);
        static_assert(std::is_base_of_v<protocol, Protocol2K3DES>);
        static_assert(std::is_base_of_v<protocol, Protocol3K3DES>);
        static_assert(std::is_base_of_v<protocol, ProtocolAES>);

        using crypto_des = CryptoDES;
        using crypto_2k3des = Crypto2K3DES;
        using crypto_3k3des = Crypto3K3DES;
        using crypto_aes = CryptoAES;

        using protocol_des = ProtocolDES;
        using protocol_2k3des = Protocol2K3DES;
        using protocol_3k3des = Protocol3K3DES;
        using protocol_aes = ProtocolAES;

        /**
         * Default constructs the appropriate @ref crypto based on the specified template parameters,
         * then calls @ref crypto::setup_with_key and returns the appropriate @ref protocol (also based on template
         * parameters) constructed using the @ref crypto object above.
         */
        [[nodiscard]] std::unique_ptr<protocol> protocol_from_key(any_key const &key) override;

        /**
         * Default constructs the appropriate @ref crypto based on the specified template parameters,
         * then calls @ref crypto::setup_with_key and returns it.
         */
        [[nodiscard]] std::unique_ptr<crypto> crypto_from_key(any_key const &key) override;

        /**
         * @copydoc crypto_from_key
         */
        [[nodiscard]] crypto_des typed_crypto_from_key(key<cipher_type::des> const &key) const {
            crypto_des retval{};
            retval.setup_with_key(key.as_range());
            return retval;
        }

        /**
         * @copydoc protocol_from_key
         */
        [[nodiscard]] protocol_des typed_protocol_from_key(key<cipher_type::des> const &key) const {
            return protocol_des{typed_crypto_from_key(key)};
        }

        /**
         * @copydoc crypto_from_key
         */
        [[nodiscard]] crypto_2k3des typed_crypto_from_key(key<cipher_type::des3_2k> const &key) const {
            crypto_2k3des retval{};
            retval.setup_with_key(key.as_range());
            return retval;
        }

        /**
         * @copydoc protocol_from_key
         */
        [[nodiscard]] protocol_2k3des typed_protocol_from_key(key<cipher_type::des3_2k> const &key) const {
            return protocol_2k3des{typed_crypto_from_key(key)};
        }

        /**
         * @copydoc crypto_from_key
         */
        [[nodiscard]] crypto_3k3des typed_crypto_from_key(key<cipher_type::des3_3k> const &key) const {
            crypto_3k3des retval{};
            retval.setup_with_key(key.as_range());
            return retval;
        }

        /**
         * @copydoc protocol_from_key
         */
        [[nodiscard]] protocol_3k3des typed_protocol_from_key(key<cipher_type::des3_3k> const &key) const {
            return protocol_3k3des{typed_crypto_from_key(key)};
        }

        /**
         * @copydoc crypto_from_key
         */
        [[nodiscard]] crypto_aes typed_crypto_from_key(key<cipher_type::aes128> const &key) const {
            crypto_aes retval{};
            retval.setup_with_key(key.as_range());
            return retval;
        }

        /**
         * @copydoc protocol_from_key
         */
        [[nodiscard]] protocol_aes typed_protocol_from_key(key<cipher_type::aes128> const &key) const {
            return protocol_aes{typed_crypto_from_key(key)};
        }
    };
}// namespace desfire

namespace desfire {

    template <class CryptoDES, class Crypto2K3DES, class Crypto3K3DES, class CryptoAES,
              class ProtocolDES, class Protocol2K3DES, class Protocol3K3DES, class ProtocolAES>
    std::unique_ptr<protocol> typed_cipher_provider<CryptoDES, Crypto2K3DES, Crypto3K3DES, CryptoAES,
                                                    ProtocolDES, Protocol2K3DES, Protocol3K3DES, ProtocolAES>::protocol_from_key(any_key const &key) {
        switch (key.type()) {
            case cipher_type::des: {
                auto crypto = std::make_unique<CryptoDES>();
                crypto->setup_with_key(key.template get<cipher_type::des>().as_range());
                return std::make_unique<ProtocolDES>(std::move(crypto));
            }
            case cipher_type::des3_2k: {
                auto crypto = std::make_unique<Crypto2K3DES>();
                crypto->setup_with_key(key.template get<cipher_type::des3_2k>().as_range());
                return std::make_unique<Protocol2K3DES>(std::move(crypto));
            }
            case cipher_type::des3_3k: {
                auto crypto = std::make_unique<Crypto3K3DES>();
                crypto->setup_with_key(key.template get<cipher_type::des3_3k>().as_range());
                return std::make_unique<Protocol3K3DES>(std::move(crypto));
            }
            case cipher_type::aes128: {
                auto crypto = std::make_unique<CryptoAES>();
                crypto->setup_with_key(key.template get<cipher_type::aes128>().as_range());
                return std::make_unique<ProtocolAES>(std::move(crypto));
            }
            case cipher_type::none:
                [[fallthrough]];
            default:
                return std::make_unique<protocol_dummy>();
        }
    }
    template <class CryptoDES, class Crypto2K3DES, class Crypto3K3DES, class CryptoAES,
              class ProtocolDES, class Protocol2K3DES, class Protocol3K3DES, class ProtocolAES>
    std::unique_ptr<crypto> typed_cipher_provider<CryptoDES, Crypto2K3DES, Crypto3K3DES, CryptoAES,
                                                  ProtocolDES, Protocol2K3DES, Protocol3K3DES, ProtocolAES>::crypto_from_key(any_key const &key) {
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
