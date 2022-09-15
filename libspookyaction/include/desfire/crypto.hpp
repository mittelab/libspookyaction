//
// Created by spak on 5/6/21.
//

#ifndef DESFIRE_CRYPTO_HPP
#define DESFIRE_CRYPTO_HPP

#include <cstdint>
#include <desfire/bits.hpp>
#include <desfire/cmac_provider.hpp>
#include <mlab/bin_data.hpp>

namespace desfire {
    namespace {
        using mlab::bin_data;
        using mlab::range;
    }// namespace
    using bits::cipher_type;

    /**
     * @brief Cryptographic operations that have to be implemented by @ref crypto.
     */
    enum struct crypto_operation {
        encrypt,///<Encryption, data is transformed into a cyphertext
        decrypt,///<Decryption, cyphertext is transformed into plaintext
        mac     ///<Message authentication, a cryptographically secure authentication code is produced from plaintext
    };

    /**
     * @brief Class that abstracts the primitive cryptographic implementation of a given @ref cipher_type.
     *
     * Different platforms may provide different implementation depending on what hardware and library features they
     * might offer. Note that this is distinct from @ref cipher. While @ref cipher provides the mechanisms for managing
     * messages in a protected session, @ref crypto **only** provides the cryptographic implementation for encryption,
     * decryption, MACing, and CMACing for the subclass @ref crypto_with_cmac.
     * @note We recommend to inherit from one of @ref crypto_des_base, @ref crypto_2k3des_base, @ref crypto_3k3des_base,
     * @ref crypto_aes_base, since these classes already do much of the heavy lifting required for these ciphers, and
     * subclasses must provide only the cryptographic primitives.
     * @see crypto_with_cmac
     * @see cipher
     * @see cipher_legacy
     */
    class crypto {
    public:
        /**
         * @brief Cipher implemented by this cryptographic implementation.
         * @return One of the supported @ref cipher_type.
         */
        [[nodiscard]] virtual desfire::cipher_type cipher_type() const = 0;

        /**
         * @brief Sets the key to be used from now on in this cryptographic implementation.
         *
         * This method should do all the setup needed for further operations, i.e. setting the key in the internal
         * cryptographic primitives, resetting or setting initialization vectors, deriving CMAC keys where needed.
         * This method should be called by @ref init_session as soon as it has derived the key from the random data.
         * @param key Range of bytes containing the key to use for the following operations. This is specified as a
         *  range on raw bytes for convenience, as the underlying cryptographic functions are likely low level.
         */
        virtual void setup_with_key(range<std::uint8_t const *> key) = 0;

        /**
         * @brief Begins a new session by deriving the session key from @p random_data and calling @ref setup_with_key.
         *
         * This method should do the appropriate operations to derive a session key from the data @p random_data which
         * was obtained as a consequence of the key exchange protocol between the two parties. These usually consist
         * in byte shift and rearrangement.
         * @note Implementations of this method must then call manually @ref setup_with_key in order to complete the
         *  session initialization process.
         * @param random_data Range of bytes containing the random data exchanged by the two parties. This has to be
         *  used to derive the session key. This is specified as a range on raw bytes for convenience, as the underlying
         *  cryptographic functions are likely low level.
         */
        virtual void init_session(range<std::uint8_t const *> random_data) = 0;

        /**
         * @brief Performs a supported cryptographic operation on the given data and initialization vector.
         * @param data Input data (plaintext for @ref crypto_operation::encrypt and @ref crypto_operation::mac, and
         *  ciphertext for @ref crypto_operation::decrypt). This data is modified and upon exit will contain the
         *  resulting ciphertext or plaintext, respectively, therefore this must be already padded and resized to the
         *  next multiple of the block size according to @ref cipher_type.
         * @param iv Initialization vector to use during the cryptographic operation. This must the the right size
         *  depending on the block size of this implementation's @ref cipher_type, and will be overwritten by the
         *  cryptographic algorithm (i.e. upon exit it is transformed).
         * @param op Cryptographic operation to perform.
         */
        virtual void do_crypto(range<std::uint8_t *> data, range<std::uint8_t *> iv, crypto_operation op) = 0;
        virtual ~crypto() = default;
    };

    /**
     * @brief Abstract class that extends @ref crypto providing CMAC capabilities.
     *
     * This is the base class for modern 3K3DES and AES128 ciphers, and uses internally @ref cmac_provider.
     * Subclasses should
     * -# Still provide the correct @ref crypto_operation::mac implementation through @ref crypto::do_crypto, as this
     *     is used as a subroutine of the more sophisticated @ref do_cmac function.
     * -# Correctly setup this class via the protected constructor @ref crypto_with_cmac::crypto_with_cmac, since some
     *     information on the block size and a given magic number is required to correctly compute the CMAC.
     * -# Avoid overriding @ref setup_with_key, since the implementation provided by this class does also CMAC subkey
     *     derivation. Instead, they should implement @ref setup_primitives_with_key, with the same effect and extents
     *     as @ref crypto::setup_with_key.
     *
     * @warning It is **not** correct to use this class through its base interface @ref crypto! Protocols and ciphers
     * that use CMAC-enabled crypto **should** use directly @ref do_cmac and this class. The reason is that these
     * ciphers require the initialization vector to be in sync with the Desfire card throughout the session, and the IV
     * is updated by a CMAC operation. Therefore, calling e.g. @ref do_crypto naively with a @ref crypto_operation::mac
     * would throw the IV out of sync. Therefore, CMAC-enabled cryptographic implementation are supposed to be used as
     * such and not through the lower abstraction layer.
     * @see crypto
     * @see cmac_provider
     * @see cipher_default
     */
    class crypto_with_cmac : public crypto {
        cmac_provider _cmac;

    protected:
        /**
         * @brief Initializes the CMAC-enabled class.
         * @param block_size Size of the cipher block. This is passed directly to @ref cmac_provider::cmac_provider.
         * @param last_byte_xor When deriving the key, if the MSB is 1, the last byte is XOR-ed with this value. I have
         *  no clue about why we have to do this, maybe some nice key pre-conditioning to resist certain attacks? I do
         *  not know, but it is a constant specific to the cipher used. This is passed directly to
         *  @ref cmac_provider::cmac_provider.
         * @see cmac_provider::cmac_provider
         */
        crypto_with_cmac(std::uint8_t block_size, std::uint8_t last_byte_xor);

        /**
         * @brief Subclasses should implement this instead of @ref setup_with_key, to the same effect.
         *
         * This method is called by the custom implementation of @ref setup_with_key provided in this class, right
         * before key derivation is performed, with the same parameters.
         * @param key Range of bytes containing the key to use for the following operations. This is specified as a
         *  range on raw bytes for convenience, as the underlying cryptographic functions are likely low level.
         */
        virtual void setup_primitives_with_key(range<std::uint8_t const *> key) = 0;

        /**
         * @addtogroup PrepareCMACData
         * @{
         * @brief Identical to @ref cmac_keychain::prepare_cmac_data.
         *
         * @see cmac_keychain::prepare_cmac_data
         */
        void prepare_cmac_data(bin_data &data) const;
        void prepare_cmac_data(bin_data &data, std::size_t desired_padded_length) const;
        /**
         * @}
         */

    public:
        /**
         * @brief The type of the CMAC MAC code, which is a fixed 8 bytes sequence.
         */
        using mac_t = std::array<std::uint8_t, 8>;

        virtual mac_t do_cmac(range<std::uint8_t const *> data, range<std::uint8_t *> iv);

        /**
         * @brief Block size for this cipher. This is specified upon construction and is cipher-specific.
         * @return Size in bytes of the underlying block cipher.
         */
        [[nodiscard]] std::size_t block_size() const;

        /**
         * @brief CMAC-enabled implementation of @ref crypto::setup_with_key.
         *
         * This method first of all calls @ref setup_primitives_with_key and right afterwards generates CMAC subkeys
         * for the internal @ref cmac_provider.
         * @warning Subclasses should leave this method alone and instead implement @ref setup_primitives_with_key.
         * @param key Range of bytes containing the key to use for the following operations. This is specified as a
         *  range on raw bytes for convenience, as the underlying cryptographic functions are likely low level.
         */
        void setup_with_key(range<std::uint8_t const *> key) override;
    };

    /**
     * @brief Base class for a DES cryptographic implementation. Inherit from this.
     *
     * Compared to @ref crypto, this class fixes the @ref cipher_type and provides the implementation of the session
     * key derivation function @ref init_session (which then calls @ref setup_with_key). Subclasses should then
     * implement only @ref setup_with_key and @ref do_crypto.
     */
    class crypto_des_base : public crypto {
    public:
        [[nodiscard]] inline desfire::cipher_type cipher_type() const final;

        /**
         * @brief Implementation of DES session key derivation; will internally call @ref setup_with_key.
         */
        void init_session(range<std::uint8_t const *> random_data) final;
    };

    /**
     * @brief Base class for a 2K3DES cryptographic implementation. Inherit from this.
     *
     * Compared to @ref crypto, this class fixes the @ref cipher_type and provides the implementation of the session
     * key derivation function @ref init_session (which then calls @ref setup_with_key). Moreover, 2K3DES has a special
     * behavior, because the two halves of the 16-bytes key are identical (except version bits), then 2K3DES falls back
     * onto plain old DES ciphers. This is a property of the cryptographic function, but there is a catch: once a 2K3DES
     * crypto object has been set up with a DES key, it becomes a DES cipher and therefore will also derive always
     * DES keys (or equivalently, 2K3DES keys with identical halves) even from the random session data. Therefore, this
     * class also implements @ref setup_with_key in order to detect "degenerate" DES keys and modify the behavior of the
     * future calls to @ref init_session accordingly.
     * Subclasses should thus implement @ref setup_primitives_with_key instead of @ref setup_with_key, as well as
     * @ref do_crypto.
     */
    class crypto_2k3des_base : public crypto {
        bool _degenerate;
        std::uint8_t _key_version;
        cmac_keychain _diversification_keychain;

    protected:
        /**
         * @brief Subclasses should implement this instead of @ref setup_with_key, to the same effect.
         *
         * This method is called by the custom implementation of @ref setup_with_key provided in this class, with the
         * same parameters, right after detecting whether the key is degenerate and updating @ref is_degenerate.
         * @param key Range of bytes containing the key to use for the following operations. This is specified as a
         *  range on raw bytes for convenience, as the underlying cryptographic functions are likely low level.
         */
        virtual void setup_primitives_with_key(range<std::uint8_t const *> key) = 0;

    public:
        crypto_2k3des_base();

        /**
         * @brief True if a 2K3DES key with identical halves (up to parity bits) was used in @ref setup_with_key.
         *
         * When a 2K3DES cipher is set up with identical halves, it turns into a DES cipher.
         * @return True iff this cipher now behaves as a simple DES.
         */
        [[nodiscard]] inline bool is_degenerate() const;

        [[nodiscard]] inline desfire::cipher_type cipher_type() const final;

        /**
         * @brief Custom implementation that detects and flags degenerate DES keys.
         *
         * Subclasses should implement instead @ref setup_primitives_with_key. Once a degenerate key is detected, this
         * crypto class behaves as a DES cryptographic implementation and the flag @ref is_degenerate is set.
         * @param key Range of bytes containing the key to use for the following operations. This is specified as a
         *  range on raw bytes for convenience, as the underlying cryptographic functions are likely low level.
         */
        void setup_with_key(range<std::uint8_t const *> key) final;

        /**
         * @brief Implementation of 2K3DES session key derivation; will internally call @ref setup_primitives_with_key.
         */
        void init_session(range<std::uint8_t const *> random_data) final;

        std::array<std::uint8_t, 16> diversify_key_an10922(bin_data &diversification_input);
    };

    /**
     * @brief Base class for a 3K3DES cryptographic implementation. Inherit from this.
     *
     * Compared to @ref crypto_with_cmac, this class fixes the @ref cipher_type and provides the implementation of the
     * session key derivation function @ref init_session (which then calls @ref setup_primitives_with_key). Subclasses
     * should then implement only @ref setup_primitives_with_key and @ref do_crypto.
     */
    class crypto_3k3des_base : public crypto_with_cmac {
        std::uint8_t _key_version;
    public:
        crypto_3k3des_base();
        [[nodiscard]] inline desfire::cipher_type cipher_type() const final;
        void init_session(range<std::uint8_t const *> random_data) final;
        void setup_with_key(range<std::uint8_t const *> key) override;

        std::array<std::uint8_t, 24> diversify_key_an10922(bin_data &diversification_input);
    };

    /**
     * @brief Base class for a AES128 cryptographic implementation. Inherit from this.
     *
     * Compared to @ref crypto_with_cmac, this class fixes the @ref cipher_type and provides the implementation of the
     * session key derivation function @ref init_session (which then calls @ref setup_primitives_with_key). Subclasses
     * should then implement only @ref setup_primitives_with_key and @ref do_crypto.
     */
    class crypto_aes_base : public crypto_with_cmac {
    public:
        crypto_aes_base();
        [[nodiscard]] inline desfire::cipher_type cipher_type() const final;
        void init_session(range<std::uint8_t const *> random_data) final;

        /**
         * @brief Performs key diversification as in specified in AN10922.
         *
         * Derives a new secure key from the current key in use in @ref crypto_aes_base and @p diversification_input.
         * Does not alter the logical state of @ref crypto_aes_base, meaning it does not disrupt a working session and can
         * be called at any time.
         *
         * @param diversification_input Diversification data. Will be modified by cryptographic operations.
         * @return A new key derived from the given data.
         */
        std::array<std::uint8_t, 16> diversify_key_an10922(bin_data &diversification_input);
    };

}// namespace desfire

namespace desfire {
    bool crypto_2k3des_base::is_degenerate() const {
        return _degenerate;
    }

    desfire::cipher_type crypto_des_base::cipher_type() const {
        return cipher_type::des;
    }

    desfire::cipher_type crypto_2k3des_base::cipher_type() const {
        return cipher_type::des3_2k;
    }

    desfire::cipher_type crypto_3k3des_base::cipher_type() const {
        return cipher_type::des3_3k;
    }

    desfire::cipher_type crypto_aes_base::cipher_type() const {
        return cipher_type::aes128;
    }

}// namespace desfire

#endif//DESFIRE_CRYPTO_HPP
