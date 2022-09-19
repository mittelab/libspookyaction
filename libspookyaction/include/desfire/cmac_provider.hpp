//
// Created by spak on 5/8/21.
//

#ifndef DESFIRE_CRYPTO_CMAC_HPP
#define DESFIRE_CRYPTO_CMAC_HPP

#include <memory>
#include <mlab/bin_data.hpp>
#include <mlab/pool.hpp>

namespace desfire {

    namespace {
        using mlab::bin_data;
        using mlab::range;
    }// namespace

    class crypto;

    /**
     * @brief Class which holds and derives subkeys to use when computing CMAC.
     *
     * CMAC as used by Desfire pads and xors the data with two different keys, derived from the cryptographic
     * implementation (by encrypting sequences of zeroes). This class manages the subkeys for CMAC operations.
     */
    class cmac_keychain {
        std::size_t _block_size;
        std::uint8_t _last_byte_xor;
        std::unique_ptr<std::uint8_t[]> _subkey_pad;
        std::unique_ptr<std::uint8_t[]> _subkey_nopad;

    public:
        /**
         * @brief Initialize a new CMAC keychain with zero subkeys.
         *
         * @param block_size Size of the block used in the @ref crypto object (8 bytes for 3K3DES, 16 for AES128).
         * @param last_byte_xor Used in subkey generation, this is specific to the Desfire implementation. Refer to
         *  @ref prepare_subkey for more details; the values used are @ref desfire::bits::crypto_cmac_xor_byte_3k3des
         *  for 3K3DES, and @ref desfire::bits::crypto_cmac_xor_byte_aes for AES128.
         *
         * @see prepare_subkey
         * @see desfire::bits::crypto_cmac_xor_byte_3k3des
         * @see desfire::bits::crypto_cmac_xor_byte_aes
         */
        inline cmac_keychain(std::size_t block_size, std::uint8_t last_byte_xor);

        /**
         * @brief Key to use for messages that need padding.
         */
        [[nodiscard]] inline range<std::uint8_t *> key_pad() const;

        /**
         * @brief Key to use for messages that do not need padding.
         */
        [[nodiscard]] inline range<std::uint8_t *> key_nopad() const;

        /**
         * @brief Block size of the underlying @ref crypto implementation.
         * @return The block size in bytes specified in @ref cmac_provider::cmac_provider.
         */
        [[nodiscard]] inline std::size_t block_size() const;

        /**
         * @brief The value used in subkey generation for the underlying @ref crypto implementation.
         * @return The value specified in @ref cmac_provider::cmac_provider.
         *
         * @see prepare_subkey
         * @see desfire::bits::crypto_cmac_xor_byte_3k3des
         * @see desfire::bits::crypto_cmac_xor_byte_aes
         */
        [[nodiscard]] inline std::uint8_t last_byte_xor() const;

        /**
         * @brief Transform a cryptogram into a subkey to use for CMACing.
         *
         * This seems to be something specific to Desfire. First some cryptographic operation is performed, then the
         * result is shifted and if the MSB is 1, the last byte is XORed with @p last_byte_xor. Maybe it is done to
         * precondition the algorithm to be more resistant?
         *
         * @param subkey Cryptogram resulting from running a regular @ref crypto_operation::mac on the appropriate IV.
         *  Upon exit, this contains the result (the shift and XOR operations are performed in-place on this range).
         * @param last_byte_xor Value that is XORed with the last byte if the MSB of the shifted @p subkey is 1.
         */
        static void prepare_subkey(range<std::uint8_t *> subkey, std::uint8_t last_byte_xor);

        /**
         * @brief Recomputes the subkeys.
         *
         * This method performs the following key-derivation operations:
         * -# Call @ref crypto::do_crypto with @ref crypto_operation::mac, a zero-filled IV and a zero-filled data.
         * -# Pass the result through @ref prepare_subkey with @ref last_byte_xor. This produces the first key that is
         *  used for messages that need padding.
         * -# Pass the newly generated key through @ref prepare_subkey again, with @ref last_byte_xor. This produces the
         *  second key, that is used for messages that do not need padding.
         *
         * @param crypto Cryptographic implementation to use for deriving the keys. Make sure that the block size matches
         *  to what used in the constructor (i.e. @ref block_size).
         *
         * @note This method actually performs cryptographic operations via @ref crypto::do_crypto in order to derive
         * the subkeys used in the CMAC operation. This is the reason why it's not performed automatically in the
         * constructor: the crypto object in the constructor is allowed to not be fully initialized at that point in
         * time. However, it must be fully initialized when this method is called. The rationale is that this class
         * might be used as a member variable in some @ref crypto subclass: since it's abstract, we first need to
         * initialize the subclass in order to have full access to @ref crypto::do_crypto, and thus we perform
         * delayed subkey initialization.
         */
        void initialize_subkeys(crypto &crypto);

        /**
         * @brief Prepares data for CMAC operation by padding it and XORing with the appropriate key.
         *
         * This performs a subset of the operations of @ref compute_cmac, namely:
         * -# Pads @p data with `80 00 .. 00`.
         * -# XORs the last block with the appropriate key, depending on whether it was padded or not.
         *
         * @param data Data to pad and XOR, modified in-place. Will be resized to a multiple of @ref block_size.
         *
         * @see compute_cmac
         */
        void prepare_cmac_data(bin_data &data) const;

        /**
         * @brief Prepares data for CMAC operation by padding it and XORing with the appropriate key.
         *
         * This performs a subset of the operations of @ref compute_cmac, namely:
         * -# Pads @p data with `80 00 .. 00` up to @p desired_padded_length.
         * -# XORs the last block with the appropriate key, depending on whether it was padded or not.
         *
         * @param data Data to pad and XOR, modified in-place. Will be resized to a multiple of the block size.
         * @param desired_padded_length Minimum length for the padded message. Will be rounded to the next multiple of @ref block_size.
         *
         * @see compute_cmac
         */
        void prepare_cmac_data(bin_data &data, std::size_t desired_padded_length) const;
    };

    /**
     * @brief Class tasked with computing CMACs using a @ref crypto implementation.
     *
     * CMAC codes are actually used only for more modern ciphers, like 3DES and AES128, but in principle can be computed
     * on any @ref crypto implementation. This is used internally by @ref crypto_aes_base and @ref crypto_3k3des_base.
     * @see crypto_aes_base
     * @see crypto_3k3des_base
     */
    class cmac_provider {
        cmac_keychain _keychain;
        std::shared_ptr<mlab::pool<bin_data>> _buffer_pool;

    public:
        /**
         * @brief All CMAC codes are 8 bytes long.
         */
        using mac_t = std::array<std::uint8_t, 8>;

        /**
         * @brief Initialize a new CMAC provider.
         *
         * You must call @ref initialize_subkeys before @ref compute_cmac can be used.
         *
         * @param block_size Size of the block used in the @ref crypto object (8 bytes for 3K3DES, 16 for AES128).
         * @param last_byte_xor Used in subkey generation, this is specific to the Desfire implementation. Refer to
         *  @ref prepare_subkey for more details; the values used are @ref desfire::bits::crypto_cmac_xor_byte_3k3des
         *  for 3K3DES, and @ref desfire::bits::crypto_cmac_xor_byte_aes for AES128.
         *
         * @see cmac_keychain::cmac_keychain
         * @see cmac_keychain::prepare_subkey
         * @see desfire::bits::crypto_cmac_xor_byte_3k3des
         * @see desfire::bits::crypto_cmac_xor_byte_aes
         */
        inline cmac_provider(std::size_t block_size, std::uint8_t last_byte_xor);

        /**
         * @brief Returns the keychain that holds the keys used for computing a CMAC.
         *
         * @see cmac_keychain::prepare_cmac_data
         */
        [[nodiscard]] inline cmac_keychain const &keychain() const;

        /**
         * @brief Computes the subkeys that will be used for @ref compute_cmac.
         *
         * You must call this method before using @ref compute_cmac, otherwise the subkeys used in the CMAC will
         * be zero-initialized and this will not only compute an incorrect CMAC, but it will also mangle the
         * initialization vector, invalidating the whole session.
         *
         * This method is identical to @ref cmac_keychain::initialize_subkeys.
         *
         * @see cmac_keychain::initialize_subkeys
         */
        void initialize_subkeys(crypto &crypto);

        /**
         * @brief Compute a CMAC on the given range of data.
         *
         * Make sure that the subkeys are initialized with @ref initialize_subkeys before calling.
         * This method performs the following operations:
         * -# Pads @p data with `80 00 .. 00`.
         * -# XORs the last block with the appropriate key, depending on whether it was padded or not.
         * -# Calls @ref crypto::do_crypto with @ref crypto_operation::mac on the resulting data together with @p iv.
         * -# The first 8 bytes of the resulting @p iv are the CMAC that is returned.
         *
         * @param crypto Cryptographic implementation to use for deriving the keys. Make sure that the block size matches
         *  to what used in the constructor (i.e. @ref block_size).
         * @param iv Initialization vector to use. This method passes the initialization vector to the
         *  method @ref crypto::do_crypto, therefore upon exit it is modified accordingly (and should contain the
         *  resulting initialization vector state after the cryptographic operation).
         * @param data Data to compute the CMAC on.
         *
         * @return A 8-byte message authentication code.
         */
        mac_t compute_cmac(crypto &crypto, range<std::uint8_t *> iv, range<std::uint8_t const *> data);
    };
}// namespace desfire

namespace desfire {
    cmac_provider::cmac_provider(std::size_t block_size, std::uint8_t last_byte_xor)
        : _keychain{block_size, last_byte_xor} {}

    cmac_keychain::cmac_keychain(std::size_t block_size, std::uint8_t last_byte_xor)
        : _block_size{block_size},
          _last_byte_xor{last_byte_xor},
          _subkey_pad{std::make_unique<std::uint8_t[]>(static_cast<std::size_t>(block_size))},
          _subkey_nopad{std::make_unique<std::uint8_t[]>(static_cast<std::size_t>(block_size))} {}

    std::size_t cmac_keychain::block_size() const {
        return _block_size;
    }

    std::uint8_t cmac_keychain::last_byte_xor() const {
        return _last_byte_xor;
    }

    range<std::uint8_t *> cmac_keychain::key_pad() const {
        return {_subkey_pad.get(), _subkey_pad.get() + block_size()};
    }

    range<std::uint8_t *> cmac_keychain::key_nopad() const {
        return {_subkey_nopad.get(), _subkey_nopad.get() + block_size()};
    }

    cmac_keychain const &cmac_provider::keychain() const {
        return _keychain;
    }

}// namespace desfire
#endif//DESFIRE_CRYPTO_CMAC_HPP
