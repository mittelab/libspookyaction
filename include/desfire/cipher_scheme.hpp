//
// Created by Pietro Saccardi on 02/01/2021.
//

#ifndef DESFIRE_CIPHER_SCHEME_HPP
#define DESFIRE_CIPHER_SCHEME_HPP

#include "cipher.hpp"
#include "crypto_algo.hpp"

namespace desfire {

    /**
     * @todo Add a note explaining why we set a decipherement key on the encryption context and why we decrypt.
     */
    class cipher_legacy_scheme : public virtual cipher, public cipher_traits<8, 4, 2> {
        block_t _global_iv;

        block_t &get_iv();
    public:
        cipher_legacy_scheme();

        void initialize();

        /**
         *
         * @param data Data to cipher, in-place. Must have a size that is a multiple of @ref block_size.
         * @param encrypt True to encrypt, false to decrypt
         * @param iv Initialization vector to use; modified in place.
         */
        virtual void do_crypto(range<bin_data::iterator> data, bool encrypt, block_t &iv) = 0;

        /**
         * Returns the first @ref mac_length bytes of the IV after encrypting @p data.
         */
        mac_t compute_mac(range<bin_data::const_iterator> data);

        static bool drop_padding_verify_crc(bin_data &d);

        void prepare_tx(bin_data &data, std::size_t offset, config const &cfg) final;

        bool confirm_rx(bin_data &data, config const &cfg) final;

    };

    template <std::size_t BlockSize, std::uint8_t CMACSubkeyR>
    class cipher_scheme : public virtual cipher, public cipher_traits<BlockSize, 8, 4> {
    public:
        using traits_base = cipher_traits<BlockSize, 8, 4>;
        using typename traits_base::mac_t;
        using typename traits_base::crc_t;
        using typename traits_base::block_t;

        using traits_base::crc_size;
        using traits_base::block_size;

    private:
        static constexpr std::uint8_t cmac_subkey_r = CMACSubkeyR;
        using cmac_subkey_t = std::array<std::uint8_t, block_size>;

        cmac_subkey_t _cmac_subkey_pad;
        cmac_subkey_t _cmac_subkey_nopad;
        block_t _global_iv;

        block_t &get_iv();

    protected:
        cipher_scheme();

        /**
         * Another oddity of how the Mifare CMAC stuff is implemented. This method shall perform a **DEcipherment**
         * operation with the current **ENcipherment** key on block of ''BlockSize'' zeroes, using zeroes as IV. In
         * pseudocode:
         * @code
         * crypto_context ctx;
         * crypto_context_set_key_encipherement(&ctx, <current key>);  // Or may reuse the crypto context of ::do_crypto
         * block_t data = {0, ... 0}, iv = {0, ... 0};
         * crypto_decipher(&ctx, &data, &iv);
         * return data;
         * @endcode
         * @warning What I wrote above is a lie. Other implementations (Easypay, RFDoorLock) use decipherment operations
         * with encipherment keys, however by trial and error, I figured that AES128 actually does the opposite, needs
         * an encryption operation with a decipherment keys. Interestingly enough, the AES128 implementation produces
         * the same CMAC keys as Easypay, but 3DES produces entirely different keys instead. What is funny enough, is
         * that those keys actually work. I have no clue why. Most likely some Xoring magic occurring inside 3DES?
         */
        virtual block_t derive_cmac_base_data() = 0;

        /**
         * @note **Subclassing guide:** subclasses shall call this method as last in the constructor, and as last in
         * @ref reinit_with_session_Key. This method will derive CMAC keys, therefore all crypto primitives shall be
         * in place before performing this call.
         */
        void initialize();

    public:
        virtual void do_crypto(range<bin_data::iterator> data, bool encrypt, block_t &iv) = 0;

        mac_t compute_mac(range<bin_data::const_iterator> data);

        /**
         * @param status The CRC is always computed on ''data || status'', so we always need to update it for that
         */
        bool drop_padding_verify_crc(bin_data &d, std::uint8_t status);

        void prepare_tx(bin_data &data, std::size_t offset, config const &cfg) final;

        bool confirm_rx(bin_data &data, config const &cfg) final;

    };


}

#endif //DESFIRE_CIPHER_SCHEME_HPP
