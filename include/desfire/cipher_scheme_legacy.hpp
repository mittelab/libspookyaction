//
// Created by Pietro Saccardi on 02/01/2021.
//

#ifndef DESFIRE_CIPHER_SCHEME_LEGACY_HPP
#define DESFIRE_CIPHER_SCHEME_LEGACY_HPP

#include "cipher.hpp"
#include "crypto_algo.hpp"

namespace desfire {

    /**
     * @todo Add a note explaining why we set a decipherement key on the encryption context and why we decrypt.
     */
    class cipher_scheme_legacy : public virtual cipher, public cipher_traits<8, 4, 2> {
        block_t _global_iv;

        block_t &get_iv();

    public:
        cipher_scheme_legacy();

        void initialize();

        /**
         *
         * @param data Data to cipher, in-place. Must have a size that is a multiple of @ref block_size.
         * @param encrypt True to encrypt, false to decrypt
         * @param iv Initialization vector to use; modified in place.
         */
        virtual void do_crypto(range<bin_data::iterator> const &data, crypto_direction dir, block_t &iv) = 0;

        /**
         * Returns the first @ref mac_length bytes of the IV after encrypting @p data.
         */
        mac_t compute_mac(range<bin_data::const_iterator> const &data);

        static bool drop_padding_verify_crc(bin_data &d);

        void prepare_tx(bin_data &data, std::size_t offset, cipher_mode mode) final;

        bool confirm_rx(bin_data &data, cipher_mode mode) final;
    };

}// namespace desfire

#endif//DESFIRE_CIPHER_SCHEME_LEGACY_HPP
