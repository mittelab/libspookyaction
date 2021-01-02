//
// Created by Pietro Saccardi on 02/01/2021.
//

#ifndef DESFIRE_CIPHER_SCHEME_HPP
#define DESFIRE_CIPHER_SCHEME_HPP

#include "cipher.hpp"

namespace desfire {

    class cipher_legacy_scheme : public virtual cipher, public cipher_traits<8, 4, 2> {
    protected:
        static constexpr std::uint16_t crc_init = 0x6363;

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

        static crc_t compute_crc(range<bin_data::const_iterator> data, std::uint16_t init);

        static bool drop_padding_verify_crc(bin_data &d);

        void prepare_tx(bin_data &data, std::size_t offset, config const &cfg) final;

        bool confirm_rx(bin_data &data, config const &cfg) final;

        void encrypt(bin_data &data) final;

        void decrypt(bin_data &data) final;

        static block_t &get_null_iv() ;
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

    protected:
        static constexpr std::uint32_t crc_init = 0xffffffff;

        cipher_scheme();

        void generate_cmac_subkeys();

        virtual void do_crypto(range<bin_data::iterator> data, bool encrypt, block_t &iv) = 0;

        mac_t compute_mac(range<bin_data::const_iterator> data);

        /**
         * Computes the CRC32 of @p data, returns LSB first.
         */
        crc_t compute_crc(range<bin_data::const_iterator> data, std::uint32_t init);

        /**
         * @param status The CRC is always computed on ''data || status'', so we always need to update it for that
         */
        bool drop_padding_verify_crc(bin_data &d, std::uint8_t status);

        void prepare_tx(bin_data &data, std::size_t offset, config const &cfg) final;

        bool confirm_rx(bin_data &data, config const &cfg) final;

        void encrypt(bin_data &data) final;

        void decrypt(bin_data &data) final;

    };


}

#endif //DESFIRE_CIPHER_SCHEME_HPP
