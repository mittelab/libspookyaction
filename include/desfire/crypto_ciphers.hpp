//
// Created by spak on 5/7/21.
//

#ifndef DESFIRE_CRYPTO_CIPHERS_HPP
#define DESFIRE_CRYPTO_CIPHERS_HPP

#include <desfire/bits.hpp>
#include <desfire/cipher.hpp>
#include <desfire/crypto.hpp>
#include <memory>

namespace desfire {
    using bits::cipher_mode;

    class cipher_legacy final : public cipher {
    public:
        static constexpr std::size_t block_size = 8;
        static constexpr std::size_t mac_size = 4;
        static constexpr std::size_t crc_size = 2;

        using block_t = std::array<std::uint8_t, block_size>;
        using mac_t = std::array<std::uint8_t, mac_size>;

        explicit cipher_legacy(std::unique_ptr<crypto> crypto);

        void prepare_tx(bin_data &data, std::size_t offset, cipher_mode mode) override;
        bool confirm_rx(bin_data &data, cipher_mode mode) override;
        void reinit_with_session_key(bin_data const &rndab) override;

    private:
        [[nodiscard]] block_t &get_zeroed_iv();
        [[nodiscard]] crypto &crypto_provider();

        /**
         * Returns the first @ref mac_length bytes of the IV after encrypting @p data.
         */
        mac_t compute_mac(range<bin_data::const_iterator> data);

        static bool drop_padding_verify_crc(bin_data &d);

        block_t _iv;
        std::unique_ptr<crypto> _crypto;
    };


    class cipher_default final : public cipher {
    public:
        static constexpr std::size_t mac_size = 8;
        static constexpr std::size_t crc_size = 4;

        explicit cipher_default(std::unique_ptr<crypto_with_cmac> crypto);

        void prepare_tx(bin_data &data, std::size_t offset, cipher_mode mode) override;
        bool confirm_rx(bin_data &data, cipher_mode mode) override;
        void reinit_with_session_key(bin_data const &rndab) override;

    private:
        [[nodiscard]] crypto_with_cmac &crypto_provider();

        [[nodiscard]] range<std::uint8_t *> iv();

        bool drop_padding_verify_crc(bin_data &d, std::uint8_t status);


        std::unique_ptr<std::uint8_t[]> _iv;
        std::unique_ptr<crypto_with_cmac> _crypto;
    };
}// namespace desfire

#endif//DESFIRE_CRYPTO_CIPHERS_HPP
