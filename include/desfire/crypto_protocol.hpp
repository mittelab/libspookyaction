//
// Created by spak on 5/7/21.
//

#ifndef DESFIRE_CRYPTO_PROTOCOL_HPP
#define DESFIRE_CRYPTO_PROTOCOL_HPP

#include <desfire/bits.hpp>
#include <desfire/crypto_ciphers_base.hpp>
#include <memory>

namespace desfire {
    using bits::cipher_mode;

    class protocol {
    public:
        virtual void prepare_tx(crypto &crypto, bin_data &data, std::size_t offset, cipher_mode mode) = 0;
        virtual bool confirm_rx(crypto &crypto, bin_data &data, cipher_mode mode) = 0;
        virtual ~protocol() = default;
    };

    class protocol_legacy final : public protocol {
        static constexpr std::size_t block_size = 8;
        static constexpr std::size_t mac_size = 4;
        static constexpr std::size_t crc_size = 2;

        using block_t = std::array<std::uint8_t, block_size>;
        using mac_t = std::array<std::uint8_t, mac_size>;

        void prepare_tx(crypto &crypto, bin_data &data, std::size_t offset, cipher_mode mode) override;
        bool confirm_rx(crypto &crypto, bin_data &data, cipher_mode mode) override;

    private:
        [[nodiscard]] block_t &get_zeroed_iv();

        /**
         * Returns the first @ref mac_length bytes of the IV after encrypting @p data.
         */
        mac_t compute_mac(crypto &crypto, range<bin_data::const_iterator> data);

        static bool drop_padding_verify_crc(bin_data &d);

        block_t _iv = {0, 0, 0, 0, 0, 0, 0, 0};
    };


    class protocol_default : public protocol {

    };
}

#endif//DESFIRE_CRYPTO_PROTOCOL_HPP
