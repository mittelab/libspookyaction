//
// Created by spak on 5/7/21.
//

#ifndef DESFIRE_CRYPTO_PROTOCOL_HPP
#define DESFIRE_CRYPTO_PROTOCOL_HPP

#include <desfire/bits.hpp>
#include <desfire/crypto_base.hpp>
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

    class cmac_provider {
        std::size_t _block_size;
        std::uint8_t _last_byte_xor;
        std::unique_ptr<std::uint8_t[]> _subkey_pad;
        std::unique_ptr<std::uint8_t[]> _subkey_nopad;

        [[nodiscard]] inline range<std::uint8_t *> key_pad() const;
        [[nodiscard]] inline range<std::uint8_t *> key_nopad() const;

    public:
        using mac_t = std::array<std::uint8_t, 8>;

        inline cmac_provider(std::size_t block_size, std::uint8_t last_byte_xor);

        [[nodiscard]] inline std::size_t block_size() const;
        [[nodiscard]] inline std::uint8_t last_byte_xor() const;

        void prepare_subkeys(crypto &crypto);
        mac_t compute_mac(crypto &crypto, range<bin_data::const_iterator> data);

        static void prep_subkey(range<std::uint8_t *> subkey, std::uint8_t last_byte_xor);
    };

    class protocol_default : public protocol {

    };
}

namespace desfire {
    cmac_provider::cmac_provider(std::size_t block_size, std::uint8_t last_byte_xor)
        : _block_size{std::max(1u, block_size)},
          _last_byte_xor{last_byte_xor},
          _subkey_pad{std::make_unique<std::uint8_t[]>(block_size)},
          _subkey_nopad{std::make_unique<std::uint8_t[]>(block_size)} {}

    std::size_t cmac_provider::block_size() const {
        return _block_size;
    }
    std::uint8_t cmac_provider::last_byte_xor() const {
        return _last_byte_xor;
    }
    range<std::uint8_t *> cmac_provider::key_pad() const {
        return {_subkey_pad.get(), _subkey_pad.get() + block_size()};
    }
    range<std::uint8_t *> cmac_provider::key_nopad() const {
        return {_subkey_nopad.get(), _subkey_nopad.get() + block_size()};
    }
}

#endif//DESFIRE_CRYPTO_PROTOCOL_HPP
