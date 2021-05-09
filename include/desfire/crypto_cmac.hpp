//
// Created by spak on 5/8/21.
//

#ifndef DESFIRE_CRYPTO_CMAC_HPP
#define DESFIRE_CRYPTO_CMAC_HPP

#include <memory>
#include <mlab/bin_data.hpp>

namespace desfire {

    namespace {
        using mlab::range;
        using mlab::bin_data;
    }

    class crypto;

    class cmac_provider {
        crypto *_crypto;
        std::size_t _block_size;
        std::uint8_t _last_byte_xor;
        std::unique_ptr<std::uint8_t[]> _subkey_pad;
        std::unique_ptr<std::uint8_t[]> _subkey_nopad;
        bin_data _cmac_buffer;

        [[nodiscard]] inline range<std::uint8_t *> key_pad() const;
        [[nodiscard]] inline range<std::uint8_t *> key_nopad() const;
        [[nodiscard]] inline crypto &crypto_provider() const;

    public:
        using mac_t = std::array<std::uint8_t, 8>;

        /**
         *
         * @param crypto Must stay alive as long as cmac_provider
         * @param block_size
         * @param last_byte_xor
         */
        inline cmac_provider(crypto &crypto, std::size_t block_size, std::uint8_t last_byte_xor);

        [[nodiscard]] inline std::size_t block_size() const;
        [[nodiscard]] inline std::uint8_t last_byte_xor() const;

        void initialize_subkeys();

        mac_t compute_cmac(range<std::uint8_t *> iv, range<std::uint8_t const *> data);

        static void prepare_subkey(range<std::uint8_t *> subkey, std::uint8_t last_byte_xor);

    };
}

namespace desfire {
    cmac_provider::cmac_provider(crypto &crypto, std::size_t block_size, std::uint8_t last_byte_xor)
            : _crypto{&crypto},
              _block_size{block_size},
              _last_byte_xor{last_byte_xor},
              _subkey_pad{std::make_unique<std::uint8_t[]>(static_cast<std::size_t>(block_size))},
              _subkey_nopad{std::make_unique<std::uint8_t[]>(static_cast<std::size_t>(block_size))} {}

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

    crypto &cmac_provider::crypto_provider() const {
        return *_crypto;
    }
}
#endif//DESFIRE_CRYPTO_CMAC_HPP
