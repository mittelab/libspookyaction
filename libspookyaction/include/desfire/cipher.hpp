//
// Created by Pietro Saccardi on 02/01/2021.
//

#ifndef DESFIRE_CIPHER_HPP
#define DESFIRE_CIPHER_HPP

#include <desfire/bits.hpp>
#include <desfire/crypto.hpp>
#include <desfire/log.h>
#include <memory>
#include <mlab/bin_data.hpp>

namespace desfire {
    using bits::cipher_mode;

    namespace {
        using mlab::bin_data;
        using mlab::range;
    }// namespace

    class cipher {
    public:
        virtual void prepare_tx(bin_data &data, std::size_t offset, cipher_mode mode) = 0;

        /**
         * Assume that status byte comes last.
         */
        virtual bool confirm_rx(bin_data &data, cipher_mode mode) = 0;

        virtual void init_session(bin_data const &random_data) = 0;

        [[nodiscard]] virtual bool is_legacy() const = 0;

        virtual ~cipher() = default;
    };

    class cipher_dummy final : public cipher {
    public:
        inline void prepare_tx(bin_data &, std::size_t, cipher_mode mode) override;

        inline bool confirm_rx(bin_data &, cipher_mode mode) override;

        inline void init_session(bin_data const &) override;

        [[nodiscard]] bool is_legacy() const override;
    };

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
        void init_session(bin_data const &random_data) override;
        [[nodiscard]] bool is_legacy() const override;

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
        void init_session(bin_data const &random_data) override;
        [[nodiscard]] bool is_legacy() const override;

    private:
        [[nodiscard]] crypto_with_cmac &crypto_provider();

        [[nodiscard]] range<std::uint8_t *> iv();

        bool drop_padding_verify_crc(bin_data &d, std::uint8_t status);


        std::unique_ptr<std::uint8_t[]> _iv;
        std::unique_ptr<crypto_with_cmac> _crypto;
    };
}// namespace desfire

namespace desfire {

    void cipher_dummy::prepare_tx(bin_data &, std::size_t, cipher_mode mode) {
        if (mode != cipher_mode::plain) {
            DESFIRE_LOGE("Dummy cipher supports only plain comm mode.");
        }
    }

    bool cipher_dummy::confirm_rx(bin_data &, cipher_mode mode) {
        if (mode != cipher_mode::plain) {
            DESFIRE_LOGE("Dummy cipher supports only plain comm mode.");
            return false;
        }
        return true;
    }

    void cipher_dummy::init_session(bin_data const &) {}

}// namespace desfire

#endif//DESFIRE_CIPHER_HPP
