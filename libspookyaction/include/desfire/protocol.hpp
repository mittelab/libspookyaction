//
// Created by Pietro Saccardi on 02/01/2021.
//

#ifndef DESFIRE_PROTOCOL_HPP
#define DESFIRE_PROTOCOL_HPP

#include <desfire/bits.hpp>
#include <desfire/crypto.hpp>
#include <desfire/log.h>
#include <memory>
#include <mlab/bin_data.hpp>

namespace desfire {

    struct block_tag {};

    /**
     * @brief Class capturing the secure communication mode over some cryptographic primitive (@ref crypto).
     *
     * A protocol instance is responsible to secure the data for transmission and decode it in reception.
     * It works by operating a @ref crypto object in an appropriate way; in general, it is a stateful object.
     *
     * @see Currently only two implementations are relevant:
     *  - protocol_legacy
     *  - protocol_default
     */
    class protocol {
    public:
        /**
         * @brief Prepares data for transmission.
         * This method is responsible for securing, in-place, all data starting at @p offset using the
         * specified @p mode.
         * @param data Data to secure; it is modified in-place.
         * @param offset Offset in @p data of the sensitive data.
         * @param mode Mode in which to operate the underlying @ref crypto.
         */
        virtual void prepare_tx(bin_data &data, std::size_t offset, comm_mode mode) = 0;

        /**
         * @brief Post-processes data after reception.
         * @param data Received data. The data must include a `bits::status` byte, which must come last
         *  in this sequence. The caller is responsible for shifting it to the last position. The data is
         *  modified in-place.
         * @param mode Mode in which to operate the underlying @ref crypto.
         * @returns A boolean representing whether @p data was successfully validated. A return value of false
         *  indicates invalid MAC, invalid key, or session, or invalid @p mode, or any unlikely but possible
         *  attempt of tampering.
         */
        virtual bool confirm_rx(bin_data &data, comm_mode mode) = 0;

        /**
         * @brief Sets up the session symmetric key used for further communication.
         * This is the first operation that follows a successful authentication.
         * This method calls @ref crypto::init_session with @p random_data.
         * @param random_data Random data obtained via key exchange
         */
        virtual void init_session(bin_data const &random_data) = 0;

        /**
         * A boolean indicating whether this class uses a legacy scheme.
         * @note Currently there are only two schemes, @ref protocol_legacy and @ref protocol_default, so this is
         *  just a way to know whether it is legacy or not.
         */
        [[nodiscard]] virtual bool is_legacy() const = 0;

        virtual ~protocol() = default;
    };

    /**
     * A dummy protocol, used only in test and in unauthenticated context, which supports only
     * plain text communication.
     */
    class protocol_dummy final : public protocol {
    public:
        /**
         * Tests whether @p mode is @ref comm_mode::plain, and does not do anything else.
         */
        inline void prepare_tx(bin_data &, std::size_t, comm_mode mode) override;

        /**
         * @copydoc prepare_tx
         */
        inline bool confirm_rx(bin_data &, comm_mode mode) override;

        /**
         * Does nothing.
         */
        inline void init_session(bin_data const &) override;

        /**
         * Yes it is.
         */
        [[nodiscard]] bool is_legacy() const override;
    };

    /**
     * Mode of operation of DES, 2K3DES legacy ciphers.
     */
    class protocol_legacy final : public protocol {
    public:
        static constexpr std::size_t block_size = 8;//!< Supports only 8-byte block ciphers.
        static constexpr std::size_t mac_size = 4;  //!< The MAC produced is 32 bits.
        static constexpr std::size_t crc_size = 2;  //!< CRC is 16 bits.

        using block_t = mlab::tagged_array<block_tag, block_size>;//!< One cipher data block
        using mac_t = mlab::tagged_array<mac_tag, mac_size>;      //!< Message Authentication Code type.

        /**
         * Creates a new protocol using @ref crypto as a underlying crypto primitive.
         * @param crypto Cryptographic primitive wrapper.
         */
        explicit protocol_legacy(std::unique_ptr<crypto> crypto);

        /**
         * @brief See @ref protocol::prepare_tx for a generic description.
         * This implementation does the following:
         *  - @ref comm_mode::plain : does nothing.
         *  - @ref comm_mode::maced : calculates a 32-bit MAC on @p data starting at @p offset, and appends it to @p data.
         *  - @ref comm_mode::ciphered : calculates a 16-bit CRC on @p data starting at @p offset, and appends it to @p data.
         *    It then proceeds as in:
         *  - @ref comm_mode::ciphered_no_crc : pads @p data with zeroes (ignoring everything before @p offset for the purpose
         *    of padding and length computation) to the next multiple of @ref block_size, and runs a @ref crypto_operation::encrypt
         *    on @p data, starting at @p offset.
         */
        void prepare_tx(bin_data &data, std::size_t offset, comm_mode mode) override;

        /**
         * @brief See @ref protocol::confirm_rx for a generic description.
         * This implementation does the following:
         *  - @ref comm_mode::plain : does nothing.
         *  - @ref comm_mode::maced : expects a sequence in the form `[message] [32-bit MAC] [status]`. Extracts the MAC,
         *    and compares it to the MAC computed on the message. If the comparison succeeds, removes the MAC from the sequence
         *    (keeping the status byte at the end) and returns positively.
         *  - @ref comm_mode::ciphered : runs a @ref crypto_operation::decrypt on @p data (excluding the last status byte).
         *    It then expects that the plaintext is a sequence `[message] [16-bit CRC] [padding] [status]`. It searches for
         *    the last sequence of 2 bytes that is a CRC on the previous data, and is following only by padding zeroes. If it finds any,
         *    and the CRC checks out, it removes the CRC and the padding, returning the message and the status byte.
         *  - @ref comm_mode::ciphered_no_crc : runs a @ref crypto_operation::decrypt on @p data (excluding the last status byte).
         */
        bool confirm_rx(bin_data &data, comm_mode mode) override;

        void init_session(bin_data const &random_data) override;

        /**
         * As the name says, it is legacy.
         */
        [[nodiscard]] bool is_legacy() const override;

    private:
        [[nodiscard]] block_t &get_zeroed_iv();
        [[nodiscard]] crypto &crypto_provider();

        /**
         * Returns the first @ref mac_size bytes of the IV after encrypting @p data.
         */
        mac_t compute_mac(range<bin_data::const_iterator> data);

        static bool drop_padding_verify_crc(bin_data &d);

        block_t _iv;
        std::unique_ptr<crypto> _crypto;
    };


    /**
     * Mode of operation of 3K3DES, AES128 ciphers.
     */
    class protocol_default final : public protocol {
    public:
        static constexpr std::size_t mac_size = 8;//!< 8-bytes MAC.
        static constexpr std::size_t crc_size = 4;//!< 32-bits CRC.

        /**
         * Creates a new protocol using @ref crypto as a underlying crypto primitive.
         * @param crypto Cryptographic primitive wrapper, which supports CMAC generation.
         */
        explicit protocol_default(std::unique_ptr<crypto_with_cmac> crypto);

        /**
         * @brief See @ref protocol::prepare_tx for a generic description.
         This implementation does the following:
         *  - @ref comm_mode::plain : passes the whole @p data through @ref crypto_with_cmac::do_cmac,
         *    but does not modify @p data. If the CMAC generation is stateful, this means that CMAC codes
         *    generated later on will depend on all commands, including plain text commands, executed through
         *    the session.
         *  - @ref comm_mode::maced : passes the whole @p data through @ref crypto_with_cmac::do_cmac and then
         *    appends the CMAC to @p data.
         *  - @ref comm_mode::ciphered : calculates a 32-bit CRC on @p data (all of it), and appends it to @p data.
         *    It then proceeds as in:
         *  - @ref comm_mode::ciphered_no_crc : pads @p data with zeroes (ignoring everything before @p offset for the purpose
         *    of padding and length computation) to the next multiple of @ref crypto_with_cmac::block_size, and runs a
         *    @ref crypto_operation::encrypt on @p data, starting at @p offset.
         */
        void prepare_tx(bin_data &data, std::size_t offset, comm_mode mode) override;

        /**
         * @brief See @ref protocol::confirm_rx for a generic description.
         This implementation does the following:
         *  - @ref comm_mode::plain : passes the whole @p data (including the status byte) through
         *    @ref crypto_with_cmac::do_cmac, but does not modify @p data. If the CMAC generation is stateful,
         *    this means that CMAC codes generated later on will depend on all commands, including plain text commands,
         *    executed through the session, as well as the status bytes obtained in the response.
         *  - @ref comm_mode::maced : expects thata in the form `[message] [cmac] [status]`; it then rotates it to
         *    `[message] [status] [cmac]`. It computes a CMAC on message and status, and compares it to the last 8 bytes of
         *    the sequence. If it matches, drops the CMAC and returns message followed by status.
         *  - @ref comm_mode::ciphered : pops the last status byte, then runs a @ref crypto_operation::decrypt on the whole
         *    remaining @p data. It then expects that the plaintext is a sequence `[message] [32-bit CRC] [padding]`.
         *    It searches for the last sequence of 4 bytes that is a CRC on the previous data, and is following only by padding zeroes.
         *    If it finds any, and the CRC checks out, it removes the CRC and the padding, returning the message and the status byte.
         *  - @ref comm_mode::ciphered_no_crc : runs a @ref crypto_operation::decrypt on @p data (excluding the last status byte).
         */
        bool confirm_rx(bin_data &data, comm_mode mode) override;

        void init_session(bin_data const &random_data) override;
        /**
         * No, this is not a legacy protocol.
         */
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

    void protocol_dummy::prepare_tx(bin_data &, std::size_t, comm_mode mode) {
        if (mode != comm_mode::plain) {
            DESFIRE_LOGE("Dummy protocol supports only plain comm mode.");
        }
    }

    bool protocol_dummy::confirm_rx(bin_data &, comm_mode mode) {
        if (mode != comm_mode::plain) {
            DESFIRE_LOGE("Dummy protocol supports only plain comm mode.");
            return false;
        }
        return true;
    }

    void protocol_dummy::init_session(bin_data const &) {}

}// namespace desfire

#endif//DESFIRE_PROTOCOL_HPP
