//
// Created by spak on 9/15/22.
//

#ifndef LIBSPOOKYACTION_KDF_HPP
#define LIBSPOOKYACTION_KDF_HPP

#include <cstdint>
#include <desfire/cmac_provider.hpp>
#include <desfire/crypto.hpp>
#include <mlab/bin_data.hpp>

namespace desfire {

    /**
     * @brief Generalized version of AN10922 key diversification protocol.
     *
     * The KDF protocol described in AN10922 essentially works always in the same way.
     *  -# A max of `(2 * block_size - 1)` diversification data is in the input.
     *  -# Prepend a constant to it.
     *  -# Prepare data according to the CMAC procedure (@ref cmac_keychain::prepare_cmac_data). This consists
     *      of padding with `80 00 .. 00` up to `2 * block_size`, and XORing the last block with the appropriately
     *      derived key.
     *  -# The resulting data is passed through the CMAC in @ref crypto::do_crypto
     *  -# The last block of encrypted data (which constitutes a CMAC) is used as diversified key.
     *  -# The procedure above is repeated with different constants for all the blocks that constitute a key, i.e.
     *      for three in 3K3DES, two in 2K3DES, one in AES128, and, well, theoretically generalizes to one for DES.
     *
     * This function abstracts the whole procedure for the given number of blocks and block size. Does not set the
     * version of the key, the caller is responsible for that.
     *
     * @tparam BlockSize Size of the cipher block in bytes. 8 for DES-derives, 16 for AES128.
     * @tparam NBlocks Number of blocks constituting a key. 1 for AES128, 1 for DES, 2 for 2K3DES, 3 for 3K3DES.
     * @param keychain Keychain object holding the subkeys for CMAC operations. Its @ref cmac_keychain::block_size must
     *  match the template parameter `BlockSize`.
     * @param crypto Cryptographic object on which the CMAC operation will be run.
     * @param diversify_input Diversification input. At most `2 * BlockSize - 1` bytes wil be used.
     * @param data_prepend_const Constants to prepend to each block process. These are specific to AN10922.
     *
     * @return A diversified key of length `BlockSize * NBlocks`.
     */
    template <std::size_t BlockSize, std::size_t NBlocks>
    [[nodiscard]] std::array<std::uint8_t, BlockSize * NBlocks> kdf_an10922(
            cmac_keychain const &keychain,
            crypto &crypto,
            mlab::bin_data &diversify_input,
            std::array<std::uint8_t, NBlocks> data_prepend_const);

}// namespace desfire

namespace desfire {

    template <std::size_t BlockSize, std::size_t NBlocks>
    std::array<std::uint8_t, BlockSize * NBlocks> kdf_an10922(
            cmac_keychain const &keychain,
            crypto &crypto,
            mlab::bin_data &diversify_input,
            std::array<std::uint8_t, NBlocks> data_prepend_const) {
        static constexpr auto MaxDiversifyLength = 2 * BlockSize - 1;
        static constexpr auto KeyLength = BlockSize * NBlocks;

        // This will be the final key returned.
        std::array<std::uint8_t, KeyLength> diversified_key{};
        std::fill_n(std::begin(diversified_key), KeyLength, 0);

        if (keychain.block_size() != BlockSize) {
            ESP_LOGE(DESFIRE_TAG, "The keychain block size differs to the block size required by the ciphers: %u != %u.", keychain.block_size(), BlockSize);
            return diversified_key;
        }

        // We use at most 15 bits of the diversification data
        if (diversify_input.size() > MaxDiversifyLength) {
            ESP_LOGW(DESFIRE_TAG, "Too long diversification input, %d > %u bytes. Will truncate.", diversify_input.size(), MaxDiversifyLength);
            diversify_input.resize(MaxDiversifyLength);
        }

        // The CMAC procedure will process a total of 2 blocks of data. We use the diversification input as a buffer:
        diversify_input.reserve(2 * BlockSize);
        // For each block, we need to insert a different constant in front of the diversification data. For now, put zero.
        diversify_input.insert(std::begin(diversify_input), 0);
        // Preprocess the diversification input. It should never alter the first block:
        keychain.prepare_cmac_data(diversify_input, 2 * BlockSize);
        assert(diversify_input.size() == 2 * BlockSize);
        assert(diversify_input[0] == 0);

        // Each block is always processed in the same way:
        auto process_one_block = [&](std::uint8_t block_data_prepend_const, std::size_t offset_in_diversified_key) {
            // Set the first constant to be the requested one
            diversify_input[0] = block_data_prepend_const;
            // The new piece of the final key is now at zero, so we can use it as an IV and then copy over it
            const range<std::uint8_t *> iv{
                    std::begin(diversified_key) + offset_in_diversified_key,
                    std::begin(diversified_key) + offset_in_diversified_key + BlockSize};
            // Perform crypto in CMAC mode with a zero block IV.
            crypto.do_crypto(diversify_input.data_view(), iv, crypto_operation::mac);
            // Copy the last block of the diversified data onto the key
            std::copy(std::begin(diversify_input) + BlockSize, std::end(diversify_input), std::begin(iv));
        };

        if constexpr (NBlocks == 1) {
            // Just process the single block
            process_one_block(data_prepend_const[0], 0);
        } else {
            // We will need to do NBlock interations, so we will need a copy of the current data.
            std::array<std::uint8_t, 2 * BlockSize> diversify_input_backup{};
            std::copy(std::begin(diversify_input), std::end(diversify_input), std::begin(diversify_input_backup));
            // Now loop once for each block
            for (std::uint_fast8_t block_idx = 0; block_idx < NBlocks; ++block_idx) {
                if (block_idx > 0) {
                    // We need to restore the original data
                    std::copy(std::begin(diversify_input_backup), std::end(diversify_input_backup), std::begin(diversify_input));
                }
                process_one_block(data_prepend_const[block_idx], BlockSize * block_idx);
            }
        }
        return diversified_key;
    }

}// namespace desfire
#endif//LIBSPOOKYACTION_KDF_HPP
