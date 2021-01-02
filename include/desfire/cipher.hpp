//
// Created by Pietro Saccardi on 02/01/2021.
//

#ifndef APERTURAPORTA_CIPHER_HPP
#define APERTURAPORTA_CIPHER_HPP

#include "mlab/bin_data.hpp"

namespace desfire {
    namespace {
        using namespace mlab;
    }

    class cipher {
    public:
        struct config;

        virtual void prepare_tx(bin_data &data, std::size_t offset, config const &cfg) = 0;

        /**
         * Assume that status byte comes last.
         */
        virtual bool confirm_rx(bin_data &data, config const &cfg) = 0;

        virtual ~cipher() = default;
    };

    enum struct comm_mode {
        plain,
        mac,
        cipher
    };

    struct cipher::config {
        comm_mode mode;
        bool do_mac;        // If required by protocol and comm_mode
        bool do_cipher;     // If required by protocol and comm_mode
        bool do_crc;        // If required by protocol and comm_mode
    };

    template <std::size_t BlockSize, std::size_t MACSize, std::size_t CRCSize>
    struct cipher_traits {
        static constexpr std::size_t block_size = BlockSize;
        static constexpr std::size_t mac_size = MACSize;
        static constexpr std::size_t crc_size = CRCSize;

        using block_t = std::array<std::uint8_t, block_size>;
        using mac_t = std::array<std::uint8_t, mac_size>;
        using crc_t = std::array<std::uint8_t, crc_size>;
    };
}

#endif //APERTURAPORTA_CIPHER_HPP
