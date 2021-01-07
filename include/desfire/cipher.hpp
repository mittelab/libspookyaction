//
// Created by Pietro Saccardi on 02/01/2021.
//

#ifndef DESFIRE_CIPHER_HPP
#define DESFIRE_CIPHER_HPP

#include "mlab/bin_data.hpp"
#include "bits.hpp"

namespace desfire {
    using bits::comm_mode;
    namespace {
        using namespace mlab;
    }

    enum cipher_iv {
        global,
        zero
    };

    class cipher {
        cipher_iv _iv_mode = cipher_iv::global;
    public:
        struct config;

        inline void set_iv_mode(cipher_iv v);

        inline cipher_iv iv_mode() const;

        virtual void prepare_tx(bin_data &data, std::size_t offset, config const &cfg) = 0;

        /**
         * Assume that status byte comes last.
         */
        virtual bool confirm_rx(bin_data &data, config const &cfg) = 0;

        virtual void reinit_with_session_key(bin_data const &rndab) = 0;

        virtual ~cipher() = default;
    };

    class iv_session {
    private:
        cipher &_c;
        cipher_iv _old_iv_mode;
    public:
        explicit iv_session(cipher &c, cipher_iv iv_mode) : _c{c}, _old_iv_mode{c.iv_mode()} {
            _c.set_iv_mode(iv_mode);
        }
        ~iv_session() {
            _c.set_iv_mode(_old_iv_mode);
        }
    };

    struct cipher::config {
        comm_mode mode;
        bool do_mac;        // If required by protocol and comm_mode
        bool do_cipher;     // If required by protocol and comm_mode
        bool do_crc;        // If required by protocol and comm_mode
    };

    static constexpr cipher::config cipher_cfg_plain{
            .mode = comm_mode::plain,
            .do_mac = true,
            .do_cipher = true,
            .do_crc = true
    };

    static constexpr cipher::config cipher_cfg_crypto_nocrc{
            .mode = comm_mode::cipher,
            .do_mac = false,
            .do_cipher = true,
            .do_crc = false
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

namespace desfire {
    void cipher::set_iv_mode(cipher_iv v) {
        _iv_mode = v;
    }
    cipher_iv cipher::iv_mode() const {
        return _iv_mode;
    }

    /// @note This is C++14 (pre C++-17) nonsense.
    template <std::size_t BlockSize, std::size_t MACSize, std::size_t CRCSize>
    constexpr std::size_t cipher_traits<BlockSize, MACSize, CRCSize>::crc_size;
}

#endif //DESFIRE_CIPHER_HPP
