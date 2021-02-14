//
// Created by Pietro Saccardi on 02/01/2021.
//

#ifndef DESFIRE_CIPHER_HPP
#define DESFIRE_CIPHER_HPP

#include "bits.hpp"
#include "log.h"
#include "mlab/bin_data.hpp"

namespace desfire {
    using bits::cipher_mode;
    using bits::file_security;

    namespace {
        using mlab::bin_data;

        template <class It>
        using range = mlab::range<It>;
    }// namespace


    inline cipher_mode cipher_mode_from_security(file_security security);

    enum struct cipher_iv {
        global,
        zero
    };

    enum struct crypto_direction {
        encrypt,
        decrypt,
        mac
    };

    class cipher {
        cipher_iv _iv_mode = cipher_iv::global;

    public:
        inline void set_iv_mode(cipher_iv v);

        inline cipher_iv iv_mode() const;

        virtual void prepare_tx(bin_data &data, std::size_t offset, cipher_mode mode) = 0;

        /**
         * Assume that status byte comes last.
         */
        virtual bool confirm_rx(bin_data &data, cipher_mode mode) = 0;

        virtual void reinit_with_session_key(bin_data const &rndab) = 0;

        inline static bool is_legacy(bits::cipher_type type);

        virtual ~cipher() = default;
    };

    class iv_session {
    private:
        cipher &_c;
        cipher_iv _old_iv_mode;

    public:
        inline explicit iv_session(cipher &c, cipher_iv iv_mode);
        inline ~iv_session();
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
}// namespace desfire

namespace desfire {

    /**
     * @todo Fix header includes so that this forward declaration is redundant.
     */
    const char *to_string(file_security);
    const char *to_string(cipher_iv);

    iv_session::iv_session(cipher &c, cipher_iv iv_mode) : _c{c}, _old_iv_mode{c.iv_mode()} {
        DESFIRE_LOGD("Switching crypto IV mode to %s (was %s).", to_string(iv_mode), to_string(_c.iv_mode()));
        _c.set_iv_mode(iv_mode);
    }

    iv_session::~iv_session() {
        DESFIRE_LOGD("Restoring crypto IV mode to %s.", to_string(_old_iv_mode));
        _c.set_iv_mode(_old_iv_mode);
    }

    cipher_mode cipher_mode_from_security(file_security security) {
        switch (security) {
            case file_security::none:
                return cipher_mode::plain;
            case file_security::authenticated:
                return cipher_mode::maced;
            case file_security::encrypted:
                return cipher_mode::ciphered;
            default:
                DESFIRE_LOGE("Unsupported file security %s", to_string(security));
                break;
        }
        return cipher_mode::plain;
    }
    void cipher::set_iv_mode(cipher_iv v) {
        _iv_mode = v;
    }
    cipher_iv cipher::iv_mode() const {
        return _iv_mode;
    }

    /// @note This is C++14 (pre C++-17) nonsense.
    template <std::size_t BlockSize, std::size_t MACSize, std::size_t CRCSize>
    constexpr std::size_t cipher_traits<BlockSize, MACSize, CRCSize>::crc_size;

    bool cipher::is_legacy(bits::cipher_type type) {
        switch (type) {
            case bits::cipher_type::des:
            case bits::cipher_type::des3_2k:
                return true;
            case bits::cipher_type::des3_3k:
            case bits::cipher_type::aes128:
                return false;
            default:
                DESFIRE_LOGE("Requesting whether a cipher is legacy with no cipher!");
                return true;
        }
    }

}// namespace desfire

#endif//DESFIRE_CIPHER_HPP
