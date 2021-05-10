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
        using mlab::range;
    }// namespace


    [[nodiscard]] inline cipher_mode cipher_mode_from_security(file_security security);

    class cipher {
    public:
        virtual void prepare_tx(bin_data &data, std::size_t offset, cipher_mode mode) = 0;

        /**
         * Assume that status byte comes last.
         */
        virtual bool confirm_rx(bin_data &data, cipher_mode mode) = 0;

        /**
         * @todo Rename to init-session
         * @param rndab
         */
        virtual void reinit_with_session_key(bin_data const &rndab) = 0;

        [[nodiscard]] inline static bool is_legacy(bits::cipher_type type);

        virtual ~cipher() = default;
    };

    class cipher_dummy final : public cipher {
    public:
        inline void prepare_tx(bin_data &, std::size_t, cipher_mode mode) override;

        inline bool confirm_rx(bin_data &, cipher_mode mode) override;

        inline void reinit_with_session_key(bin_data const &) override;
    };
}// namespace desfire

namespace desfire {

    /**
     * @todo Fix header includes so that this forward declaration is redundant.
     */
    [[nodiscard]] const char *to_string(file_security);

    cipher_mode cipher_mode_from_security(file_security security) {
        switch (security) {
            case file_security::none:
                return cipher_mode::plain;
            case file_security::authenticated:
                return cipher_mode::maced;
            case file_security::encrypted:
                return cipher_mode::ciphered;
        }
        return cipher_mode::plain;
    }

    bool cipher::is_legacy(bits::cipher_type type) {
        switch (type) {
            case bits::cipher_type::des:
                [[fallthrough]];
            case bits::cipher_type::des3_2k:
                return true;
            case bits::cipher_type::des3_3k:
                [[fallthrough]];
            case bits::cipher_type::aes128:
                return false;
            default:
                DESFIRE_LOGE("Requesting whether a cipher is legacy with no cipher!");
                return true;
        }
    }

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

    void cipher_dummy::reinit_with_session_key(bin_data const &) {}

}// namespace desfire

#endif//DESFIRE_CIPHER_HPP
