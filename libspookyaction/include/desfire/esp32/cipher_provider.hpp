//
// Created by spak on 1/4/23.
//

#ifndef DESFIRE_ESP32_CIPHER_PROVIDER_HPP
#define DESFIRE_ESP32_CIPHER_PROVIDER_HPP

#include <desfire/cipher_provider.hpp>
#include <desfire/esp32/crypto_impl.hpp>

/**
 * ESP32-specific classes and structures
 */
namespace desfire::esp32 {
    /**
     * Cipher provider which yields ESP32 implementations (WolfSSL, MbedTLS) of the ciphers.
     */
    using default_cipher_provider = typed_cipher_provider<crypto_des, crypto_2k3des, crypto_3k3des, crypto_aes>;
}// namespace desfire::esp32

#endif//DESFIRE_ESP32_CIPHER_PROVIDER_HPP
