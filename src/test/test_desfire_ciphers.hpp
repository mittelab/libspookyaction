//
// Created by spak on 3/16/21.
//

#ifndef KEYCARD_ACCESS_TEST_DESFIRE_CIPHERS_HPP
#define KEYCARD_ACCESS_TEST_DESFIRE_CIPHERS_HPP

namespace ut::desfire_ciphers {
    void test_des();
    void test_2k3des();
    void test_3k3des();
    void test_aes();
    void test_crc32();
    void test_crc16();
}// namespace ut::desfire_ciphers

#endif//KEYCARD_ACCESS_TEST_DESFIRE_CIPHERS_HPP
