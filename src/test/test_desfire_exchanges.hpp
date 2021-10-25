//
// Created by spak on 3/17/21.
//

#ifndef SPOOKY_ACTION_TEST_DESFIRE_EXCHANGES_HPP
#define SPOOKY_ACTION_TEST_DESFIRE_EXCHANGES_HPP

namespace ut::desfire_exchanges {
    void test_change_key_aes();
    void test_change_key_2k3des();
    void test_change_key_2k3des_regression();
    void test_change_key_des();
    void test_create_write_file_rx_cmac();
    void test_get_key_version_rx_cmac();
    void test_write_data_cmac_des();
}// namespace ut::desfire_exchanges

#endif//SPOOKY_ACTION_TEST_DESFIRE_EXCHANGES_HPP
