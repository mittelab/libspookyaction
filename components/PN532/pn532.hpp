#ifndef __PN532_HPP__
#define __PN532_HPP__

#include <array>
#include <vector>
#include <stddef.h>
#include "instructions.hpp"


template<class T>
class PN532 : public T{
    public:
        using T::T;
        void begin(TickType_t timeout = PN532_DEFAULT_TIMEOUT);
        int cmd(const uint8_t cmd, const std::vector<uint8_t> param = {}, TickType_t timeout = PN532_DEFAULT_TIMEOUT);
        int data_exchange(const uint8_t command, const std::vector<uint8_t> param, std::vector<uint8_t> data, TickType_t timeout = PN532_DEFAULT_TIMEOUT);
        int sam_config(TickType_t timeout = PN532_DEFAULT_TIMEOUT);
        //int wake_up(TickType_t timeout);
};
#include "pn532.cpp"
#endif