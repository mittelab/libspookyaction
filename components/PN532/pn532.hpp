#ifndef __PN532_HPP__
#define __PN532_HPP__

#include <array>
#include <vector>
#include <stddef.h>
#include "instructions.hpp"

enum SAM_mode : uint8_t{
    normal_mode=0x01,
    virtual_card=0x02,
    wired_card=0x03,
    dual_card=0x04
};

enum diagnose: uint8_t{
    comunication_test=0x00,
    rom_test=0x01,
    ram_test=0x02,
    polling_test=0x04,
    echo_test=0x05,
    attention_request_test=0x06,
    slef_antenna_test=0x07
};

typedef struct{
    uint8_t :5;
    bool iso14443b:1;
    bool iso14443a:1;
    bool iso18092:1;
} card_t;

typedef struct{
    uint8_t ic_version;
    uint8_t firmware_version;
    uint8_t firmware_revision;
    card_t card_supported;
} pn532_info_t;

typedef struct{
    bool P30:1, P31:1,P32:1,P33:1,P34:1,P35:1,:2;
} p3_t;

typedef struct{
    bool :1,P71:1, P72:1,:5;
}p7_t;

typedef struct{
    p3_t P3;
    p7_t P7;
} gpio_t;


template<class T>
class PN532 : private T{
    public:
        using T::T;
        void begin(TickType_t timeout = PN532_DEFAULT_TIMEOUT);
        int cmd(const uint8_t cmd, const std::vector<uint8_t>& param = {}, TickType_t timeout = PN532_DEFAULT_TIMEOUT);
        int read(const uint8_t command, std::vector<uint8_t>& data, TickType_t timeout = PN532_DEFAULT_TIMEOUT);
        int data_exchange(const uint8_t command, const std::vector<uint8_t>& param, std::vector<uint8_t>& data, TickType_t timeout = PN532_DEFAULT_TIMEOUT);
        int sam_config(SAM_mode mode=normal_mode, uint8_t time=0x14, uint8_t irq=0x01, TickType_t timeout = PN532_DEFAULT_TIMEOUT);
        //int wake_up(TickType_t timeout);

        pn532_info_t getFirmwareVersion(TickType_t timeout = PN532_DEFAULT_TIMEOUT);
        uint8_t readRegister(const uint16_t address ,TickType_t timeout = PN532_DEFAULT_TIMEOUT);
        void writeRegister(const uint16_t address, const uint8_t data ,TickType_t timeout = PN532_DEFAULT_TIMEOUT);
        void readGpio(gpio_t& gpio, TickType_t timeout);
        void writeGpio(gpio_t& gpio, TickType_t timeout);

};
#include "pn532.cpp"
#endif