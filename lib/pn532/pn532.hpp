#ifndef __PN532_HPP__
#define __PN532_HPP__

#include <array>
#include <vector>
#include <stddef.h>
#include "instructions.hpp"
extern "C"{
    #include "freertos/FreeRTOS.h"
    #include "freertos/task.h"
    #include <esp_log.h>
}

#define PN532_POLLING_PERIOD_MS 150

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

enum rfConfigItem: uint8_t{
    rf_field = 0x01,
    various_timings = 0x02,
    maxRtyCOM = 0x04,
    maxRetries = 0x05,
    analog_settings_typeA= 0x0A,
    analog_settings_212_424kbps= 0x0B,
    analog_settings_typeB= 0x0C,
    analog_settings_ISO14443_4= 0x0D
};


template<class T>
class PN532: public T{

    public:
        using T::T;
        void begin(TickType_t timeout = PN532_DEFAULT_TIMEOUT);

        template<typename Container> int cmd(const uint8_t cmd, Container& param = {}, TickType_t timeout = PN532_DEFAULT_TIMEOUT);
        int cmd(const uint8_t cmd, std::initializer_list<uint8_t> param_literal, TickType_t timeout = PN532_DEFAULT_TIMEOUT);
        template<typename Container> int read(const uint8_t command, Container& data, TickType_t timeout = PN532_DEFAULT_TIMEOUT);
        bool data_exchange(const uint8_t command, std::initializer_list<uint8_t> param_literal, std::vector<uint8_t>& data, TickType_t timeout = PN532_DEFAULT_TIMEOUT);
        template<typename Container> bool data_exchange(const uint8_t command, Container& param, Container& data, TickType_t timeout = PN532_DEFAULT_TIMEOUT);
        int sam_config(SAM_mode mode=normal_mode, uint8_t time=0x14, uint8_t irq=0x01, TickType_t timeout = PN532_DEFAULT_TIMEOUT);
        //int wake_up(TickType_t timeout);

        bool getFirmwareVersion(pn532_info_t& chipVersion, TickType_t timeout = PN532_DEFAULT_TIMEOUT);
        uint8_t readRegister(const uint16_t address ,TickType_t timeout = PN532_DEFAULT_TIMEOUT);
        void writeRegister(const uint16_t address, const uint8_t data ,TickType_t timeout = PN532_DEFAULT_TIMEOUT);
        bool readGpio(uint8_t gpio, TickType_t timeout = PN532_DEFAULT_TIMEOUT);
        bool writeGpio(uint8_t gpio, bool value, TickType_t timeout = PN532_DEFAULT_TIMEOUT);
        bool InSelect(uint8_t tagID, TickType_t timeout = PN532_DEFAULT_TIMEOUT);
        bool InRelease(uint8_t tagID, TickType_t timeout = PN532_DEFAULT_TIMEOUT);
        bool InDeselect(uint8_t tagID, TickType_t timeout = PN532_DEFAULT_TIMEOUT);
        bool InAutoPoll(uint8_t polling_number, uint8_t period, uint8_t tag_type, std::vector<uint8_t>& data);
        bool InAutoPoll(uint8_t polling_number, uint8_t period, std::initializer_list<uint8_t> tag_types_literal, std::vector<uint8_t>& data);
        bool InAutoPoll(uint8_t polling_number, uint8_t period, std::vector<uint8_t>& tag_types, std::vector<uint8_t>& data);
        bool setParameters(bool fNADUsed, bool fDIDUsed, bool fAutomaticATR_RES, bool fAutomaticRATS, bool fISO14443_4_PICC, bool fRemovePrePostAmble, TickType_t timeout = PN532_DEFAULT_TIMEOUT);
        bool setParameters(uint8_t flags, TickType_t timeout = PN532_DEFAULT_TIMEOUT);
        bool rfConfiguration(uint8_t cfgItem, std::initializer_list<uint8_t> configData_literal, TickType_t timeout = PN532_DEFAULT_TIMEOUT);
        bool rfConfiguration(uint8_t cfgItem, std::vector<uint8_t>& configData, TickType_t timeout = PN532_DEFAULT_TIMEOUT);
        template<typename Container> bool InDataExchange(uint8_t tagID, Container& host2tag, Container& tag2host, TickType_t timeout = PN532_DEFAULT_TIMEOUT);
        template<typename Container> bool InDataExchange(uint8_t tagID, std::initializer_list<uint8_t> host2tag, Container& tag2host, TickType_t timeout = PN532_DEFAULT_TIMEOUT);

};
#include "pn532.cpp"
#endif