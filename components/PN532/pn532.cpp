#include "pn532.hpp"
#include <array>
#include <bitset>
#include <deque>
#include <esp_log.h>

#define PN532_DEFAULT_TIMEOUT (1000/portTICK_PERIOD_MS)



template<class T>
void PN532<T>::begin(TickType_t timeout)
{
    BaseType_t tWrite = xTaskGetTickCount();
    T::wake_up(timeout);
    sam_config(normal_mode,0x14,0x01,timeout - xTaskGetTickCount() + tWrite);
    setParameters(0x14, timeout - xTaskGetTickCount() + tWrite);
    rfConfiguration(rf_field, {0x01}, timeout - xTaskGetTickCount() + tWrite);
    rfConfiguration(maxRetries, {0xFF, 0xFF, 0xFF}, timeout - xTaskGetTickCount() + tWrite);
}

template<class T>
int PN532<T>::cmd(const uint8_t cmd, std::initializer_list<uint8_t> param_literal, TickType_t timeout)
{
    std::vector<uint8_t> param(param_literal);
    return PN532<T>::cmd(cmd,param,timeout);
}

template<class T>
template<typename Container>
int PN532<T>::cmd(const uint8_t cmd, Container& param, TickType_t timeout)
{
    BaseType_t tStart = xTaskGetTickCount();
    T::send(cmd, param, timeout);
    return T::wait_ack(timeout - xTaskGetTickCount() + tStart);
}

template<class T>
int PN532<T>::sam_config(SAM_mode mode, uint8_t time, uint8_t irq, TickType_t timeout)
{
    ESP_LOGI(PN532_LOG, "Configuring pn532 SAM as not used");
    const std::vector<uint8_t> ackbuff = {
        mode,   // normal mode
        time,   // timeout 50ms * 20 = 1 second
        irq    // use IRQ pin
    };
    return cmd(PN532_COMMAND_SAMCONFIGURATION, ackbuff, timeout);

}

template<class T>
template<typename Container>
int PN532<T>::read(const uint8_t command, Container& data, TickType_t timeout)
{
    BaseType_t tStart = xTaskGetTickCount();
    T::send(command, std::vector<uint8_t>(), timeout);
    T::wait_ack(timeout - xTaskGetTickCount() + tStart);
    T::receive(data, timeout - xTaskGetTickCount() + tStart);
    T::send_ack(timeout - xTaskGetTickCount() + tStart);
    return ESP_OK;

}


template<class T>
bool PN532<T>::data_exchange(const uint8_t command, std::initializer_list<uint8_t> param_literal, std::vector<uint8_t>& data, TickType_t timeout)
{
    std::vector<uint8_t> param(param_literal);
    return PN532<T>::data_exchange(command,param,data,timeout);
}

template<class T>
template<typename Container>
bool PN532<T>::data_exchange(const uint8_t command, Container& param, Container& data, TickType_t timeout)
{
    std::deque<uint8_t> data_buffer;
    BaseType_t tWrite = xTaskGetTickCount();
    if(cmd(command, param, timeout - xTaskGetTickCount() + tWrite))
    {
        if(T::receive(data_buffer, timeout - xTaskGetTickCount() + tWrite))
        {
            if(data_buffer.front() == command + 1)
            data_buffer.pop_front();
            data.insert(data.begin(), data_buffer.begin(), data_buffer.end());
            return true;
        }
    }
    ESP_LOGE(PN532_LOG,"DATA EXCHANGE FAILED");
    return false;
}

// template<class T>
// int PN532<T>::Diagnose(){}

template<class T>
bool PN532<T>::getFirmwareVersion(pn532_info_t& chipVersion,TickType_t timeout)
{
    std::vector<uint8_t> version;
    read(PN532_COMMAND_GETFIRMWAREVERSION, version, timeout);
    std::copy(version.begin(), version.end(), chipVersion);
    return true;
}

// template<class T>
// int PN532<T>::getGeneralStatus(){}

template<class T>
uint8_t PN532<T>::readRegister(const uint16_t address ,TickType_t timeout)
{
    const std::vector<uint8_t> adr = {
        (uint8_t) (address & 0xFF00) >> 8,
        (uint8_t) (address & 0x00FF)
    };
    std::vector<uint8_t> data;
    data_exchange(PN532_COMMAND_READREGISTER,adr,data,timeout);
    return data[0];
}

// template<class T>
// int PN532<T>::readRegister(const std::vector<uint16_t>& adresses ,TickType_t timeout)
// {}


template<class T>
void PN532<T>::writeRegister(const uint16_t address, const uint8_t data ,TickType_t timeout)
{
    const std::vector<uint8_t> packet = {
        (uint8_t) (address & 0xFF00) >> 8,
        (uint8_t) (address & 0x00FF),
        data
    };
    cmd(PN532_COMMAND_WRITEREGISTER,packet,timeout);
}
// template<class T>
// int PN532<T>::writeRegister(){}

template<class T>
bool PN532<T>::readGpio(uint8_t gpio, TickType_t timeout)
{
    std::vector<uint8_t> data;
    read(PN532_COMMAND_READGPIO,data);
    uint32_t values = data[1] + (data[2] << 8) + (data[3] << 16);
    return (bool)((values >> (gpio)) & 1U);
}

template<class T>
bool PN532<T>::writeGpio(uint8_t gpio, bool value, TickType_t timeout)
{
    std::vector<uint8_t> gpioState;
    read(PN532_COMMAND_READGPIO, gpioState);

    std::vector<uint8_t> gpioNewState(gpioState.begin() + 1, gpioState.end() - 1);
    if(gpio > PN532_GPIO_P72){
        return false;
    }
    gpioNewState[gpio / 7] = (value<< (gpio % 8)) | 0x80;

    return cmd(PN532_COMMAND_WRITEGPIO,gpioNewState, timeout);
}

// template<class T>
// int PN532<T>::setSerialBaudrate(){}

template<class T>
bool PN532<T>::setParameters(bool fNADUsed, bool fDIDUsed, bool fAutomaticATR_RES, bool fAutomaticRATS, bool fISO14443_4_PICC, bool fRemovePrePostAmble, TickType_t timeout)
{
    std::bitset<8> flags = {fNADUsed, fDIDUsed, fAutomaticATR_RES, 0, fAutomaticRATS, fISO14443_4_PICC, fRemovePrePostAmble};
    return setParameters((uint8_t)flags.to_ulong(), timeout);
}

template<class T>
bool PN532<T>::setParameters(uint8_t flags, TickType_t timeout)
{
    return cmd(PN532_COMMAND_SETPARAMETERS, {flags}, timeout);
}

// template<class T>
// int PN532<T>::powerDown(){}

template<class T>
bool PN532<T>::rfConfiguration(uint8_t cfgItem, std::initializer_list<uint8_t> configData_literal, TickType_t timeout)
{
    std::vector<uint8_t> param(configData_literal);
    return rfConfiguration(cfgItem, param, timeout);
}

template<class T>
bool PN532<T>::rfConfiguration(uint8_t cfgItem, std::vector<uint8_t>& configData, TickType_t timeout)
{
    std::vector<uint8_t> param = {cfgItem};
    param.insert(param.end(), configData.begin(), configData.end());
    return cmd(PN532_COMMAND_RFCONFIGURATION, param, timeout);
}

// template<class T>
// int PN532<T>::InJumpForDEP(){}

// template<class T>
// int PN532<T>::InJumpForPSL(){}

// template<class T>
// int PN532<T>::InListPassiveTarget(){}

// template<class T>
// int PN532<T>::InATR(){}

// template<class T>
// int PN532<T>::InPSL(){}

template<class T>
template<typename Container>
bool PN532<T>::InDataExchange(uint8_t tagID, std::initializer_list<uint8_t> host2tag_literal, Container& tag2host, TickType_t timeout)
{
    std::vector<uint8_t> host2tag(host2tag_literal);
    return InDataExchange(tagID, host2tag, tag2host,timeout);
}

template<class T>
template<typename Container>
bool PN532<T>::InDataExchange(uint8_t tagID, Container& host2tag, Container& tag2host, TickType_t timeout)
{
    std::vector<uint8_t> data_exchange_cmd={tagID};
    std::vector<uint8_t> data_exchange_receive_buffer;
    data_exchange_cmd.reserve(host2tag.size() + 1);
    data_exchange_cmd.insert(data_exchange_cmd.end(), host2tag.begin(), host2tag.end());
    if(data_exchange(PN532_COMMAND_INDATAEXCHANGE, data_exchange_cmd, data_exchange_receive_buffer, timeout)){
        tag2host.insert(tag2host.begin(), data_exchange_receive_buffer.begin() - 1, data_exchange_receive_buffer.end());
        return true;
    }
    return false;
}

// template<class T>
// int PN532<T>::InCommunicateThru(){}

template<class T>
bool PN532<T>::InDeselect(uint8_t tagID, TickType_t timeout)
{
    std::vector<uint8_t> data;
    data_exchange(PN532_COMMAND_INDESELECT, {tagID}, data, timeout);
    return data[2] == 0x00;
}

template<class T>
bool PN532<T>::InRelease(uint8_t tagID, TickType_t timeout)
{
    std::vector<uint8_t> data;
    data_exchange(PN532_COMMAND_INRELEASE, {tagID}, data, timeout);
    return data[2] == 0x00;
}

template<class T>
bool PN532<T>::InSelect(uint8_t tagID, TickType_t timeout)
{
    std::vector<uint8_t> data;
    data_exchange(PN532_COMMAND_INSELECT, {tagID}, data, timeout);
    return data[0] == 0x00;
}

template<class T>
bool PN532<T>::InAutoPoll(uint8_t polling_number, uint8_t period, uint8_t tag_type, std::vector<uint8_t>& data)
{
    return InAutoPoll(polling_number, period, {tag_type}, data);
}

template<class T>
bool PN532<T>::InAutoPoll(uint8_t polling_number, uint8_t period, std::initializer_list<uint8_t> tag_types_literal, std::vector<uint8_t>& data)
{
    std::vector<uint8_t> tag_types(tag_types_literal);
    return InAutoPoll(polling_number, period, tag_types, data);
}

template<class T>
bool PN532<T>::InAutoPoll(uint8_t polling_number, uint8_t period, std::vector<uint8_t>& tag_types, std::vector<uint8_t>& data)
{
    std::vector<uint8_t> param = {
        polling_number,
        period
    };

    if(polling_number < 0x01)
        return false;

    if(period < 0x01 || period > 0x0F)
        return false;

    if(tag_types.size() < 1)
        return false;

    TickType_t polling_time = polling_number == 0xFF? portMAX_DELAY : (polling_number + 1)*period;

    param.reserve(tag_types.size() + 2);
    param.insert(param.end(), tag_types.begin(), tag_types.end());

    if(! data_exchange(PN532_COMMAND_INAUTOPOLL, param, data, polling_time)){
        T::send_ack(); //abort
        return false;
    }

    return true;
}
