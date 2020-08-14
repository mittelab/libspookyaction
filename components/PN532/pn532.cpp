#include "pn532.hpp"
#include <array>
#define PN532_DEFAULT_TIMEOUT (1000/portTICK_PERIOD_MS)



template<class T>
void PN532<T>::begin(TickType_t timeout)
{
    BaseType_t tWrite = xTaskGetTickCount();
    T::wake_up(xTaskGetTickCount() - tWrite);
    sam_config(normal_mode,0x14,0x01,xTaskGetTickCount() - tWrite);
}

template<class T>
int PN532<T>::cmd(const uint8_t cmd, const std::vector<uint8_t>& param, TickType_t timeout)
{
    BaseType_t tWrite = xTaskGetTickCount();
    T::send(cmd, param, xTaskGetTickCount() - tWrite);
    return T::wait_ack(xTaskGetTickCount() - tWrite);
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
int PN532<T>::read(const uint8_t command, std::vector<uint8_t>& data, TickType_t timeout)
{
    BaseType_t tWrite = xTaskGetTickCount();
    if(cmd(command, std::vector<uint8_t>(), xTaskGetTickCount() - tWrite) >= 0)
        return T::receive(data, xTaskGetTickCount() - tWrite);
}

template<class T>
int PN532<T>::data_exchange(const uint8_t command, const std::vector<uint8_t>& param, std::vector<uint8_t>& data, TickType_t timeout)
{
    BaseType_t tWrite = xTaskGetTickCount();
    if(cmd(command, param, xTaskGetTickCount() - tWrite) >= 0)
        return T::receive(data, xTaskGetTickCount() - tWrite);
}

// template<class T>
// int PN532<T>::Diagnose(){}

template<class T>
pn532_info_t PN532<T>::getFirmwareVersion(TickType_t timeout)
{   
    std::vector<uint8_t> version;
    data_exchange(PN532_COMMAND_GETFIRMWAREVERSION, std::vector<uint8_t>(), version, timeout);
    pn532_info_t data;
    std::copy(version.begin(), version.end(), &data);
    return data;
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
void PN532<T>::readGpio(gpio_t& gpio, TickType_t timeout)
{   
    std::vector<uint8_t> data;
    data_exchange(PN532_COMMAND_READGPIO,std::vector<uint8_t>(), data);
    std::copy(data.begin(), data.end(), gpio);
}

template<class T>
void PN532<T>::writeGpio(gpio_t& gpio, TickType_t timeout)
{
    auto ptr = reinterpret_cast<uint8_t*>(gpio);
    std::vector<uint8_t> data(ptr, ptr + sizeof gpio);
    cmd(PN532_COMMAND_READGPIO,std::vector<uint8_t>(), data);
}

// template<class T>
// int PN532<T>::setSerialBaudrate(){}

// template<class T>
// int PN532<T>::setParameters(){}

// template<class T>
// int PN532<T>::powerDown(){}

// template<class T>
// int PN532<T>::rfConfiguration(){}

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

// template<class T>
// int PN532<T>::InDataExchange(){}

// template<class T>
// int PN532<T>::InCommunicateThru(){}

// template<class T>
// int PN532<T>::InDeselect(){}

// template<class T>
// int PN532<T>::InRelease(){}

// template<class T>
// int PN532<T>::InSelect(){}

// template<class T>
// int PN532<T>::InAutoPoll(){}
