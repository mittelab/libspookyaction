#ifndef __DESFIRE_HPP__
#define __DESFIRE_HPP__

#include <array>
#include <vector>
#include <stddef.h>
#include "instructions.hpp"

extern "C"{
    #include "freertos/FreeRTOS.h"
    #include "freertos/task.h"
    #include <esp_log.h>
    #include "mbedtls/des.h"
    #include "mbedtls/aes.h"
}

#define DESFIRE_LOG "desfire"

#define DESFIRE_AUTHENTICATE_LEGACY        0x0A
#define DESFIRE_CHANGE_KEY_SETTINGS        0x54
#define DESFIRE_GET_KEY_SETTINGS           0x45
#define DESFIRE_CHANGE_KEY                 0xC4
#define DESFIRE_GET_KEY_VERSION            0x64

#define DESFIRE_CREATE_APPLICATION         0xCA
#define DESFIRE_DELETE_APPLICATION         0xDA
#define DESFIRE_GET_APPLICATION_IDS        0x6A
#define DESFIRE_SELECT_APPLICATION         0x5A

#define DESFIRE_FORMAT_PICC                0xFC
#define DESFIRE_GET_VERSION                0x60

#define DESFIRE_GET_FILE_IDS               0x6F
#define DESFIRE_GET_FILE_SETTINGS          0xF5
#define DESFIRE_CHANGE_FILE_SETTINGS       0x5F
#define DESFIRE_CREATE_STD_DATA_FILE       0xCD
#define DESFIRE_CREATE_BACKUP_DATA_FILE    0xCB
#define DESFIRE_CREATE_VALUE_FILE          0xCC
#define DESFIRE_CREATE_LINEAR_RECORD_FILE  0xC1
#define DESFIRE_CREATE_CYCLIC_RECORD_FILE  0xC0
#define DESFIRE_DELETE_FILE                0xDF

#define DESFIRE_READ_DATA                  0xBD
#define DESFIRE_WRITE_DATA                 0x3D
#define DESFIRE_GET_VALUE                  0x6C
#define DESFIRE_CREDIT                     0x0C
#define DESFIRE_DEBIT                      0xDC
#define DESFIRE_LIMITED_CREDIT             0x1C
#define DESFIRE_WRITE_RECORD               0x3B
#define DESFIRE_READ_RECORDS               0xBB
#define DESFIRE_CLEAR_RECORD_FILE          0xEB
#define DESFIRE_COMMIT_TRANSACTION         0xC7
#define DESFIRE_ABORT_TRANSACTION          0xA7

#define DESFIRE_ADDITIONAL_FRAME           0xAF // data did not fit into a frame, another frame will follow

// -------- Desfire EV1 instructions ----------

#define DFEV1_INS_AUTHENTICATE_ISO        0x1A
#define DFEV1_INS_AUTHENTICATE_AES        0xAA
#define DFEV1_INS_FREE_MEM                0x6E
#define DFEV1_INS_GET_DF_NAMES            0x6D
#define DFEV1_INS_GET_CARD_UID            0x51
#define DFEV1_INS_GET_ISO_FILE_IDS        0x61
#define DFEV1_INS_SET_CONFIGURATION       0x5C

// ---------- ISO7816 instructions ------------

#define ISO7816_INS_EXTERNAL_AUTHENTICATE 0x82
#define ISO7816_INS_INTERNAL_AUTHENTICATE 0x88
#define ISO7816_INS_APPEND_RECORD         0xE2
#define ISO7816_INS_GET_CHALLENGE         0x84
#define ISO7816_INS_READ_RECORDS          0xB2
#define ISO7816_INS_SELECT_FILE           0xA4
#define ISO7816_INS_READ_BINARY           0xB0
#define ISO7816_INS_UPDATE_BINARY         0xD6

// ---------- Status Code ------------

#define DESFIRE_OPERATION_OK            (0x00)
#define DESFIRE_NO_CHANGES              (0x0C)
#define DESFIRE_OUT_OF_EEPROM_ERROR     (0x0E)
#define DESFIRE_ILLEGAL_COMMAND_CODE    (0x1C)
#define DESFIRE_INTEGRITY_ERROR         (0x1E)
#define DESFIRE_NO_SUCH_KEY             (0x40)
#define DESFIRE_LENGTH_ERROR            (0x7E)
#define DESFIRE_PERMISSION_DENIED       (0x9D)
#define DESFIRE_PARAMETER_ERROR         (0x9E)
#define DESFIRE_APPLICATION_NOT_FOUND   (0xA0)
#define DESFIRE_APPL_INTEGRITY_ERROR    (0xA1)
#define DESFIRE_AUTHENTICATION_ERROR    (0xAE)
#define DESFIRE_ADDITIONAL_FRAME        (0xAF)
#define DESFIRE_BOUNDARY_ERROR          (0xBE)
#define DESFIRE_PICC_INTEGRITY_ERROR    (0xC1)
#define DESFIRE_PICC_DISABLED_ERROR     (0xCD)
#define DESFIRE_COUNT_ERROR             (0xCE)
#define DESFIRE_DUPLICATE_ERROR         (0xDE)
#define DESFIRE_EEPROM_ERROR            (0xEE)
#define DESFIRE_FILE_NOT_FOUND          (0xF0)
#define DESFIRE_FILE_INTEGRITY_ERROR    (0xF1)









enum keyType{
    KEY_2K3DES=0x00,
    KEY_3K3DES=0x40,
    KEY_AES=0x80,
    KEY_INVALID = 0xFF
};


template<keyType E>
class AppKey;
// {
//     public:
//     keyType E;
//     uint8_t keyID;
//     std::vector<uint8_t> key;
//     // std::conditional<type==KEY_AES,mbedtls_aes_context,std::conditional<type==KEY_3K3DES,mbedtls_des3_context,mbedtls_des_context>::type>::type context;

//     AppKey(uint8_t id=0x00, std::vector<uint8_t> desfireKey = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
//     template<typename Container> void encrypt(Container& dataIn, Container& dataOut);
//     template<typename Container> void decrypt(Container& dataIn, Container& dataOut);

// };


template<>
class AppKey<KEY_2K3DES>{
    keyType E;
    std::vector<uint8_t> key;
    mbedtls_des_context context;
    std::array<uint8_t, 8> iv;
    std::array<uint8_t, 8> sessionKey;

    public:
    uint8_t keyID=0x00;
    AppKey(uint8_t id=0x00, std::vector<uint8_t> desfireKey = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    template<typename Container> void encrypt(Container& data);
    template<typename Container> void decrypt(Container& data);
    template<typename Container> void setSessionKey(Container& data);
    template<typename Container> uint32_t cmac(Container& data);
    template<typename Iter> void random(Iter start, Iter end);

};

template<>
class AppKey<KEY_3K3DES>{
    keyType E;
    std::vector<uint8_t> key;
    mbedtls_des3_context context;
    std::array<uint8_t, 8> iv;

    public:
    uint8_t keyID=0x00;
    AppKey(uint8_t id=0x00, std::vector<uint8_t> desfireKey = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    template<typename Container> void encrypt(Container& data);
    template<typename Container> void decrypt(Container& data);
    template<typename Container> void setSessionKey(Container& data);
};


template<>
class AppKey<KEY_AES>{
    keyType E;
    std::vector<uint8_t> key;
    mbedtls_aes_context context;

    public:
    uint8_t keyID=0x00;
    AppKey(uint8_t id=0x00, std::vector<uint8_t> desfireKey = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    template<typename Container> void encrypt(Container& data);
    template<typename Container> void decrypt(Container& data);
};

template<keyType E>
class DesfireApp
{
    public:
    bool isAuth = false;
    AppKey<E> appKey;
    std::array<uint8_t, 8> sessionKey;
    std::array<uint8_t, 3> appID;
    DesfireApp(uint32_t id = 0x000000, AppKey<E> key= AppKey<E>());
    void getFileIDs();
    void getFileSetting();
    void setFileSettings();
    void createFile();
    void deleteFile();

};

template <class T>
class Desfire: public T
{
    uint8_t tagID=0x01;


    public:
    using T::T;
    void selectTag(uint8_t id);
    template<typename ContainerIN, typename ContainerOUT>
    void tagCommand(uint8_t command, ContainerIN& param, ContainerOUT& data);
    template<typename ContainerIN=std::initializer_list<uint8_t>, typename ContainerOUT>
    void tagCommand(uint8_t command, std::initializer_list<uint8_t> param, ContainerOUT& data);

    template<keyType E> void selectApp(DesfireApp<E>& application);
    template<keyType E> bool authenticate(DesfireApp<E>& application = DesfireApp<E>());
    template<keyType E> bool createApp(DesfireApp<E>& application);
};

#include "desfire.cpp"
#endif