#ifndef __DESFIRE_HPP__
#define __DESFIRE_HPP__

#include <array>
#include <vector>
#include <cstddef>
#include "old/old_instructions.hpp"

extern "C"{
    #include "freertos/FreeRTOS.h"
    #include "freertos/task.h"
    #include <esp_log.h>
    #include "mbedtls/des.h"
    #include "mbedtls/aes.h"
    #include "mbedtls/cipher.h"
    #include "mbedtls/cmac.h"
    #include "mbedtls/cmac.h"
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
    KEY_2K3DES  = 0x00,
    KEY_3K3DES  = 0x40,
    KEY_AES     = 0x80,
    KEY_INVALID = 0xFF
};

enum keySettings{
    FACTORY_DEFAULT                = 0x0F,
    // ------------ BITS 0-3 ---------------
    ALLOW_CHANGE_MK                = 0x01, // If this bit is set, the MK can be changed, otherwise it is frozen.
    LISTING_WITHOUT_MK             = 0x02, // Picc key: If this bit is set, GetApplicationIDs, GetKeySettings do not require MK authentication.
                                           // App  key: If this bit is set, GetFileIDs, GetFileSettings, GetKeySettings do not require MK authentication.
    CREATE_DELETE_WITHOUT_MK       = 0x04, // Picc key: If this bit is set, CreateApplication does not require MK authentication.
                                           // App  key: If this bit is set, CreateFile, DeleteFile do not require MK authentication.
    CONFIGURATION_CHANGEABLE       = 0x08, // If this bit is set, the configuration settings of the MK can be changed, otherwise they are frozen.

    // ------------ BITS 4-7 (not used for the PICC master key) -------------
    CHANGE_KEY_WITH_MK             = 0x00, // A key change requires MK authentication
    CHANGE_KEY_WITH_KEY_1          = 0x10, // A key change requires authentication with key 1
    CHANGE_KEY_WITH_KEY_2          = 0x20, // A key change requires authentication with key 2
    CHANGE_KEY_WITH_KEY_3          = 0x30, // A key change requires authentication with key 3
    CHANGE_KEY_WITH_KEY_4          = 0x40, // A key change requires authentication with key 4
    CHANGE_KEY_WITH_KEY_5          = 0x50, // A key change requires authentication with key 5
    CHANGE_KEY_WITH_KEY_6          = 0x60, // A key change requires authentication with key 6
    CHANGE_KEY_WITH_KEY_7          = 0x70, // A key change requires authentication with key 7
    CHANGE_KEY_WITH_KEY_8          = 0x80, // A key change requires authentication with key 8
    CHANGE_KEY_WITH_KEY_9          = 0x90, // A key change requires authentication with key 9
    CHANGE_KEY_WITH_KEY_A          = 0xA0, // A key change requires authentication with key 10
    CHANGE_KEY_WITH_KEY_B          = 0xB0, // A key change requires authentication with key 11
    CHANGE_KEY_WITH_KEY_C          = 0xC0, // A key change requires authentication with key 12
    CHANGE_KEY_WITH_KEY_D          = 0xD0, // A key change requires authentication with key 13
    CHANGE_KEY_WITH_TARGETED_KEY   = 0xE0, // A key change requires authentication with the same key that is to be changed
    CHANGE_KEY_FROZEN              = 0xF0, // All keys are frozen
};

enum macConfig{
    CMAC_None = 0x00,
    CMAC_CALC_TX = 0x01,
    CMAC_ENC_TX = 0x02,

    CMAC_CALC_RX = 0x04,
    CMAC_DEC_RX = 0x08,

    CMAC_NO_ENCRYPT = CMAC_CALC_TX | CMAC_CALC_RX,
    CMAC_RX_ENCRYPT = CMAC_CALC_TX | CMAC_DEC_RX,
    CMAC_TX_ENCRYPT = CMAC_ENC_TX | CMAC_CALC_RX,

};



template<keyType E>
class AppKey;

template<>
class AppKey<KEY_2K3DES>{
    keyType E;
    std::vector<uint8_t> key;
    mbedtls_des_context context;
    //std::array<uint8_t, 8> iv;
    std::array<uint8_t, 8> sessionKey;
    static const uint8_t authType = DFEV1_INS_AUTHENTICATE_ISO;
    uint8_t keyID;
    static const uint8_t keySize = 8;

    template<typename Container>
    bool GenerateCmacSubkeys(uint8_t block_size, Container& K1, Container& K2);

    public:
    std::array<uint8_t, 8> iv;
    AppKey(uint8_t id=0x00, std::vector<uint8_t> desfireKey = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    template<typename Container> void encrypt(Container& data);
    template<typename IterStart, typename IterEnd, typename IterOut> void encrypt(IterStart start, IterEnd end, IterOut out);
    template<typename IterStart, typename IterEnd, typename IterOut> void decrypt(IterStart start, IterEnd end, IterOut out);
    template<typename Container> void decrypt(Container& data);
    template<typename Container> void setSessionKey(Container& data);
    template<typename IterStart, typename IterEnd, typename IterOut> void cmac(IterStart start, IterEnd end, IterOut cmac);
    template<typename ContainerIn, typename ContainerOut> void cmac(ContainerIn& data, ContainerOut& cmac);
    // template<typename Container> void cmac(Container& data);
    template<typename Container> uint32_t crc32(Container& data);



    void padding(std::vector<uint8_t>& data);
    template<typename Iter> void random(Iter start, Iter end);
    uint8_t getKeyID();
    uint8_t getAuthType();
    uint8_t getKeySize();
};

template<>
class AppKey<KEY_3K3DES>{
    keyType E;
    uint8_t keyID;
    std::vector<uint8_t> key;
    mbedtls_des3_context context;
    std::array<uint8_t, 8> iv;
    static const size_t keySize = 16;
    static const uint8_t authType = DFEV1_INS_AUTHENTICATE_ISO;

    public:
    AppKey(uint8_t id=0x00, std::vector<uint8_t> desfireKey = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    template<typename IterStart, typename IterEnd, typename IterOut> void encrypt(IterStart start, IterEnd end, IterOut out);
    template<typename IterStart, typename IterEnd, typename IterOut> void decrypt(IterStart start, IterEnd end, IterOut out);
    template<typename Container> void encrypt(Container& data);
    template<typename Container> void decrypt(Container& data);
    template<typename Container> void setSessionKey(Container& data);
    template<typename Container> void cmac(Container& data, Container& cmac);
    template<typename Container> void cmac(Container& data);
    template<typename Container> uint32_t crc32(Container& data);

    void padding(std::vector<uint8_t> data);
    template<typename Iter> void random(Iter start, Iter end);
    uint8_t getKeyID();
    uint8_t getAuthType();
    uint8_t getKeySize();

};


template<>
class AppKey<KEY_AES>{
    keyType E;
    uint8_t keyID;
    std::vector<uint8_t> key;
    std::array<uint8_t, 16> iv;
    mbedtls_aes_context context;
    static const size_t keySize = 16;
    static const uint8_t authType = DFEV1_INS_AUTHENTICATE_AES;

    public:
    AppKey(uint8_t id=0x00, std::vector<uint8_t> desfireKey = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
    template<typename IterStart, typename IterEnd, typename IterOut> void encrypt(IterStart start, IterEnd end, IterOut out);
    template<typename IterStart, typename IterEnd, typename IterOut> void decrypt(IterStart start, IterEnd end, IterOut out);
    template<typename Container> void encrypt(Container& data);
    template<typename Container> void decrypt(Container& data);
    template<typename Container> void setSessionKey(Container& data);
    template<typename Container> void cmac(Container& data, Container& cmac);
    template<typename Container> void cmac(Container& data);
    template<typename Container> uint32_t crc32(Container& data);

    void padding(std::vector<uint8_t> data);
    template<typename Iter> void random(Iter start, Iter end);
    uint8_t getKeyID();
    uint8_t getAuthType();
    uint8_t getKeySize();
};

template<class T, class E>
class DesfireApp
{
    uint8_t tagID;
    T* tagReader;


    public:
    E appKey;
    bool isAuth = false;
    std::array<uint8_t, 8> sessionKey;
    std::array<uint8_t, 3> appID;
    DesfireApp(T& device, uint8_t tag_id = 0x01, uint32_t app_id = 0, E key = E()): appKey{std::move(key)} {
        tagReader = &device;
        appID[0] = (app_id >> 16) & 0xFF;
        appID[1] = (app_id >> 8) & 0xFF;
        appID[2] = app_id & 0xFF;
        tagID = tag_id;
    };
    template<typename ContainerIN=std::initializer_list<uint8_t>, typename ContainerOUT>
    bool tagCommand(uint8_t command, std::initializer_list<uint8_t> param, ContainerOUT& data, macConfig mac=CMAC_None);
    template<typename ContainerIN, typename ContainerOUT>
    bool tagCommand(uint8_t command, ContainerIN& param, ContainerOUT& data, macConfig mac=CMAC_None);



    void selectApp();
    void createApp(uint32_t app, uint8_t key_count = 1, keyType type = KEY_2K3DES, keySettings settings = FACTORY_DEFAULT);

    bool authenticate();
    void getFileIDs();
    void getFileSetting();
    void setFileSettings();
    void createFile();
    void deleteFile();
    void formatCard();
    void listApplication(std::vector<uint32_t> ids);
};

template <class T, class E>
DesfireApp<T, E> build_desfire(T &device, uint8_t tag_id = 0x01, uint32_t app_id = 0, E key = E());

// template <class T>
// class Desfire: public T
// {
//     uint8_t tagID=0x01;

//     public:
//     using T::T;
//     void selectTag(uint8_t id);
//     template<typename ContainerIN, typename ContainerOUT>
//     bool tagCommand(uint8_t tagID, uint8_t command_code, std::initializer_list<uint8_t> param, ContainerOUT& data, macConfig mac=MAC_None);
//     template<typename ContainerIN=std::initializer_list<uint8_t>, typename ContainerOUT>
//     bool tagCommand(uint8_t tagID, uint8_t command_code, ContainerIN& param, ContainerOUT& data, macConfig mac=MAC_None);

//     template<keyType E> void selectApp();
//     template<keyType E> bool authenticate();
//     template<keyType E> bool createApp();
// };

#endif