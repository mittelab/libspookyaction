#include <vector>
#include <algorithm>
#include <functional>
#include "desfire.hpp"

// #define PN532_LOG "APP"
// #define PN532_LOG "CRYPTO"
// #define DES_CMAC "CMAC"


/////////////
void AppKey<KEY_2K3DES>::padding(std::vector<uint8_t>& data)
{
    // ESP_LOGE(PN532_LOG, "PADDING:");
    // ESP_LOG_BUFFER_HEX_LEVEL(PN532_LOG,data.data(), data.size(), ESP_LOG_ERROR);
    size_t padding = (keySize - (data.size() % keySize)) % keySize;
    data.reserve(data.size() + padding);
    if(padding > 0) data.push_back(0x80);
    if(padding > 1) data.insert(data.end(),padding-1,0x00);
    // ESP_LOGE(PN532_LOG, "padding %d", padding);
    // ESP_LOG_BUFFER_HEX_LEVEL(PN532_LOG,data.data(), data.size(), ESP_LOG_ERROR);
}

uint8_t AppKey<KEY_2K3DES>::getKeyID()
{
    return keyID;
}

uint8_t AppKey<KEY_2K3DES>::getKeySize()
{
    return keySize;
}

uint8_t AppKey<KEY_2K3DES>::getAuthType()
{
    return authType;
}

template<typename Iter>
void AppKey<KEY_2K3DES>::random(Iter start, Iter end)
{
    esp_fill_random(&(*start), std::distance(start,end));
}
////
void AppKey<KEY_3K3DES>::padding(std::vector<uint8_t> data)
{
    size_t padding = data.size() % keySize;
    data.reserve(data.size() + padding);
    if(padding > 0) data.push_back(0x80);
    if(padding > 1) data.insert(data.end(),padding-1,0x00);
}

uint8_t AppKey<KEY_3K3DES>::getKeyID()
{
    return keyID;
}

uint8_t AppKey<KEY_3K3DES>::getKeySize()
{
    return keySize;
}

uint8_t AppKey<KEY_3K3DES>::getAuthType()
{
    return authType;
}

template<typename Iter>
void AppKey<KEY_3K3DES>::random(Iter start, Iter end)
{
    esp_fill_random(&(*start), std::distance(start,end));
}
////
void AppKey<KEY_AES>::padding(std::vector<uint8_t> data)
{
    size_t padding = data.size() % keySize;
    data.reserve(data.size() + padding);
    if(padding > 0) data.push_back(0x80);
    if(padding > 1) data.insert(data.end(),padding-1,0x00);
}

uint8_t AppKey<KEY_AES>::getKeyID()
{
    return keyID;
}

uint8_t AppKey<KEY_AES>::getKeySize()
{
    return keySize;
}

uint8_t AppKey<KEY_AES>::getAuthType()
{
    return authType;
}

template<typename Iter>
void AppKey<KEY_AES>::random(Iter start, Iter end)
{
    esp_fill_random(&(*start), std::distance(start,end));
}
////


////////////
// APPKEY //
////////////

AppKey<KEY_2K3DES>::AppKey(uint8_t id, std::vector<uint8_t> desfireKey)
{
    keyID = id;
    key = desfireKey;
    iv = {0,0,0,0,0,0,0,0};
    std::copy(key.begin(), key.begin() + sessionKey.size(), sessionKey.begin());
    mbedtls_des_init(&context);
    mbedtls_des_setkey_dec(&context, sessionKey.data());

}

template<typename IterStart, typename IterEnd, typename IterOut>
void AppKey<KEY_2K3DES>::encrypt(IterStart start, IterEnd end, IterOut out)
{
    if(std::equal(key.begin(),key.end(), sessionKey.begin())) ESP_LOGE(PN532_LOG, "key == session key");
    //TODO: implement padding
    mbedtls_des_crypt_cbc(&context, MBEDTLS_DES_ENCRYPT, std::distance(start, end) ,iv.data(), &(*start), &(*out));
}

template<typename Container>
void AppKey<KEY_2K3DES>::encrypt(Container& data)
{
    //TODO: implement padding
    encrypt(data.begin(), data.end(), data.begin());
}

template<typename IterStart, typename IterEnd, typename IterOut>
void AppKey<KEY_2K3DES>::decrypt(IterStart start, IterEnd end, IterOut out)
{
    if(std::equal(key.begin(),key.end(), sessionKey.begin())) ESP_LOGE(PN532_LOG, "key == session key");
    //TODO: implement padding
    mbedtls_des_crypt_cbc(&context, MBEDTLS_DES_DECRYPT, std::distance(start, end) ,iv.data(), &(*start), &(*out));
}

template<typename Container>
void AppKey<KEY_2K3DES>::decrypt(Container& data)
{
    //TODO: implement padding strip
    decrypt(data.begin(), data.end(), data.begin());
}

template<typename Container>
void AppKey<KEY_2K3DES>::setSessionKey(Container& data)
{
    std::copy(data.begin(), data.begin() + 8, sessionKey.begin());
}

template<typename Container>
void leftshift(Container& data)
{
    Container result;
    // ESP_LOG_BUFFER_HEX_LEVEL(PN532_LOG,data.data(), data.size(), ESP_LOG_ERROR);
    //do shift operation for N-1 bytes (left shift by 1)
    std::transform(data.rbegin() + 1, data.rend(), data.rbegin(), result.rbegin() + 1, [](uint8_t n1, uint8_t n2) -> uint8_t {return n1 << 1 | n2 >> 7;});
    //left shift the last byte
    result.back() = data.back() << 1;
    data = result;
    // ESP_LOG_BUFFER_HEX_LEVEL(PN532_LOG,data.data(), data.size(), ESP_LOG_ERROR);
}

template<typename Container>
bool  AppKey<KEY_2K3DES>::GenerateCmacSubkeys(uint8_t block_size, Container& K1, Container& K2)
{
    const uint8_t u8_R = (block_size == 8) ? 0x1B : 0x87;
    std::array<uint8_t, 8> u8_Data = {0,0,0,0,0,0,0,0};
    std::array<uint8_t, 8> iv_temp = {0,0,0,0,0,0,0,0};
    mbedtls_des_context context_temp;
    mbedtls_des_init(&context_temp);
    mbedtls_des_setkey_dec(&context_temp, sessionKey.data());
    mbedtls_des_setkey_enc(&context_temp, sessionKey.data());
    // ESP_LOG_BUFFER_HEX_LEVEL(PN532_LOG,u8_Data.data(), u8_Data.size(), ESP_LOG_ERROR);
    mbedtls_des_crypt_cbc(&context_temp, MBEDTLS_DES_ENCRYPT, block_size ,iv_temp.data(), u8_Data.data(), u8_Data.data());
    // ESP_LOG_BUFFER_HEX_LEVEL(PN532_LOG,u8_Data.data(), u8_Data.size(), ESP_LOG_ERROR);
    std::copy(u8_Data.begin(), u8_Data.begin() + block_size, K1.begin());
    leftshift(K1);
    if (u8_Data[0] & 0x80)
        K1[block_size-1] ^= u8_R;

    K2 = K1;
    leftshift(K2);
    if (K2[0] & 0x80)
        K2[block_size-1] ^= u8_R;

    // ESP_LOGE(PN532_LOG, "Session Key");
    // ESP_LOG_BUFFER_HEX_LEVEL(PN532_LOG,sessionKey.data(), sessionKey.size(), ESP_LOG_ERROR);
    // ESP_LOGE(PN532_LOG, "SUBKEY K1:");
    // ESP_LOG_BUFFER_HEX_LEVEL(PN532_LOG,K1.data(), K1.size(), ESP_LOG_ERROR);

    // ESP_LOGE(PN532_LOG, "SUBKEY K2:");
    // ESP_LOG_BUFFER_HEX_LEVEL(PN532_LOG,K2.data(), K2.size(), ESP_LOG_ERROR);
    mbedtls_des_free(&context_temp);
    return true;
}

// template<typename IterStart, typename IterEnd, typename IterOut>
// void AppKey<KEY_2K3DES>::cmac(IterStart start, IterEnd end, IterOut cmac)
// {
//     std::array<uint8_t, 8> K1,K2;
//     GenerateCmacSubkeys(8, K1,K2);
//     if(std::equal(key.begin(),key.end(), sessionKey.begin())) ESP_LOGE(PN532_LOG, "key == session key");
//     std::vector<uint8_t> padded(start,end);
//     padding(padded);

//     if(padded.size() > keySize) encrypt(padded.begin(),padded.end() - keySize, padded.begin()); //encrypt the N-1 block
//     auto subkey = std::distance(start,end)%keySize == 0? K1.begin() : K2.begin();
//     std::transform(padded.end() - keySize, padded.end(), subkey, padded.end() - keySize, std::bit_xor<uint8_t>());

//     encrypt(padded.end() - keySize, padded.end(), padded.end() - keySize); //encrypt the last block
//     if(std::equal(padded.end() - keySize,padded.end(), iv.begin())) ESP_LOGE(PN532_LOG, "IV == cmac");

//     std::copy(iv.begin(),iv.end(), cmac);
// }

template<typename IterStart, typename IterEnd, typename IterOut>
void AppKey<KEY_2K3DES>::cmac(IterStart start, IterEnd end, IterOut cmac)
{
    std::array<uint8_t, 24> cmac_key;
    auto keyinfo = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_DES_EDE3_ECB);
    std::copy(sessionKey.begin(),sessionKey.end(),cmac_key.begin());
    std::copy(sessionKey.begin(),sessionKey.end(),cmac_key.begin() + sessionKey.size());
    std::copy(sessionKey.begin(),sessionKey.end(),cmac_key.begin() + 2*sessionKey.size());
    std::vector<uint8_t> padded(start, end);
    if(padded.size() < 8) padded.insert(padded.begin(),8 - (padded.size() % 8),0x00);
    std::transform(padded.begin(), padded.end() - keySize, iv.begin(), padded.begin(), std::bit_xor<uint8_t>());
    mbedtls_cipher_cmac(keyinfo, cmac_key.data(), 8*cmac_key.size(), &(*start),std::distance(start,end), &(*cmac));
    std::copy(cmac,cmac + iv.size(),iv.begin());
}

template<typename ContainerIn, typename ContainerOut>
void AppKey<KEY_2K3DES>::cmac(ContainerIn& dataIn, ContainerOut& cmac)
{
    cmac(dataIn.begin(), dataIn.end(), cmac.begin());
}

// template<typename Container>
// void AppKey<KEY_2K3DES>::cmac(Container& dataIn)
// {
//     std::vector<uint8_t> paddedData(dataIn.begin(), dataIn.end());
//     padding(paddedData);
//     mbedtls_des_crypt_cbc(&context, MBEDTLS_DES_ENCRYPT, paddedData.size() ,iv.data(), paddedData.data(), NULL);
// }

template<typename Container>
uint32_t AppKey<KEY_2K3DES>::crc32(Container& data)
{
    return crc32_le(0, data.data(), data.size());
}

///////////////////////////////////////////////////////////////////////
AppKey<KEY_3K3DES>::AppKey(uint8_t id, std::vector<uint8_t> desfireKey)
{
    keyID = id;
    key = desfireKey;
    mbedtls_des3_init(&context);
    //mbedtls_des3_setkey_dec(&context, key.data());
}

template<typename IterStart, typename IterEnd, typename IterOut>
void AppKey<KEY_3K3DES>::encrypt(IterStart start, IterEnd end, IterOut out)
{
    //TODO: implement padding
    mbedtls_des_crypt_cbc(&context, MBEDTLS_DES_ENCRYPT, std::distance(start, end) ,iv.data(), &(*start), &(*out));
}

template<typename Container>
void AppKey<KEY_3K3DES>::encrypt(Container& data)
{
    //TODO: implement padding
    encrypt(data.begin(), data.end(), data.begin());
}

template<typename IterStart, typename IterEnd, typename IterOut>
void AppKey<KEY_3K3DES>::decrypt(IterStart start, IterEnd end, IterOut out)
{
    //TODO: implement padding
    mbedtls_des_crypt_cbc(&context, MBEDTLS_DES_DECRYPT, std::distance(start, end) ,iv.data(), &(*start), &(*out));
}

template<typename Container>
void AppKey<KEY_3K3DES>::decrypt(Container& data)
{
    //TODO: implement padding strip
    decrypt(data.begin(), data.end(), data.begin());
}

template<typename Container>
void AppKey<KEY_3K3DES>::setSessionKey(Container& data)
{
    std::copy(data.begin(), data.begin() + 8, iv.begin());
}

template<typename Container>
void AppKey<KEY_3K3DES>::cmac(Container& dataIn, Container& cmac)
{
    std::vector<uint8_t> paddedData(dataIn.begin(), dataIn.end());
    std::vector<uint8_t> outbuff;
    outbuff.reserve(paddedData.size());
    padding(paddedData);
    encrypt(paddedData.begin(), paddedData.end(), outbuff.begin());
    std::copy(iv.begin(), iv.end(), cmac.begin());
}

template<typename Container>
uint32_t AppKey<KEY_3K3DES>::crc32(Container& data)
{
    return crc32_le(0, data.data(), data.size());
}
///////////////////////////////////////////////////////////////////////

AppKey<KEY_AES>::AppKey(uint8_t id, std::vector<uint8_t> desfireKey)
{
    keyID = id;
    key = desfireKey;
    iv = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    mbedtls_aes_init(&context);
    mbedtls_aes_setkey_dec(&context, key.data(), 128);
    mbedtls_aes_setkey_enc(&context, key.data(), 128);
}

template<typename IterStart, typename IterEnd, typename IterOut>
void AppKey<KEY_AES>::encrypt(IterStart start, IterEnd end, IterOut out)
{
    //TODO: implement padding
    mbedtls_aes_crypt_cfb128(&context, MBEDTLS_AES_ENCRYPT, std::distance(start, end) ,iv.data(), &(*start), &(*out));
}

template<typename Container>
void AppKey<KEY_AES>::encrypt(Container& data)
{
    encrypt(data.begin(), data.end(), data.begin());
}

template<typename IterStart, typename IterEnd, typename IterOut>
void AppKey<KEY_AES>::decrypt(IterStart start, IterEnd end, IterOut out)
{
    //TODO: implement padding
    mbedtls_aes_crypt_cfb128(&context, MBEDTLS_AES_DECRYPT, std::distance(start, end) ,iv.data(), &(*start), &(*out));
}

template<typename Container>
void AppKey<KEY_AES>::decrypt(Container& data)
{
    decrypt(data.begin(), data.end(), data.begin());
}

template<typename Container>
void AppKey<KEY_AES>::setSessionKey(Container& data)
{
    std::copy(data.begin(), data.begin() + 16, iv.begin());
}

template<typename Container>
uint32_t AppKey<KEY_AES>::crc32(Container& data)
{
    return crc32_le(0, data.data(), data.size());
}

/////////////////
// DESFIRE APP //
/////////////////


template<class T, class E>
template<typename ContainerIN, typename ContainerOUT>
bool DesfireApp<T, E>::tagCommand(uint8_t command, std::initializer_list<uint8_t> param, ContainerOUT& data, macConfig mac)
{
    std::vector<uint8_t> sendBuffer = {param};
    return tagCommand(command, sendBuffer, data, mac);
}

template<class T, class E>
template<typename ContainerIN, typename ContainerOUT>
bool DesfireApp<T, E>::tagCommand(uint8_t command, ContainerIN& param, ContainerOUT& data, macConfig mac)
{
    std::vector<uint8_t> sendBuffer = {command};
    std::vector<uint8_t> cmac;
    cmac.reserve(appKey.getKeySize());
    cmac.resize(8);

    if(!param.empty()) sendBuffer.insert(sendBuffer.end(), param.begin(), param.end());
    if(mac & CMAC_ENC_TX)
    {
        //calculate crc from command_code and parameters
        uint32_t crc32 = appKey.crc32(sendBuffer);
        sendBuffer.push_back(crc32 >> 24);
        sendBuffer.push_back(crc32 >> 16);
        sendBuffer.push_back(crc32 >> 8);
        sendBuffer.push_back(crc32);
        appKey.encrypt(sendBuffer.begin() + 1, sendBuffer.end(), sendBuffer.begin() + 1);
    }
    else if((mac & CMAC_CALC_TX) && command != DESFIRE_ADDITIONAL_FRAME && isAuth)
    {
        std::vector<uint8_t> buff(sendBuffer.begin(), sendBuffer.end());
        ESP_LOGE(PN532_LOG, "TXCMAC");
        appKey.cmac(buff.begin(), buff.end(), cmac.begin());
        ESP_LOG_BUFFER_HEX_LEVEL(PN532_LOG,cmac.data(),cmac.size(), ESP_LOG_ERROR);
    }

    tagReader->InDataExchange(tagID, sendBuffer, data);
    // TODO: check response code

    // TODO: check additional frames
    if(mac & CMAC_DEC_RX)
    {
        //TODO: do not decrypt the status data
        appKey.decrypt(data.begin(), data.end(), data.begin());
    }
    else if(mac & CMAC_CALC_RX)
    {
        std::vector<uint8_t> buff(data.begin() + 1, data.end() - 8);
        buff.push_back(0);
        ESP_LOGE(PN532_LOG, "RXCMAC");
        appKey.cmac(buff.begin(), buff.end(),cmac.begin());
        ESP_LOG_BUFFER_HEX_LEVEL(PN532_LOG,cmac.data(),cmac.size(), ESP_LOG_ERROR);
        if(std::equal(data.end() - 8, data.end(), cmac.begin()) != 0)
        {
            ESP_LOGE(PN532_LOG,"DEAUTH");
            isAuth = false;
            return false;
        }
    }
    return true;
}

template<class T, class E>
bool DesfireApp<T, E>::authenticate()
{

    uint8_t key_size = appKey.getKeySize();
    std::vector<uint8_t> randomNum;
    randomNum.reserve(key_size);
    std::vector<uint8_t> challenge;
    std::vector<uint8_t> response;
    ESP_LOGE(PN532_LOG,"0x%02x%02x%02x->DEAUTH",appID[0], appID[1] ,appID[2]);
    isAuth = false;
    uint8_t auth_type = appKey.getAuthType();
    std::array<uint8_t, 1> id = {appKey.getKeyID()};
    tagCommand(auth_type,id,challenge);
    if(challenge.front() != 0xAF){
        ESP_LOGE(PN532_LOG,"0x%02x%02x%02x->DEAUTH",appID[0], appID[1] ,appID[2]);
        isAuth = false;
        return false;
    }

    // //pop status byte
    challenge.erase(challenge.begin());


    //decode and calculate response
    appKey.decrypt(challenge);
    std::copy(challenge.begin(),challenge.begin() + key_size/2, sessionKey.begin() + key_size/2); //store second half of session key
    std::rotate(challenge.begin(), challenge.begin() + 1, challenge.end());

    challenge.resize(key_size*2); //double space for make space for the new response
    std::rotate(challenge.begin(), challenge.begin() + key_size, challenge.end());
    appKey.random(challenge.begin(), challenge.begin() + key_size);
    std::copy(challenge.begin(),challenge.begin() + key_size, randomNum.begin());
    std::copy(challenge.begin(),challenge.begin() + key_size/2, sessionKey.begin()); //store first half of session key
    std::for_each(sessionKey.begin(), sessionKey.end(), [](uint8_t byte){ byte &= 0xFE; }); //clear first bit of each byte of the session key
    appKey.encrypt(challenge);
    tagCommand(0xAF,challenge, response);



    if(response.front() != 0x00){
        ESP_LOGE(PN532_LOG,"0x%02x%02x%02x->DEAUTH",appID[0], appID[1] ,appID[2]);
        isAuth = false;
        return false;
    }
    response.erase(response.begin());
    appKey.decrypt(response);
    std::rotate(response.begin(), response.end() - 1, response.end());

    if(! std::equal(randomNum.begin(),randomNum.end(), response.begin())){
        ESP_LOGE(PN532_LOG,"0x%02x%02x%02x->DEAUTH",appID[0], appID[1] ,appID[2]);
        isAuth = false;
        return false;
    }

    ESP_LOGE(DESFIRE_LOG, "AUTH OK");
    //set session key
    appKey.setSessionKey(sessionKey);
    ESP_LOGE(PN532_LOG,"0x%02x%02x%02x->AUTH",appID[0], appID[1] ,appID[2]);
    isAuth = true;
    return true;
}

template<class T, class E>
void DesfireApp<T, E>::selectApp()
{
    std::vector<uint8_t> test;
    tagCommand(DESFIRE_SELECT_APPLICATION,appID, test);
}

template<class T, class E>
void DesfireApp<T, E>::createApp(uint32_t app, uint8_t key_count, keyType type, keySettings settings)
{
    std::vector<uint8_t> test;
    tagCommand(DESFIRE_CREATE_APPLICATION,
    {
        static_cast<uint8_t>(app),
        static_cast<uint8_t>(app >> 16),
        static_cast<uint8_t>(app >> 24),
        settings,
        static_cast<uint8_t> (key_count | type)
    }, test, CMAC_NO_ENCRYPT);
}

template<class T, class E>
void DesfireApp<T, E>::formatCard()
{
    std::vector<uint8_t> test;
    tagCommand(DESFIRE_FORMAT_PICC,{}, test, CMAC_NO_ENCRYPT);
}

template<class T, class E>
void DesfireApp<T, E>::listApplication(std::vector<uint32_t> ids)
{
    std::vector<uint8_t> list;
    tagCommand(DESFIRE_GET_APPLICATION_IDS,{}, list, CMAC_NO_ENCRYPT);
    for(std::size_t i = 0; i < list.size(); i += 3)
        ids.push_back(list[i] + (list[i+1] >> 8) + (list[i+2] >> 16));
}


template <class T, class E>
DesfireApp<T, E> build_desfire(T &device, uint8_t tag_id, uint32_t app_id, E key) {
    return DesfireApp<T, E>{device, tag_id, app_id, std::move(key)};
}
///
// template <class T>
// void Desfire<T>::selectTag(uint8_t id)
// {
//     tagID = id;
// }

// template <class T>
// template<typename ContainerIN, typename ContainerOUT>
// bool Desfire<T>::tagCommand(uint8_t command_code, std::initializer_list<uint8_t> param, ContainerOUT& data, macConfig mac)
// {
//     std::vector<uint8_t> sendBuffer = {command_code};
//     sendBuffer.insert(sendBuffer.end(), param.begin(), param.end());
//     T::InDataExchange(tagID, sendBuffer, data);
//     return true;
// }

// template <class T>
// template<typename ContainerIN, typename ContainerOUT>
// bool Desfire<T>::tagCommand(uint8_t command_code, ContainerIN& param, ContainerOUT& data, macConfig mac)
// {
//     std::vector<uint8_t> sendBuffer = {command_code};
//     sendBuffer.insert(sendBuffer.end(), param.begin(), param.end());
//     T::InDataExchange(tagID, sendBuffer, data);
//     return true;
// }

// template <class T>
// template<keyType E>
// void Desfire<T>::selectApp(DesfireApp<E>& application)
// {
//     std::vector<uint8_t> test;
//     tagCommand(DESFIRE_SELECT_APPLICATION,application.appID, test);
// }

// template <class T>
// template<keyType E>
// bool Desfire<T>::authenticate(DesfireApp<E>& application)
// {
//     std::array<uint8_t, 8> randomNum;
//     uint8_t authType = DFEV1_INS_AUTHENTICATE_ISO;
//     std::vector<uint8_t> challenge;
//     std::vector<uint8_t> response;
//     tagCommand(authType,{application.appKey.keyID},challenge);
//     if(challenge.front() != 0xAF)
//         return false;
//     // //pop status byte
//     challenge.erase(challenge.begin());
//     //decode and calculate response
//     application.appKey.decrypt(challenge);
//     std::copy(challenge.begin(),challenge.begin() + 4, application.sessionKey.begin() + 4); //store second half of session key
//     std::rotate(challenge.begin(), challenge.begin() + 1, challenge.end());
//     size_t key_size = challenge.size();
//     challenge.resize(key_size*2); //double space for make space for the new response
//     std::rotate(challenge.begin(), challenge.begin() + key_size, challenge.end());
//     //esp_fill_random(challenge.data(), key_size);
//     application.appKey.random(challenge.begin(), challenge.begin() + key_size);
//     std::copy(challenge.begin(),challenge.begin() + 8, randomNum.begin());
//     std::copy(challenge.begin(),challenge.begin() + 4, application.sessionKey.begin()); //store first half of session key
//     std::for_each(application.sessionKey.begin(), application.sessionKey.end(), [](uint8_t byte){ byte &= 0xFE; }); //clear first bit of each byte of the session key
//     application.appKey.encrypt(challenge);
//     tagCommand(0xAF,challenge, response);
//     if(response.front() != 0x00)
//         return false;
//     response.erase(response.begin());
//     application.appKey.decrypt(response);
//     std::rotate(response.begin(), response.end() - 1, response.end());
//     if(! std::equal(randomNum.begin(),randomNum.end(), response.begin()))
//         return false;
//     ESP_LOGE(DESFIRE_LOG, "AUTH OK");
//     //set session key
//     application.appKey.setSessionKey(application.sessionKey);
//     application.isAuth = true;
//     return true;
// }

// template <class T>
// template<keyType E>
// bool Desfire<T>::authenticate(DesfireApp<E>& application)
// {
//     uint8_t key_size = application.appKey.getKeySize();
//     std::vector<uint8_t> randomNum;
//     randomNum.reserve(key_size);
//     std::vector<uint8_t> challenge;
//     std::vector<uint8_t> response;

//     uint8_t auth_type = application.appKey.getAuthType();
//     std::array<uint8_t, 1> id = {application.appKey.getKeyID()};
//     tagCommand(auth_type,id,challenge);
//     if(challenge.front() != 0xAF){
//         application.isAuth = false;
//         return false;
//     }

//     // //pop status byte
//     challenge.erase(challenge.begin());


//     //decode and calculate response
//     application.appKey.decrypt(challenge);
//     std::copy(challenge.begin(),challenge.begin() + key_size/2, application.sessionKey.begin() + key_size/2); //store second half of session key
//     std::rotate(challenge.begin(), challenge.begin() + 1, challenge.end());

//     challenge.resize(key_size*2); //double space for make space for the new response
//     std::rotate(challenge.begin(), challenge.begin() + key_size, challenge.end());
//     application.appKey.random(challenge.begin(), challenge.begin() + key_size);
//     std::copy(challenge.begin(),challenge.begin() + key_size, randomNum.begin());
//     std::copy(challenge.begin(),challenge.begin() + key_size/2, application.sessionKey.begin()); //store first half of session key
//     std::for_each(application.sessionKey.begin(), application.sessionKey.end(), [](uint8_t byte){ byte &= 0xFE; }); //clear first bit of each byte of the session key
//     application.appKey.encrypt(challenge);
//     tagCommand(0xAF,challenge, response);



//     if(response.front() != 0x00){
//         application.isAuth = false;
//         return false;
//     }
//     response.erase(response.begin());
//     application.appKey.decrypt(response);
//     std::rotate(response.begin(), response.end() - 1, response.end());

//     if(! std::equal(randomNum.begin(),randomNum.end(), response.begin())){
//         application.isAuth = false;
//         return false;
//     }

//     ESP_LOGE(DESFIRE_LOG, "AUTH OK");
//     //set session key
//     application.appKey.setSessionKey(application.sessionKey);
//     application.isAuth = true;
//     return true;
// }


// template <class T>
// template<keyType E>
// bool Desfire<T>::createApp(DesfireApp<E>& application, keySettings settings, uint8_t keyCount, keyType type)
// {
//     tagCommand(DESFIRE_CREATE_APPLICATION, {application.appID, settings, type | keyCount});
// }
