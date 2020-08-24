
#include <vector>
#include <deque>
#include <algorithm>

AppKey<KEY_2K3DES>::AppKey(uint8_t id, std::vector<uint8_t> desfireKey)
{
    keyID = id;
    key = desfireKey;
    iv = {0,0,0,0,0,0,0,0};
    mbedtls_des_init(&context);
    mbedtls_des_setkey_dec(&context, key.data());

}

template<typename Container>
void AppKey<KEY_2K3DES>::encrypt(Container& data)
{
    //TODO: implement padding
    mbedtls_des_crypt_cbc(&context, MBEDTLS_DES_ENCRYPT, data.size() ,iv.data(), data.data(), data.data());
}

template<typename Container>
void AppKey<KEY_2K3DES>::decrypt(Container& data)
{
    //TODO: implement padding strip
    mbedtls_des_crypt_cbc(&context, MBEDTLS_DES_DECRYPT, data.size() ,iv.data(), data.data(), data.data());
}


AppKey<KEY_3K3DES>::AppKey(uint8_t id, std::vector<uint8_t> desfireKey)
{
    keyID = id;
    key = desfireKey;
    mbedtls_des3_init(&context);
    //mbedtls_des3_setkey_dec(&context, key.data());
}


AppKey<KEY_AES>::AppKey(uint8_t id, std::vector<uint8_t> desfireKey)
{
    keyID = id;
    key = desfireKey;
    mbedtls_aes_init(&context);
    //mbedtls_aes_setkey_dec(&context, key.data());
}


///////////////////////////////////////////////////////////////////////////////

template<keyType E>
DesfireApp<E>::DesfireApp(uint32_t id, AppKey<E> key)
{
    appID[0] = (id >> 16) & 0xFF;
    appID[1] = (id >> 8) & 0xFF;
    appID[2] = id & 0xFF;
    appKey = key;
}

///////////////////////////////////////////////////////////////////////////////

template <class T>
void Desfire<T>::selectTag(uint8_t id)
{
    tagID = id;
}

template <class T>
template<typename ContainerIN, typename ContainerOUT>
void Desfire<T>::tagCommand(uint8_t command, std::initializer_list<uint8_t> param, ContainerOUT& data)
{
    std::vector<uint8_t> sendBuffer = {command};
    sendBuffer.insert(sendBuffer.end(), param.begin(), param.end());
    T::InDataExchange(tagID, sendBuffer, data);
}

template <class T>
template<typename ContainerIN, typename ContainerOUT>
void Desfire<T>::tagCommand(uint8_t command, ContainerIN& param, ContainerOUT& data)
{
    std::vector<uint8_t> sendBuffer = {command};
    sendBuffer.insert(sendBuffer.end(), param.begin(), param.end());
    T::InDataExchange(tagID, sendBuffer, data);
}

template <class T>
template<keyType E>
void Desfire<T>::selectApp(DesfireApp<E>& application)
{
    std::vector<uint8_t> test;
    tagCommand(DESFIRE_SELECT_APPLICATION,application.appID, test);
}

template <class T>
template<keyType E>
void Desfire<T>::autenticate(DesfireApp<E>& application)
{
    uint8_t authType = DFEV1_INS_AUTHENTICATE_ISO;
    std::vector<uint8_t> challenge;
    std::vector<uint8_t> response;
    tagCommand(authType,{application.appKey.keyID},challenge);
    if(challenge.front() != 0xAF)
        return;


    // //pop status byte
    std::rotate(challenge.begin(), challenge.begin() + 1, challenge.end());
    challenge.pop_back();

    //decode and calculate response

    application.appKey.decrypt(challenge);
    std::rotate(challenge.begin(), challenge.begin() + 1, challenge.end());
    size_t key_size = challenge.size();
    challenge.resize(key_size*2); //double space for make space for the new response
    std::rotate(challenge.begin(), challenge.begin() + key_size, challenge.end());
    esp_fill_random(challenge.data(), key_size);
    application.appKey.encrypt(challenge);
    tagCommand(0xAF,challenge, response);
}