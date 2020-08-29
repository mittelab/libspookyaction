
#include <vector>
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
bool Desfire<T>::authenticate(DesfireApp<E>& application)
{
    std::array<uint8_t, 8> randomNum;
    uint8_t authType = DFEV1_INS_AUTHENTICATE_ISO;
    std::vector<uint8_t> challenge;
    std::vector<uint8_t> response;
    tagCommand(authType,{application.appKey.keyID},challenge);
    if(challenge.front() != 0xAF)
        return false;


    // //pop status byte
    challenge.erase(challenge.begin());


    //decode and calculate response

    application.appKey.decrypt(challenge);
    std::copy(challenge.begin(),challenge.begin() + 4, application.sessionKey.begin() + 4); //store second half of session key
    std::rotate(challenge.begin(), challenge.begin() + 1, challenge.end());
    size_t key_size = challenge.size();
    challenge.resize(key_size*2); //double space for make space for the new response
    std::rotate(challenge.begin(), challenge.begin() + key_size, challenge.end());
    //esp_fill_random(challenge.data(), key_size);
    application.appKey.random(challenge.begin(), challenge.begin() + key_size);
    std::copy(challenge.begin(),challenge.begin() + 8, randomNum.begin());
    std::copy(challenge.begin(),challenge.begin() + 4, application.sessionKey.begin()); //store first half of session key
    std::for_each(application.sessionKey.begin(), application.sessionKey.end(), [](uint8_t byte){ byte &= 0xFE; }); //clear first bit of each byte of the session key
    application.appKey.encrypt(challenge);
    tagCommand(0xAF,challenge, response);



    if(response.front() != 0x00)
        return false;
    response.erase(response.begin());
    application.appKey.decrypt(response);
    std::rotate(response.begin(), response.end() - 1, response.end());

    if(! std::equal(randomNum.begin(),randomNum.end(), response.begin()))
        return false;

    ESP_LOGI(DESFIRE_LOG, "AUTH OK");
    //set session key
    application.appKey.setSessionKey(application.sessionKey);
    application.isAuth = true;
    return true;
}


template <class T>
template<keyType E>
bool Desfire<T>::createApp(DesfireApp<E>& application)
{
    tagCommand();
}





template<typename Container>
void AppKey<KEY_2K3DES>::setSessionKey(Container& data)
{
    std::copy(data.begin(), data.begin() + 8, iv.begin());
}

template<typename Container>
uint32_t AppKey<KEY_2K3DES>::cmac(Container& data)
{
    return crc32_le(0, data.data(), data.size());
}

template<typename Iter>
void AppKey<KEY_2K3DES>::random(Iter start, Iter end)
{
    esp_fill_random(&(*start), std::distance(start,end));
}