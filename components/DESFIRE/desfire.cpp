
#include <vector>
#include <algorithm>

/////////////
void AppKey<KEY_2K3DES>::padding(std::vector<uint8_t> data)
{
    size_t padding = data.size() % keySize;
    data.reserve(data.size() + padding);
    if(padding > 0) data.push_back(0x80);
    if(padding > 1) data.insert(data.end(),padding-1,0x00);
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

template<typename Container>
void AppKey<KEY_2K3DES>::setSessionKey(Container& data)
{
    std::copy(data.begin(), data.begin() + 8, iv.begin());
}

template<typename Container>
uint32_t AppKey<KEY_2K3DES>::cmac(Container& data)
{
    std::vector<uint8_t> paddedData(data.begin(), data.end());
    padding(paddedData);
    return crc32_le(0, paddedData.data(), paddedData.size());
}

///////////////////////////////////////////////////////////////////////
AppKey<KEY_3K3DES>::AppKey(uint8_t id, std::vector<uint8_t> desfireKey)
{
    keyID = id;
    key = desfireKey;
    mbedtls_des3_init(&context);
    //mbedtls_des3_setkey_dec(&context, key.data());
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

template<typename Container>
void AppKey<KEY_AES>::encrypt(Container& data)
{
    //TODO: implement padding
    mbedtls_aes_crypt_cfb128(&context, MBEDTLS_AES_ENCRYPT, data.size() ,iv.data(), data.data(), data.data());
}

template<typename Container>
void AppKey<KEY_AES>::decrypt(Container& data)
{
    //TODO: implement padding strip
    mbedtls_aes_crypt_cfb128(&context, MBEDTLS_AES_DECRYPT, data.size() ,iv.data(), data.data(), data.data());
}

template<typename Container>
void AppKey<KEY_AES>::setSessionKey(Container& data)
{
    std::copy(data.begin(), data.begin() + 16, iv.begin());
}

/////////////////
// DESFIRE APP //
/////////////////
template<class T, class E>
DesfireApp<T, E>::DesfireApp(T device, uint8_t tag_id, uint32_t id, E key)
{
    tagReader = device;
    tagID = tag_id;
    appID[0] = (id >> 16) & 0xFF;
    appID[1] = (id >> 8) & 0xFF;
    appID[2] = id & 0xFF;
    appKey = key;
}

template<class T, class E>
template<typename ContainerIN, typename ContainerOUT>
bool DesfireApp<T, E>::tagCommand(uint8_t command, std::initializer_list<uint8_t> param, ContainerOUT& data, macConfig mac)
{
    std::vector<uint8_t> sendBuffer = {command};
    sendBuffer.insert(sendBuffer.end(), param.begin(), param.end());
    T::InDataExchange(tagID, sendBuffer, data);
    return true;
}

template<class T, class E>
template<typename ContainerIN, typename ContainerOUT>
bool DesfireApp<T, E>::tagCommand(uint8_t command, ContainerIN& param, ContainerOUT& data, macConfig mac)
{
    std::vector<uint8_t> sendBuffer = {command};
    sendBuffer.insert(sendBuffer.end(), param.begin(), param.end());
    tagReader.InDataExchange(tagID, sendBuffer, data);
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

    uint8_t auth_type = appKey.getAuthType();
    std::array<uint8_t, 1> id = {appKey.getKeyID()};
    tagCommand(auth_type,id,challenge);
    if(challenge.front() != 0xAF){
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
        isAuth = false;
        return false;
    }
    response.erase(response.begin());
    appKey.decrypt(response);
    std::rotate(response.begin(), response.end() - 1, response.end());

    if(! std::equal(randomNum.begin(),randomNum.end(), response.begin())){
        isAuth = false;
        return false;
    }

    ESP_LOGI(DESFIRE_LOG, "AUTH OK");
    //set session key
    appKey.setSessionKey(sessionKey);
    isAuth = true;
    return true;
}

template<class T, class E>
void DesfireApp<T, E>::selectApp()
{
    std::vector<uint8_t> test;
    tagCommand(DESFIRE_SELECT_APPLICATION,appID, test);
}

///
// template <class T>
// void Desfire<T>::selectTag(uint8_t id)
// {
//     tagID = id;
// }

// template <class T>
// template<typename ContainerIN, typename ContainerOUT>
// bool Desfire<T>::tagCommand(uint8_t command, std::initializer_list<uint8_t> param, ContainerOUT& data, macConfig mac)
// {
//     std::vector<uint8_t> sendBuffer = {command};
//     sendBuffer.insert(sendBuffer.end(), param.begin(), param.end());
//     T::InDataExchange(tagID, sendBuffer, data);
//     return true;
// }

// template <class T>
// template<typename ContainerIN, typename ContainerOUT>
// bool Desfire<T>::tagCommand(uint8_t command, ContainerIN& param, ContainerOUT& data, macConfig mac)
// {
//     std::vector<uint8_t> sendBuffer = {command};
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
//     ESP_LOGI(DESFIRE_LOG, "AUTH OK");
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

//     ESP_LOGI(DESFIRE_LOG, "AUTH OK");
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
