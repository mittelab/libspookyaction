
#include <vector>

AppKey<KEY_2K3DES>::AppKey(uint8_t id, std::vector<uint8_t> desfireKey)
{
    keyID = id;
    key = desfireKey;
    iv = {0,0,0,0,0,0,0,0};
    mbedtls_des_init(&context);
    mbedtls_des_setkey_dec(&context, key.data());

}

template<typename Container>
void AppKey<KEY_2K3DES>::encrypt(Container& dataIn, Container& dataOut)
{
    //TODO: implement padding
    dataOut.resize(dataIn.size());
    mbedtls_des_crypt_cbc(&context, MBEDTLS_DES_ENCRYPT, dataIn.size() ,iv.data(), dataIn.data(), dataOut.data());
}

template<typename Container>
void AppKey<KEY_2K3DES>::decrypt(Container& dataIn, Container& dataOut)
{
    //TODO: implement padding strip
    dataOut.resize(dataIn.size());
    mbedtls_des_crypt_cbc(&context, MBEDTLS_DES_DECRYPT, dataIn.size() ,iv.data(), dataIn.data(), dataOut.data());
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
template<keyType E, typename Container>
void Desfire<T>::tagCommand(uint8_t command, std::initializer_list<uint8_t> param, Container& data)
{
    Container sendBuffer = {command};
    sendBuffer.insert(sendBuffer.end(), param.begin(), param.end());
    T::InDataExchange(tagID, sendBuffer, data);
}

template <class T>
template<keyType E, typename Container>
void Desfire<T>::tagCommand(uint8_t command, Container& param, Container& data)
{
    Container sendBuffer = {command};
    sendBuffer.insert(sendBuffer.end(), param.begin(), param.end());
    T::InDataExchange(tagID, sendBuffer, data);
}

template <class T>
template<keyType E>
void Desfire<T>::selectApp(DesfireApp<E>& application)
{
    T::tagCommand(DESFIRE_SELECT_APPLICATION,application.appID);
}