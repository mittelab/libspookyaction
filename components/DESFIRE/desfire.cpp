
AppKey::AppKey(keyType appKeyType, std::vector<uint8_t> desfireKey)
{
    type = appKeyType;
    key = desfireKey;
    switch appKeyType
    {
        case KEY_2K3DES:
            mbedtls_des_init(&context);
            mbedtls_aes_setkey_dec();
        break;

        case KEY_3K3DES:
            mbedtls_des_init(&context);
            mbedtls_aes_setkey_dec();
        break;

        case KEY_AES:
            mbedtls_aes_init(&context);
        break;
    }
}

template<typename Container>
void AppKey::encode_2K3DES(Container& dataIn, Container& dataOut)
{

}