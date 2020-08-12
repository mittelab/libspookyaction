#include "desfire.h"
#include "driver/uart.h"
#include <pn532.h>
#include <string.h>
#include "mbedtls/des.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include <esp_log.h>

static const char* TAG = "desfire";

int get_applications(uart_port_t port, uint8_t tagID, uint32_t ids[28], TickType_t timeout){
    uint8_t getappID[]={
        DESFIRE_GET_APPLICATION_IDS
    };
    uint8_t ids_buff[3+28*3];
    int received = pn532_serial_data_exchange(port, tagID, getappID, sizeof(getappID), ids_buff, sizeof(ids_buff), timeout);
    ESP_LOGE(TAG, "RICEVUTI ID: %i", received);
    ESP_LOG_BUFFER_HEXDUMP(TAG, ids_buff, received, ESP_LOG_ERROR);
    return ESP_OK;
}

int select_application(uart_port_t port, uint8_t tagID, uint32_t appID, TickType_t timeout){
    uint8_t select[]={
        DESFIRE_SELECT_APPLICATION,
        (appID >> 16) & 0xFF,
        (appID >> 8) & 0xFF,
        appID & 0xFF,
    };
    uint8_t ret[3];

    pn532_serial_data_exchange(port, tagID, select, sizeof(select), ret, sizeof(ret), timeout);
    if(ret[2] != DESFIRE_OPERATION_OK)
    {
        ESP_LOGE(TAG, "TAG %#02x failed with error: %#02x", tagID, ret[2]);
        return ESP_FAIL;
    }
    return ESP_OK;
}

int autenticate(uart_port_t port, uint8_t tagID, uint8_t keyNo, uint8_t *key, uint8_t sessionKey[16], TickType_t timeout)
{
    uint8_t autenticate[]={
        DFEV1_INS_AUTHENTICATE_ISO,
        keyNo
    };
    uint8_t challenge[11];
    uint8_t response[17];
    uint8_t sessionKeybuff[16];
    unsigned char iv[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    ESP_LOGI(TAG, "###START AUTH ATTEMPT ###");
    pn532_serial_data_exchange(port, tagID, autenticate, sizeof(autenticate), challenge, sizeof(challenge) ,timeout);

    if(challenge[2] != DESFIRE_ADDITIONAL_FRAME)
    {
        ESP_LOGE(TAG, "TAG %#02x failed with error: %#02x", tagID, challenge[2]);
        return ESP_FAIL;
    }


    mbedtls_des_context des;
    mbedtls_des_init(&des);
    mbedtls_des_setkey_enc(&des, key);
    mbedtls_des_setkey_dec(&des, key);
    //uint8_t random[8] = {0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04};
    uint8_t random[8];
    uint8_t random_rotated[8];
    esp_fill_random(random, sizeof(random));

    //copy the random num,ber, and rotate left by 1
    memcpy(random_rotated, random + 1, sizeof(random_rotated) - 1* sizeof(uint8_t));
    random_rotated[7] = random [0];


    ESP_LOGI(TAG, "CHALLENGE");
    ESP_LOG_BUFFER_HEXDUMP(TAG,challenge + 3, 8 * sizeof(uint8_t), ESP_LOG_INFO);
    mbedtls_des_crypt_cbc(&des, MBEDTLS_DES_DECRYPT,8, iv, challenge + 3, response + 8);
    memcpy(sessionKeybuff     , random      , 4 * sizeof(uint8_t));
    memcpy(sessionKeybuff + 4 , response + 8, 4 * sizeof(uint8_t));
    memcpy(sessionKeybuff + 8 , random      , 4 * sizeof(uint8_t));
    memcpy(sessionKeybuff + 12, response + 8, 4 * sizeof(uint8_t));
    //rotate left
    response[16] = response[8];
    memcpy(response + 1, random, sizeof(random));
    response[0] = DESFIRE_ADDITIONAL_FRAME;

    ESP_LOGI(TAG, "RESPONSE");
    ESP_LOG_BUFFER_HEXDUMP(TAG,response + 1, 16 * sizeof(uint8_t), ESP_LOG_INFO);

    mbedtls_des_crypt_cbc(&des, MBEDTLS_DES_ENCRYPT,16, iv, response + 1, response + 1);
    ESP_LOGI(TAG, "RESPONSE(ENCRIPTED)");
    ESP_LOG_BUFFER_HEXDUMP(TAG,response + 1, 16 * sizeof(uint8_t), ESP_LOG_INFO);

    pn532_serial_data_exchange(port, tagID, response, sizeof(response), challenge, sizeof(challenge), timeout);

    ESP_LOG_BUFFER_HEXDUMP(TAG,challenge, sizeof(challenge), ESP_LOG_INFO);

    mbedtls_des_crypt_cbc(&des, MBEDTLS_DES_DECRYPT,8, iv, challenge + 3, challenge + 3);
    mbedtls_des_free(&des);

    if(challenge[2] != DESFIRE_OPERATION_OK)
    {
        ESP_LOGE(TAG, "TAG %#02x failed with error: %#02x", tagID, challenge[2]);
        return ESP_FAIL;
    }
    if(memcmp(random_rotated, challenge+3, sizeof(random_rotated)) == 0){
        memcpy(sessionKey , sessionKeybuff, sizeof(sessionKeybuff));
        ESP_LOGI(TAG, "Session Key:");
        ESP_LOG_BUFFER_HEX(TAG, sessionKeybuff, sizeof(sessionKeybuff));
        ESP_LOGI(TAG, "### AUTH SUCCESSFULL ###");
        return ESP_OK;
    }
    ESP_LOGE(TAG, "random number mismatch");
    ESP_LOG_BUFFER_HEX_LEVEL(TAG,random_rotated, sizeof(random_rotated), ESP_LOG_ERROR);
    ESP_LOG_BUFFER_HEX_LEVEL(TAG,challenge+3, sizeof(random), ESP_LOG_ERROR);
    ESP_LOGI(TAG, "### AUTH FAILED ###");
    return ESP_FAIL;
}
