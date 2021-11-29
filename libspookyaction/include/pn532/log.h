//
// Created by Pietro Saccardi on 21/12/2020.
//

#ifndef PN532_LOG_H
#define PN532_LOG_H

#include <esp_log.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PN532_TAG "PN532"
#define PN532_LOGE(format, ...) ESP_LOGE(PN532_TAG, format, ##__VA_ARGS__)
#define PN532_LOGW(format, ...) ESP_LOGW(PN532_TAG, format, ##__VA_ARGS__)
#define PN532_LOGI(format, ...) ESP_LOGI(PN532_TAG, format, ##__VA_ARGS__)
#define PN532_LOGD(format, ...) ESP_LOGD(PN532_TAG, format, ##__VA_ARGS__)
#define PN532_LOGV(format, ...) ESP_LOGV(PN532_TAG, format, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif//PN532_LOG_H
