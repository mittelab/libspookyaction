//
// Created by Pietro Saccardi on 21/12/2020.
//

#ifndef APERTURAPORTA_LOG_H
#define APERTURAPORTA_LOG_H

#include <esp_log.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PN532_TAG "PN532"
#define LOGE(format, ...) ESP_LOGE(PN532_TAG, format, ##__VA_ARGS__)
#define LOGW(format, ...) ESP_LOGW(PN532_TAG, format, ##__VA_ARGS__)
#define LOGI(format, ...) ESP_LOGI(PN532_TAG, format, ##__VA_ARGS__)
#define LOGD(format, ...) ESP_LOGD(PN532_TAG, format, ##__VA_ARGS__)
#define LOGV(format, ...) ESP_LOGV(PN532_TAG, format, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif //APERTURAPORTA_LOG_H
