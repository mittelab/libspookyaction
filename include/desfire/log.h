//
// Created by Pietro Saccardi on 21/12/2020.
//

#ifndef DESFIRE_LOG_H
#define DESFIRE_LOG_H

#include <esp_log.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DESFIRE_TAG "DESFIRE"
#define LOGE(format, ...) ESP_LOGE(DESFIRE_TAG, format, ##__VA_ARGS__)
#define LOGW(format, ...) ESP_LOGW(DESFIRE_TAG, format, ##__VA_ARGS__)
#define LOGI(format, ...) ESP_LOGI(DESFIRE_TAG, format, ##__VA_ARGS__)
#define LOGD(format, ...) ESP_LOGD(DESFIRE_TAG, format, ##__VA_ARGS__)
#define LOGV(format, ...) ESP_LOGV(DESFIRE_TAG, format, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif //DESFIRE_LOG_H
