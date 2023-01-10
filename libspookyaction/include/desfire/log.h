//
// Created by Pietro Saccardi on 21/12/2020.
//

#ifndef DESFIRE_LOG_H
#define DESFIRE_LOG_H

#include <esp_log.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef DESFIRE_LOG_PREFIX
#define DESFIRE_LOG_PREFIX "DESFIRE"
#endif
#define DESFIRE_LOGE(format, ...) ESP_LOGE(DESFIRE_LOG_PREFIX, format, ##__VA_ARGS__)
#define DESFIRE_LOGW(format, ...) ESP_LOGW(DESFIRE_LOG_PREFIX, format, ##__VA_ARGS__)
#define DESFIRE_LOGI(format, ...) ESP_LOGI(DESFIRE_LOG_PREFIX, format, ##__VA_ARGS__)
#define DESFIRE_LOGD(format, ...) ESP_LOGD(DESFIRE_LOG_PREFIX, format, ##__VA_ARGS__)
#define DESFIRE_LOGV(format, ...) ESP_LOGV(DESFIRE_LOG_PREFIX, format, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif//DESFIRE_LOG_H
