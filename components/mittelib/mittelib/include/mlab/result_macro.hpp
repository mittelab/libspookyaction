//
// Created by spak on 7/10/23.
//

#ifndef MLAB_RESULT_MACRO_HPP
#define MLAB_RESULT_MACRO_HPP

#include <esp_log.h>

#ifndef MLAB_NO_RESULT_MACROS

#ifndef MLAB_RESULT_LOG_PREFIX
#define MLAB_RESULT_LOG_PREFIX "MLAB"
#endif

#define MLAB_FAIL_MSG(CMD_STR, RESULT)                          \
    ESP_LOGW(MLAB_RESULT_LOG_PREFIX, "%s:%d failed %s with %s", \
             __FILE__, __LINE__, CMD_STR, to_string((RESULT).error()));

#define MLAB_FAIL_CMD(CMD_STR, RESULT) \
    MLAB_FAIL_MSG(CMD_STR, RESULT)     \
    return (RESULT).error();

#define MLAB_FAIL_CAST_CMD(CMD_STR, RESULT) \
    MLAB_FAIL_MSG(CMD_STR, RESULT)          \
    return cast_error((RESULT).error());

#define MLAB_CMD_WITH_NAMED_RESULT(CMD, RESULT_NAME) \
    if (auto RESULT_NAME = (CMD); not RESULT_NAME) { \
        MLAB_FAIL_CMD(#CMD, RESULT_NAME)             \
    }

#define MLAB_CAST_CMD_WITH_NAMED_RESULT(CMD, RESULT_NAME) \
    if (auto RESULT_NAME = (CMD); not RESULT_NAME) {      \
        MLAB_FAIL_CAST_CMD(#CMD, RESULT_NAME)             \
    }

#define MLAB_CMD_WITH_NAMED_RESULT_SILENT(CMD, RESULT_NAME) \
    if (auto RESULT_NAME = (CMD); not RESULT_NAME) {        \
        return RESULT_NAME.error();                         \
    }

#define TRY(CMD) MLAB_CMD_WITH_NAMED_RESULT(CMD, _r)

#define TRY_SILENT(CMD) MLAB_CMD_WITH_NAMED_RESULT_SILENT(CMD, _r)

#define TRY_RESULT(CMD)                \
    MLAB_CMD_WITH_NAMED_RESULT(CMD, r) \
    else

#define TRY_RESULT_SILENT(CMD)                \
    MLAB_CMD_WITH_NAMED_RESULT_SILENT(CMD, r) \
    else

#define TRY_RESULT_AS(CMD, RES_VAR)          \
    MLAB_CMD_WITH_NAMED_RESULT(CMD, RES_VAR) \
    else

#define TRY_RESULT_AS_SILENT(CMD, RES_VAR)          \
    MLAB_CMD_WITH_NAMED_RESULT_SILENT(CMD, RES_VAR) \
    else

#define TRY_CAST(CMD) MLAB_CAST_CMD_WITH_NAMED_RESULT(CMD, _r)

#define TRY_CAST_SILENT(CMD) MLAB_CAST_CMD_WITH_NAMED_RESULT_SILENT(CMD, _r)

#define TRY_CAST_RESULT(CMD)                \
    MLAB_CAST_CMD_WITH_NAMED_RESULT(CMD, r) \
    else

#define TRY_CAST_RESULT_SILENT(CMD)                \
    MLAB_CAST_CMD_WITH_NAMED_RESULT_SILENT(CMD, r) \
    else

#define TRY_CAST_RESULT_AS(CMD, RES_VAR)          \
    MLAB_CAST_CMD_WITH_NAMED_RESULT(CMD, RES_VAR) \
    else

#define TRY_CAST_RESULT_AS_SILENT(CMD, RES_VAR)          \
    MLAB_CAST_CMD_WITH_NAMED_RESULT_SILENT(CMD, RES_VAR) \
    else

#endif

#endif//MLAB_RESULT_MACRO_HPP
