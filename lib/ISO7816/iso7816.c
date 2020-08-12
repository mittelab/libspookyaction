#include "iso7816.h"
#include <stddef.h>
#include <esp_err.h>


size_t select_application(uint8_t *aid, size_t aid_len, uint8_t *buffer, size_t buff_len)
{
    if(buff_len < aid_len + 4)
        return ESP_FAIL;

    buffer[0] = CLA_INTER_INUSTRY;
    buffer[1] = ISO7816_SELECT;
    buffer[2] = 0x00;
    memcpy(buffer+3,aid, aid_len);
    buffer[3 + aid_len] = 0x00;

    return 4 + aid_len;
}