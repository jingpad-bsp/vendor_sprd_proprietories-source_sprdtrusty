#include "string.h"
#include "stdio.h"
#include "tui_vecft.h"
#include "vecfont_ipc.h"
#include <log/log.h>

#undef LOG_TAG
#define LOG_TAG "tui_vecfont"

int setTuiLanguage(const char* lang)
{
    int rc = 0;
    ALOGI("setTuiLang:%s\n", lang);

    if (lang && strlen(lang) > 0) {
        uint8_t in[64];
        uint32_t insize = 64;
        uint8_t out[128];
        uint32_t outsize = 128;

        int rc = 0;
        char ftTaPortStr[128];
        vecft_session* session = NULL;
        char* token = strtok(lang, ":");

        while (token) {
            memset(ftTaPortStr, 0, 128);
            sprintf(ftTaPortStr, "%s%s", VECTOR_FONT_TA_PORT_PRIFIX, token);

            if ((session = trusty_vecfont_ta_connect(ftTaPortStr)) != NULL) {
                if ((rc = trusty_vecfont_ta_call(session,  VECFT_TA_FONT_DATA_PREPARE, in, insize, out,
                                                 &outsize)) < 0) {
                    ALOGE("call vec font ta(%s) error(%d)! pls check ta first\n", ftTaPortStr, rc);
                }

                // need something to do for 'out' ?
                //disconnect
                trusty_vecfont_ta_disconnect(session);
            }
            else {
                ALOGE("setTuiLang '%s' (com port:%s) faild!\n", token, ftTaPortStr);
                return -1;
            }

            token = strtok(NULL, ":");
        }

    }

    return rc;
}
