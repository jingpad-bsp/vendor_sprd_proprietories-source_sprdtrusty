#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <log/log.h>
#include <stdarg.h>
#include <unistd.h>
#include "confirmationui_ipc.h"
#include "tui_vecft.h"


#undef LOG_TAG
#define LOG_TAG "confirmationcaller"


uint8_t* pDataIn = 0;
uint32_t dataInSize = 0;
uint8_t* pDataOut = 0;
uint32_t dataOutSize = 4000;
static char localeStr[30];

extern int secure_display_config(void);
extern int secure_display_switch(int on);
extern int secure_tp_config(void);
extern int notify_pwr_key(int tuiOn);
extern int tui_launch(void* in, uint32_t in_size, uint8_t* out, uint32_t out_size);
int tuiStateNotify(bool tuion);


static void i2aa(uint8_t* a, uint32_t asize, uint32_t offset, int i, uint32_t isize)
{
    uint32_t j;

    for (j = 0; j < isize && asize >= (offset + isize); j++) {
        a[offset + j] = (uint8_t)((i >> (j * 8)) & 0xff);
    }
}

static void* confirmation_launch_thread(void* rc)
{
    ALOGD("confirmationui_launch thread...\n");
    uint32_t command = CONFIRMATIONUI_TA_LAUNCH;
    int flag = 0;

    if (tuiStateNotify(true) < 0) {
        ALOGE("notify tui state(on) failed !\n");
        *(int*)rc = -4;
        return NULL;
    }

    flag = setTuiLanguage(localeStr);

    if (flag < 0) {
        ALOGE("Error initializing fontta trusty: %d\n", flag);
        *(int*)rc = -5;
        goto label_out_b;
    }

    flag = trusty_confirmationui_connect();

    if (flag < 0) {
        ALOGE("Error initializing trusty session: %d\n", flag);
        *(int*)rc = -2;
        goto label_out_b;
    }

    flag = secure_display_switch(1);

    if (flag != 0) {
        ALOGE("confirmationui switch secure display on failed. %d\n", flag);
        *(int*)rc = -1;
        goto label_out_a;
    }

    flag = notify_pwr_key(1);

    if (flag != 0) {
        ALOGE("tui enter. notify pwr key failed. %d\n", flag);
        goto label_out_c;
    }

    flag = trusty_confirmationui_call(command, pDataIn, dataInSize, pDataOut, &dataOutSize);

    if (flag < 0) {
        ALOGE("calling  confirmationui TA error (%d) \n", flag);
        *(int*)rc = -3;
    }
    else {
#if 0
        const struct confirmationui_message* msg = (struct confirmationui_message*)pDataOut;
        const uint8_t* payload = msg->payload;
        ALOGD("confirmationui TA returned %d\n", flag);

        for (unsigned int i = 0; i < dataOutSize; i++) {
            ALOGD("0x%02x, ", payload[i]);
        }

        ALOGD("\n");
#endif
    }

    flag = notify_pwr_key(0);

    if (flag != 0) {
        ALOGE("tui quit. notify pwr key failed. %d\n", flag);
    }

label_out_c:
    flag = secure_display_switch(0);

    if (flag != 0) {
        ALOGE("confirmationui switch secure display off failed. %d\n", flag);
        *(int*)rc = -4;
    }
label_out_a:
    trusty_confirmationui_disconnect();
label_out_b:
    if (tuiStateNotify(false) < 0) {
        ALOGE("notify tui state(off) failed !\n");
    }

    ALOGD("confirmation_launch_thread ... end \n");

    return NULL;
}


static int configTui()
{
    int rc = 0;

    if ((rc = secure_display_config()) < 0) {
        ALOGD("confirmationui_launch tui display conf failed! rc=%d\n", rc);
        return -1;
    }

    if ((rc = secure_tp_config()) < 0) {
        ALOGD("confirmationui_launch tui tp conf failed! rc=%d\n", rc);
        return -2;
    }

    ALOGD("configTui. end (%d) \n", rc);
    return rc;
}


void printdata(uint32_t offset)
{
    ALOGD(" ========= DATA send to confirmationUI ta (%d) : \n", offset);

    for (uint32_t i = 0; i < offset; i++) {
        ALOGD("%x, ", pDataIn[i]);
    }

    ALOGD("========== end \n");
}

int confirmation_launch(const char* promptText, uint32_t promptTextSize, const uint8_t* extraData,
                        uint32_t extraDataSize,
                        const char* locale, uint32_t localeTextSize, uint32_t* uiOptions, uint32_t uiOptionSize,
                        uint8_t* dtwc, uint32_t* dtwcLen, uint8_t* confirmToken, uint32_t* confirmTokenLen)
{
    int rc = 0;
    int len = 0;
    uint32_t i = 0, offset = 0;
    int rc_thread = 0;
    pthread_t thread_t;

    if (!strcmp(promptText, (char*)"sampletui")) { //for app tui demo
        uint8_t recv_buf[512];
        uint32_t response_size = 512;
        uint8_t send_buf[512];
        uint32_t request_size = 512;
        ALOGI("launch sample tui ... \n");
        send_buf[0] = 0xff;
        rc = tui_launch(send_buf, request_size, recv_buf, response_size);
        ALOGI("launch sample_tui_launch_thread  %d\n", rc);
        rc = 4;// Ignored
        goto quit_;
    }

    if (promptTextSize == 0) {
        ALOGE("confirmationui_launch. null promp text. return\n");
        rc = -1;
        goto out_;
    }

    if (extraDataSize == 0) {
        ALOGE("confirmationui_launch. null extraData. return\n");
        rc = -2;
        goto out_;
    }

    // configure TUI
    if (configTui() < 0) {
        rc = -3;
        goto out_;
    }

    dataInSize = promptTextSize + extraDataSize + localeTextSize + uiOptionSize * sizeof(
                     uint32_t) + 4 * sizeof(int);

    if (dataInSize > 4096) {
        ALOGE("WARNING - confirmationui_launch - transfer data (%d bytes) larger than 4k\n", dataInSize);
    }

    pDataIn = (uint8_t*)malloc(dataInSize);

    if (pDataIn) {
        memset((uint8_t*)pDataIn, 0, dataInSize);
        offset = 0;
        // prompt text
        len = promptTextSize;
        i2aa(pDataIn, dataInSize, offset, len, sizeof(len));
        offset += sizeof(len);
        //printdata(offset);
        memcpy((uint8_t*)pDataIn + offset, promptText, len);
        offset += len;
        //printdata(offset);
        // locale
        len = localeTextSize;
        i2aa(pDataIn, dataInSize, offset, len, sizeof(len));
        offset += sizeof(len);
        //printdata(offset);
        memcpy((uint8_t*)pDataIn + offset, locale, len);
        offset += len;
        //printdata(offset);
        // extra data
        len = extraDataSize;
        i2aa(pDataIn, dataInSize, offset, len, sizeof(len));
        offset += sizeof(len);
        //printdata(offset);
        memcpy((uint8_t*)pDataIn + offset, extraData, len);
        offset += len;
        //printdata(offset);
        // UIOptions
        len = uiOptionSize;
        i2aa(pDataIn, dataInSize, offset, len, sizeof(len));
        offset += sizeof(len);

        uint32_t option = 0;

        for (i = 0; i < uiOptionSize; i++) {
            option = *((uint32_t*)(uiOptions + i));
            ALOGD("uiOption (%d) = %d\n", i, option);
            i2aa(pDataIn, dataInSize, offset, option, sizeof(option));
            offset += sizeof(option);
        }

        memset(localeStr, 0, 30);
        memcpy(localeStr, locale, localeTextSize);
    }

    if ((pDataOut = (uint8_t*)malloc(dataOutSize)) == NULL) {
        rc = -4;
        goto out_;
    }

    memset(pDataOut, 0, dataOutSize);

    rc = pthread_create(&thread_t,  NULL,  confirmation_launch_thread, (void*)(&rc_thread));

    if (rc) {
        ALOGE("confirmationui_launch_thread creat failed!\n");
        rc = -5;
        goto out_;
    }

    pthread_join(thread_t, NULL);

    if (rc_thread != 0) {
        ALOGI("launch thread occured error %d\n", rc_thread);
        rc = 4;// Ignored
        goto quit_;
    }

out_:
    if (pDataOut) {
        const struct confirmationui_message* msg = (struct confirmationui_message*)pDataOut;
        rc = (int)msg->select;
        ALOGI("user confirmed: %d\n", rc);

        if (dataOutSize > 0) {
            // return dtwc&confirmation token
            uint16_t len1 = 0, len2 = 0;
            uint8_t byte_h = 0, byte_l = 0;
            const uint8_t* payload = msg->payload;

            ALOGD("confirmationui_launch. getting confirm token.\n");

            if (confirmToken != NULL && confirmTokenLen != NULL) {
                byte_h = *(payload) & 0xff;
                byte_l = *(payload + 1) & 0xff;
                len1 = (byte_h << 8) | byte_l;
                memcpy((confirmToken), payload + 2, len1);
                *confirmTokenLen = (uint32_t)len1;
            }

            ALOGD("confirmationui_launch. getting DTWC.\n");

            if (dtwc != NULL  && dtwcLen != NULL) {
                byte_h = *(payload + 2 + len1) & 0xff;
                byte_l = *(payload + 3 + len1) & 0xff;
                len2 = (byte_h << 8) | byte_l;
                memcpy((dtwc), payload + 4 + len1, len2);
                *dtwcLen = (uint32_t)len2;
            }
        }
    }

quit_:

    // free
    if (pDataIn) {
        free(pDataIn);
    }

    if (pDataOut) {
        free(pDataOut);
    }

    pDataIn = 0;
    pDataOut = 0;

    ALOGD("confirmationui_launch. end (%d).\n", rc);
    return rc;
}



