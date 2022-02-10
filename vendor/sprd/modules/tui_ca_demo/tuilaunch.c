#include <stdio.h>
#include <stdbool.h>
#include <pthread.h>
#include "tuica_ipc.h"
#include "tui_vecft.h"
#include <log/log.h>

#undef LOG_TAG
#define LOG_TAG "tuiLaunch"


static uint8_t* mPtrDataIn = 0;
static uint32_t mDataInSize = 0;
static uint8_t* mPtrDataOut = 0;
static uint32_t mDataOutSize = 0;


extern int secure_display_config(void);
extern int secure_display_switch(int on);
extern int secure_tp_config(void);
extern int notify_pwr_key(int tuiOn);
#if 0 // disable key
extern int secure_kb_switch(bool on);
extern int key_receiver_start(void);
extern void key_receiver_stop(void);
#endif
int tuiStateNotify(bool tuion);


void* tui_launch_thread(void* write_fd)
{
    (void)write_fd;//remove compiling warning
    int flag = 0;
    uint32_t command = TUITA_DISP;
    ALOGI("tui_launch_thread...\n");

    if (tuiStateNotify(true) < 0) {
        ALOGE("notify tui state(on) failed !\n");
        return NULL;
    }

    flag = setTuiLanguage("zh");

    if (flag < 0) {
        ALOGE("Error initializing fontta trusty: %d\n", flag);
        goto label_out_b;
    }


    flag = trusty_cademo_connect();

    if (flag < 0) {
        ALOGE("Error initializing trusty session: %d\n", flag);
        goto label_out_b;
    }

#if 1
    flag = secure_display_switch(1);

    if (flag != 0) {
        ALOGE("secure display switch failed. %d\n", flag);
        goto label_out_a;
    }

    flag = notify_pwr_key(1);

    if (flag != 0) {
        ALOGE("tui enter. notify pwr key failed. %d\n", flag);
        goto label_out_c;
    }

#else // disable key
    flag = secure_kb_switch(1);

    if (flag != 0) {
        ALOGE("secure kb switch failed. %d\n", flag);
        goto label_out_a;
    }

    flag = key_receiver_start();

    if (flag != 0) {
        ALOGE("key receiver start failed. %d\n", flag);
        goto label_out_a;
    }

#endif

    flag = trusty_cademo_call(command, mPtrDataIn, mDataInSize, mPtrDataOut, &mDataOutSize);

    if (flag < 0) {
        ALOGE("calling  tui TA error (%d) \n", flag);
    }

#if 0
    if (flag >= 0) {
        const tademo_message* msg = reinterpret_cast<tademo_message*>(recv_buf);
        const uint8_t* payload = msg->payload;

        ALOGI("...Invoking TA to increment  counter: \n");

        for (unsigned int i = 0; i < response_size; i++) {
            ALOGI("0x%02x, ", payload[i]);
        }

        ALOGI("\n");
    }
#endif

#if 0// disable key
    key_receiver_stop();

    flag = secure_kb_switch(0);

    if (flag == 0) {
        ALOGE("secure kb switch(0) error ...\n");
        return NULL;
    }

#else
    flag = notify_pwr_key(0);

    if (flag != 0) {
        ALOGE("tui quit. notify pwr key failed. %d\n", flag);
    }

label_out_c:
    flag = secure_display_switch(0);

    if (flag != 0) {
        ALOGE("secure display switch(0) error ...\n");
    }

#endif

label_out_a:
    trusty_cademo_disconnect();
label_out_b:
    if (tuiStateNotify(false) < 0) {
        ALOGE("notify tui state(off) failed !\n");
    }

    return NULL;
}

int tui_launch(void* in, uint32_t in_size, uint8_t* out, uint32_t out_size)
{
    int rc = 0;

    if (in == NULL || in_size == 0 || out == NULL || out_size == 0) {
        return -1;
    }

    mPtrDataIn = (uint8_t*)in;
    mDataInSize = in_size;
    mPtrDataOut = out;
    mDataOutSize = out_size;

    if ((rc = secure_display_config()) < 0) {
        ALOGE("tui_launch display conf failed! rc=%d\n", rc);
        return -2;
    }

    if ((rc = secure_tp_config()) < 0) {
        ALOGE("tui_launch tp conf failed! rc=%d\n", rc);
        return -3;
    }

    pthread_t thread_t;
    rc = pthread_create(&thread_t,  NULL,  tui_launch_thread,  NULL);

    if (rc) {
        ALOGE("tui_launch_thread creat failed!\n");
        return -4;
    }

    ALOGI("tui_launch_thread creat OK\n");
    pthread_join(thread_t, NULL);

    return rc;
}



