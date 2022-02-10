#include <trusty/tipc.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>


#include "tuimon_ipc.h"
#include "serializer.h"



#define MATRIX_KEY_CNT  9
#define GPIO_KEY_CNT  16

#define INVALID_CONF_KEY_CODE  0xff


static const char* conf_file_path = "/system/etc/seckey.conf";
static const char* conf_matrix_key_prefix = "matrix_key";
static const char* conf_gpio_key_prefix = "secgpio_key";


static int get_sec_keys_conf(uint8_t* conf, uint32_t conf_size)
{
    if (conf == NULL || conf_size <= 0) {
        return -1;
    }

    uint32_t i = 0;
    int key = 0, j = 0;
    int keycnt = 0, confkeycnt = 0;
    char* pStr = NULL;
    char* token = NULL;

    char* pFiledata = (char*)malloc(conf_size);

    if (pFiledata == NULL) {
        return -2;
    }

    memset(pFiledata, 0, conf_size);
    memset(conf, INVALID_CONF_KEY_CODE, conf_size);

    FILE* pFile = fopen(conf_file_path, "r");

    if (NULL == pFile) {
        // file open fail
        perror("open /system/etc/seckey.conf ");
        free(pFiledata);
        return -3;
    }

    while (fgets(pFiledata, conf_size, pFile) != NULL) {
        i = 0;

        // trim line
        while (isspace(pFiledata[i++]));

        if (i >= conf_size) {
            continue;
        }

        // note content
        if (*(pFiledata + i - 1) == '#') {
            continue;
        }

        // conf
        if ((pStr = strchr(pFiledata + i, ':')) == NULL) {
            continue;
        }

        if (0 == memcmp(pFiledata, conf_matrix_key_prefix, strlen(conf_matrix_key_prefix))) {
            keycnt = MATRIX_KEY_CNT;
        }
        else if (0 == memcmp(pFiledata, conf_gpio_key_prefix, strlen(conf_gpio_key_prefix))) {
            keycnt = GPIO_KEY_CNT;
        }

        token = strtok(pStr + 1, ",");

        while (token && j <= keycnt + confkeycnt) {
            key = atoi(token);
            i2a(conf, conf_size, sizeof(key) * (j++), key, sizeof(key));
            token = strtok(NULL, ",");
        }

        confkeycnt += keycnt;
        j = confkeycnt;

        memset(pFiledata, 0, conf_size);
    }

    free(pFiledata);

    fclose(pFile);

    return 0;
}


#if 0
static void test_set_file_flag(int flag)
{
    FILE* pFile = fopen("/data/tui/temp_tui", "a+");

    if (pFile != NULL) {
        if (flag) {
            fputs("1\n", pFile);
        }
        else {
            fputs("0\n", pFile);
        }
    }
}
#endif

int secure_key_config(void)
{
    //test_set_file_flag(0);
    int rc = trusty_tuimon_connect();

    if (rc < 0) {
        printf("Error connect to tui monitor ta: %d\n", rc);
        return -2;
    }

    uint32_t cmd = TUIMON_SEC_KEY_REG;
    uint8_t recv_buf[RESP_BUF_SIZE];
    uint32_t response_size = RESP_BUF_SIZE;
    uint8_t send_buf[TRAN_BUF_SIZE];
    uint32_t request_size = TRAN_BUF_SIZE;

    memset(send_buf, 0, sizeof(send_buf));
    memset(recv_buf, 0, sizeof(recv_buf));


    rc = get_sec_keys_conf(send_buf, TRAN_BUF_SIZE);

    if (rc < 0) {
        printf("get secure key config failed...\n");
        rc = -3;
        goto fail_label;
    }

    rc = trusty_tuimon_call(cmd, send_buf, request_size, recv_buf, &response_size);

    if (rc >= 0) {
        // TODO:
    }
    else {
        printf("trusty_tuimon_call error: %d\n", rc);
        rc = -4;
        goto fail_label;
    }

    //test_set_file_flag(1);
fail_label:
    trusty_tuimon_disconnect();

    return rc;
}

