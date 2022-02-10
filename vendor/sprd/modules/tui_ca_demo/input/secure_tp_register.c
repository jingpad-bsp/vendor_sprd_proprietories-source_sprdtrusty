#include <trusty/tipc.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <log/log.h>

#include "tuimon_ipc.h"
#include "serializer.h"


#undef LOG_TAG
#define LOG_TAG "sec_tp_config"

#define CHARS_PER_CONG_ROW  256


struct stp_config {
    uint32_t int_pin_offset; //offset relative to pin reg addr
    uint32_t rst_pin_offset; //offset relative to pin reg addr
    uint32_t int_gpio_num;
    uint32_t rst_gpio_num;
    uint32_t pin_fun_mask; //function bits
    uint32_t int_fun_ns; //function in non secure world
    uint32_t int_fun_se; //function in secure world
    uint32_t rst_fun_ns; //function in non secure world
    uint32_t rst_fun_se; //function in secure world
    uint16_t width; //tp width
    uint16_t height; //tp height
    uint16_t i2c_intf; //i2c pin matrix interface
    uint16_t i2c_bus;
    uint16_t i2c_addr;
    char     vendor[32];
    char     product[32];
} __attribute__((packed));

static const char* conf_file_path = "/vendor/etc/stp.conf";
static const int struct_stp_config_mem_offset[16] = {0, 4, 4, 4, 4, 4, 4, 4, 4, 4, 2, 2, 2, 2, 2, 32};

static int getSecTpConf(struct stp_config* conf)
{
    int rc = 0;

    if (conf == NULL) {
        ALOGE("get sec tp conf ... bad param\n");
        return -1;
    }

    int i = 0, idx = 0, len = 0;
    unsigned long value;
    char* p = (char*)conf;

    FILE* pFile = fopen(conf_file_path, "r");

    if (NULL == pFile) {
        // file open fail
        perror("open /system/etc/stp.conf ");
        return -2;
    }

    char* line = (char*)malloc(CHARS_PER_CONG_ROW);

    if (line == NULL) {
        ALOGD("malloc fail.\n");
        return -3;
    }

    memset(line, 0, CHARS_PER_CONG_ROW);

    while (fgets(line, CHARS_PER_CONG_ROW, pFile) != NULL) {
        i = 0;
        len = 0;

        // trim line
        while (isspace(*(line + (i++))));

        i--;

        if (*(line + i) == '#' || strlen(line + i) == 0) {
            continue;
        }

        // conf
        p += struct_stp_config_mem_offset[idx];

        if (idx < 14) {
            value = strtoul(line, 0, 0);

            if (idx < 9) {
                *((uint32_t*)p) = (uint32_t)value;
            }
            else {
                *((uint16_t*)p) = (uint16_t)value;
            }
        }
        else {
            char* pstr = line + i;

            while (!isspace(*(pstr++))) {
                len++;
            }

            memcpy(p, line + i, (len > 32 ? 32 : len));
        }

        memset(line, 0, CHARS_PER_CONG_ROW);

        if (idx++ >= 16) {
            break;
        }
    }

    free(line);

    fclose(pFile);

#if 0
    // test
    ALOGD("//////============\n");
    char* q = (char*)conf;

    for (int i = 0; i < 120; i++) {
        if (i % 20 == 0) {
            ALOGD("\n");
        }

        ALOGD("%d , ", *(q + i));
    }

    ALOGD("\n\n");
#endif

    return rc;
}


void serialize_stp_config(struct stp_config* conf, uint8_t* buffer, uint32_t buffer_size)
{
    int i = 0;
    int offset = 0;
    uint32_t value = 0, len = 0;
    char* p = (char*)conf;

    if (conf && buffer && buffer_size > 0) {
        for (i = 0; i < 16; i++) {
            p += struct_stp_config_mem_offset[i];

            if (i < 14) {
                if (i < 9) {
                    value = *((uint32_t*)p);
                    len = sizeof(uint32_t);
                }
                else {
                    value = *((uint16_t*)p);
                    len = sizeof(uint16_t);
                }

                i2a(buffer, buffer_size, offset, value, len);
                offset += len;

            }
            else {
                memcpy(buffer + offset, p, 32);
                offset += 32;
            }
        }

    }

#if 0
    // test
    ALOGD("============\n");

    for (int i = 0; i < 120; i++) {
        if (i % 20 == 0) {
            ALOGD("\n");
        }

        ALOGD("%d , ", buffer[i]);
    }

    ALOGD("\n\n");
#endif
}


int secure_tp_config(void)
{
    ALOGD("secure_tp_config ...\n");
    //test_set_file_flag(0);
    int rc = trusty_tuimon_connect();

    if (rc < 0) {
        ALOGE("Error connect to tui monitor ta: %d\n", rc);
        return -2;
    }

    uint32_t cmd = TUIMON_SEC_TP_REG;
    uint8_t recv_buf[RESP_BUF_SIZE];
    uint32_t response_size = RESP_BUF_SIZE;
    uint8_t send_buf[TRAN_BUF_SIZE];
    uint32_t request_size = TRAN_BUF_SIZE;

    memset(send_buf, 0, sizeof(send_buf));
    memset(recv_buf, 0, sizeof(recv_buf));

    struct stp_config conf;
    memset(&conf, 0, sizeof(conf));

    rc = getSecTpConf(&conf);

    if (rc < 0) {
        ALOGE("get secure tp config failed...rc: %d\n", rc);
        rc = -3;
        goto fail_label;
    }

    serialize_stp_config(&conf, send_buf, request_size);

    rc = trusty_tuimon_call(cmd, send_buf, request_size, recv_buf, &response_size);

    if (rc >= 0) {
        // TODO:
        ALOGD("secure_tp_config. after call tui mon\n");
    }
    else {
        ALOGD("trusty_tuimon_call error: %d\n", rc);
        rc = -4;
        goto fail_label;
    }

    //test_set_file_flag(1);
fail_label:
    trusty_tuimon_disconnect();

    ALOGD("secure_tp_config . end: %d\n", rc);
    return rc;
}

