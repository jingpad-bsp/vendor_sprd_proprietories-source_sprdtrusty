#include <stdio.h>
#include <string.h>
#include <log/log.h>

#include "se_display.h"
#include "serializer.h"
#include "tuimon_ipc.h"


#undef LOG_TAG
#define LOG_TAG "sec_display_conf"


void serialize_disp_config(se_disp_conf* conf, uint8_t* buffer, uint32_t buffer_size)
{
    int offset = 0, len = 0;

    if (conf) {
        // first integer field for length of conf info
        offset += sizeof(int);
        //dpu ver
        len = strlen(conf->dpu_ver) - 1;
        buffer[offset] = len;
        memcpy(buffer + offset + 1, conf->dpu_ver, len);
        // spi mode
        offset += len + 1;
        buffer[offset] = sizeof(int);
        offset += 1;
        i2a(buffer, buffer_size, offset, conf->spi_mode, sizeof(conf->spi_mode));
        // lcd w
        offset += sizeof(int);
        buffer[offset] = sizeof(int);
        offset += 1;
        i2a(buffer, buffer_size, offset, conf->lcd_width, sizeof(conf->lcd_width));
        // lcd h
        offset += sizeof(int);
        buffer[offset] = sizeof(int);
        offset += 1;
        i2a(buffer, buffer_size, offset, conf->lcd_height, sizeof(conf->lcd_height));
        // cd gpio
        offset += sizeof(int);
        buffer[offset] = sizeof(int);
        offset += 1;
        i2a(buffer, buffer_size, offset, conf->cd_gpio, sizeof(conf->cd_gpio));
        // te gpio
        offset += sizeof(int);
        buffer[offset] = sizeof(int);
        offset += 1;
        i2a(buffer, buffer_size, offset, conf->te_gpio, sizeof(conf->te_gpio));
        // length of whole conf info
        offset += sizeof(int);
        i2a(buffer, buffer_size, 0, offset, sizeof(offset));
    }

#if 0 // test
    printf("============\n");

    for (int i = 0; i < 40; i++) {
        printf("0x%02x, ", buffer[i]);
    }

    printf("\n\n");
#endif
}


int secure_display_config(void)
{
    // get some config data of display device
    se_disp_conf conf;
    memset(&conf, 0, sizeof(se_disp_conf));

    int flag = get_secure_display_conf(&conf);

    if (flag != 0) {
        ALOGD("get secure display config failed: %d\n", flag);
        return -1;
    }

    int rc = trusty_tuimon_connect();

    if (rc < 0) {
        ALOGD("Error connect to tui monitor ta: %d\n", rc);
        return -2;
    }

    uint32_t cmd = TUIMON_SEC_DISP_REG;
    uint8_t recv_buf[RESP_BUF_SIZE];
    uint32_t response_size = RESP_BUF_SIZE;
    uint8_t send_buf[TRAN_BUF_SIZE];
    uint32_t request_size = TRAN_BUF_SIZE;

    memset(send_buf, 0, TRAN_BUF_SIZE);
    memset(recv_buf, 0, RESP_BUF_SIZE);

    serialize_disp_config(&conf, send_buf, request_size);

    rc = trusty_tuimon_call(cmd, send_buf, request_size, recv_buf, &response_size);

    if (rc >= 0) {
        const tuimonitor_message* msg = (tuimonitor_message*)recv_buf;

        if (msg->payload[0] == 0) {
            rc = -4;
            ALOGD("secure_display_config. error feedbacked ... \n");
        }
    }
    else {
        ALOGD("trusty_tuimon_call error: %d\n", rc);
        rc = -3;
    }

    ALOGD("secure_display_config. end: %d\n", rc);

    trusty_tuimon_disconnect();

    return rc;
}

