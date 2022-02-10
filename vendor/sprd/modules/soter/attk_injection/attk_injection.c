/**
 * @file attk_injection.c
 * @brief inject SOTER attk on device
 * @version 1.0
 * @date 2019-07-05
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <cutils/properties.h>

#include "tee_production.h"
#include "production_ipc.h"

#define CHIP_CODE_OFFSET (2)
#define DEFAULT_BUF_SIZE (2048)

int main(int argc, char *argv[])
{
    uint32_t ta_return_size = DEFAULT_BUF_SIZE;
    char brand_value[PROPERTY_VALUE_MAX] = {'\0'};
    char model_value[PROPERTY_VALUE_MAX] = {'\0'};
    char platform_value[PROPERTY_VALUE_MAX] = {'\0'};
    char device_id[33] = {'\0'};
    uint8_t *tee_out = NULL;

    // platform code, e.g. ums312
    property_get("ro.board.platform", platform_value, "unknown brand");
    printf("ro.board.platform=%s\n", platform_value);

    // connect production ta
    int rc = trusty_production_connect();
    if (rc < 0)
    {
        printf("trusty_production_connect failed(%d)\n", rc);
        return -1;
    }

    tee_out = (uint8_t *) malloc(DEFAULT_BUF_SIZE);
    if (NULL == tee_out)
    {
        printf("malloc for tee_out failed.\n");
        trusty_production_disconnect();
        return -1;
    }
    memset(tee_out, 0, DEFAULT_BUF_SIZE);

    // ipc call
    rc = trusty_production_call(PRODUCTION_SECURE_SOTER, platform_value + CHIP_CODE_OFFSET, strlen(platform_value) - CHIP_CODE_OFFSET, tee_out, &ta_return_size);
    if (rc != 0)
    {
        printf("trusty_production_call failed(%d)\n", rc);
        free(tee_out);
        trusty_production_disconnect();
        return -1;
    }
    production_message *return_msg = (production_message *) tee_out;
    printf("CMD_SOTER_ATTK_OPS result: ret_code=%d ret_len=%d\n", return_msg->msg_code, ta_return_size);

    // brand & model info
    property_get("ro.product.brand", brand_value, "unknown brand");
    property_get("ro.product.model", model_value, "unknown model");
    memcpy(device_id, return_msg->payload, 32);

    // attk infos
    printf("\n=========== attk infos: ===========\n");
    printf("secure level: 10\n");
    printf("product brand: %s\n", brand_value);
    printf("product model: %s\n", model_value);
    printf("product batch:\n" );
    printf("device id: %s\n", device_id);
    printf("public key: %s\n", return_msg->payload + 32);
    printf("=========== attk infos end =========\n");

    free(tee_out);
    // disconnect ta
    trusty_production_disconnect();
    return 0;
}
