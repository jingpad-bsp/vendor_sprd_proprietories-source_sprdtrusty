/*
 * Copyright (C) 2017 spreadtrum.com
 */

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>

#include <sprdimgversion.h>
#include <rpmbproxyinterface.h>
#include "../librpmbproxy/rpmb_blk_rng.h"
#include "log.h"

#define SPRD_IMGVER_MAGIC 0xA50000A5

struct sprd_img_ver_t {
    uint32_t magic;
    uint32_t system_imgver;
    uint32_t vendor_imgver;
};

static int sprd_get_imgver(struct sprd_img_ver_t *imgver)
{
    uint8_t data_rd[MMC_BLOCK_SIZE];
    uint16_t block_ind, block_count;
    int ret;

    memset(data_rd, 0x0, sizeof(data_rd));
    block_count = sizeof(data_rd) / RPMB_DATA_SIZE;
    block_ind = SPRD_IMGVERSION_BLK;
    ret = rpmb_read(data_rd, block_ind, block_count);
    if(ret < 0) {
        LOG_ERROR("read fail! return code %d \n", ret);
        return ret;
    }

    memcpy((void *)imgver, data_rd, sizeof(struct sprd_img_ver_t));

    return 0;

}



int sprd_get_imgversion(antirb_image_type imgType, unsigned int* swVersion)
{
    struct sprd_img_ver_t imgver;
    int ret;

    ret = init_rpmb();
    if (0 != ret) {
        LOG_ERROR("init_rpmb error %d \n", ret);
        return ret;
    }

    if (imgType != IMAGE_SYSTEM && imgType != IMAGE_VENDOR) {
        LOG_ERROR("can't read antirb_image_type(%d)'s version\n", imgType);
        release_rpmb();
		return -1;
    }

    ret = sprd_get_imgver(&imgver);
    if(ret < 0) {
        LOG_ERROR("get image version fail! return code %d \n", ret);
        release_rpmb();
        return ret;
    }

    if (imgver.magic != (uint32_t)SPRD_IMGVER_MAGIC) {
        LOG_ERROR("invalid sprd imgversion magic %x exp %x \n", imgver.magic, SPRD_IMGVER_MAGIC);
        release_rpmb();
        return -1;
    }

    switch(imgType) {
        case IMAGE_SYSTEM:
            *swVersion = imgver.system_imgver;
            break;
        case IMAGE_VENDOR:
            *swVersion = imgver.vendor_imgver;
            break;
        default:
            LOG_ERROR("invalid sprd image type %d\n", imgType);
            release_rpmb();
            return -1;
    }

    release_rpmb();
    return 0;

}


int sprd_set_imgversion(antirb_image_type imgType, unsigned int swVersion)
{
    uint8_t data_wr[MMC_BLOCK_SIZE];
    uint16_t block_ind, block_count;
    struct sprd_img_ver_t imgver;
    int ret;

    ret = init_rpmb();
    if (0 != ret) {
        LOG_ERROR("init_rpmb error %d \n", ret);
        release_rpmb();
        return ret;
    }

    if (imgType != IMAGE_SYSTEM && imgType != IMAGE_VENDOR) {
        LOG_ERROR("can't write antirb_image_type(%d)'s version\n", imgType);
        release_rpmb();
		return -1;
    }

    ret = sprd_get_imgver(&imgver);
    if(ret < 0) {
        LOG_ERROR("get image version fail! return code %d \n", ret);
        release_rpmb();
        return ret;
    }

    switch(imgType) {
        case IMAGE_SYSTEM:
            imgver.system_imgver = swVersion;
            break;
        case IMAGE_VENDOR:
            imgver.vendor_imgver = swVersion;
            break;
        default:
            LOG_ERROR("invalid sprd image type %d\n", imgType);
            release_rpmb();
            return -1;
    }

    memset(data_wr, 0x0, sizeof(data_wr));
    imgver.magic = SPRD_IMGVER_MAGIC;
    memcpy((void *)data_wr, &imgver, sizeof(struct sprd_img_ver_t));

    block_ind = SPRD_IMGVERSION_BLK;
    block_count = sizeof(data_wr) / RPMB_DATA_SIZE;
    ret = rpmb_write(data_wr, block_ind, block_count);
    if (ret != block_count * RPMB_DATA_SIZE) {
        LOG_ERROR("write fail! return code %d \n", ret);
        release_rpmb();
        return ret;
    }

    release_rpmb();
    return 0;

}
