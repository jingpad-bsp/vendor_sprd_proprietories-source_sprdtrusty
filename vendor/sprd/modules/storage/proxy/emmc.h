/*
 * Copyright (C) 2018 spreadtrum.com
 */
#pragma once

#include <stdint.h>
#include <trusty/interface/storage.h>

#define EMMC_BLOCK_DEV_NAME "/dev/block/mmcblk0p5"
#define EMMC_BLOCK_COUNT_FILE "/sys/class/block/mmcblk0p5/size"
#define EMMC_BLOCK_SIZE 512
#define EMMC_BLOCK_USE_SIZE (1024*1024)



int emmc_open(void);

void emmc_close(void);

int emmc_cal(void);

int emmc_read(struct storage_msg *msg, const void *r, size_t req_len);

int emmc_write(struct storage_msg *msg, const void *r, size_t req_len);

