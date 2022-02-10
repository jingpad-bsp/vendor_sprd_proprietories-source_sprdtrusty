#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <log/log.h>
#include <stdarg.h>

#include "se_display.h"

#undef LOG_TAG
#define LOG_TAG "sec_display_conf"


const char* const REFRESH = "/sys/class/display/dispc0/refresh";
const char* const DISABLE_FLIP = "/sys/class/display/dispc0/disable_flip";
const char* const DISABLE_TIMEOUT = "/sys/class/display/dispc0/disable_timeout";
const char* const BG_COLOR = "/sys/class/display/dispc0/bg_color";

const char* const DPU_IRQ_REG = "/sys/class/display/dispc0/irq_register";
const char* const DPU_IRQ_UNREG = "/sys/class/display/dispc0/irq_unregister";
const char* const DPU_VERSION = "/sys/class/display/dispc0/dpu_version";

const char* const ESD_CHECK = "sys/class/display/panel0/esd_check";

const char* const BRIGNTNESS =
    "/sys/devices/platform/sprd_backlight/backlight/sprd_backlight/brightness";


static int isScreenOff()
{
    int fd = open(BRIGNTNESS, O_RDONLY);

    if (fd < 0) {
        ALOGE("open screen brightness file failed. fd: %d\n", fd);
        return 0;
    }

    char brightness[20] = {0};
    read(fd, brightness, 20);
    int b = atoi(brightness);

    return b == 0 ? 1 : 0;
}


int secure_display_switch(int on)
{
    int fd0, fd1, fd2, fd3, fd4, fd5;
    char str[10] = {0};
    //int disable_flip;
    int timeout;
    int refresh;
    int bg_color;
    int reg_dpu_irq;
    static int esd_check;

    if (isScreenOff()) {
        ALOGE("display not ready. light screen on\n");
        return -2;
    }

    fd0 = open(REFRESH, O_WRONLY);
    fd1 = open(ESD_CHECK, O_WRONLY);//open(DISABLE_FLIP, O_WRONLY);
    fd2 = open(DISABLE_TIMEOUT, O_WRONLY);
    fd3 = open(BG_COLOR, O_WRONLY);
    fd4 = open(DPU_IRQ_REG, O_WRONLY);
    fd5 = open(DPU_IRQ_UNREG, O_WRONLY);

    if (fd0 < 0 || fd1 < 0 || fd2 < 0 || fd3 < 0 || fd4 < 0 || fd5 < 0) {
        ALOGE("secureDisplay Open display file node fail. %d, %d, %d, %d, %d, %d\n", fd0, fd1, fd2, fd3,
              fd4, fd5);
        return -1;
    }

    if (on == 1) {
        timeout = -1;
        //disable_flip = 1;
        bg_color = 0xffffffff;//0x00;
        reg_dpu_irq = 1;
        sprintf(str, "%d", timeout);
        ALOGD("secureDisplay enter timeout %s\n", str);
        write(fd2, str, sizeof(str));
        //sprintf(str, "%d", disable_flip);
        //write(fd1, str, sizeof(str));
        sprintf(str, "%x", bg_color);
        write(fd3, str, sizeof(str));
        sprintf(str, "%d", reg_dpu_irq);
        write(fd5, str, sizeof(str));
        //esd set last
        read(fd1, &esd_check, sizeof(esd_check));
        int esd = 0;
        sprintf(str, "%d", esd);
        write(fd1, str, sizeof(str));
    }
    else {
        timeout = 0;
        //disable_flip = 0;
        refresh = 1;
        reg_dpu_irq = 1;
        sprintf(str, "%d", refresh);
        write(fd0, str, sizeof(str));
        sprintf(str, "%d", reg_dpu_irq);
        write(fd4, str, sizeof(str));
        //esd_check
        sprintf(str, "%d", esd_check);
        write(fd1, str, sizeof(str));
    }

    return 0;
}

int get_secure_display_conf(se_disp_conf* conf)
{
    int rc = 0;
    char ver[30] = {0};

    if (conf != NULL) {
        int fd = open(DPU_VERSION, O_RDONLY);

        if (fd < 0) {
            ALOGE("get_secure_display_conf. open display file node fail. \n");
            return -1;
        }

        ssize_t cnt = read(fd, ver, 30);

        if (cnt > 0) {
            memcpy(conf->dpu_ver, ver, cnt);
        }

        // TODO: spi_mode/lcd_width/lcd_height/cd_gpio/te_gpio for spi lcd
        /*conf->spi_mode = 1;
        conf->lcd_width = 240;
        conf->lcd_height = 320;
        conf->cd_gpio = 2;
        conf->te_gpio = 3;*/
    }

    return rc;
}

