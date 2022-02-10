#ifndef __SE_DISPLAY_H__
#define __SE_DISPLAY_H__

typedef struct {
    char dpu_ver[30];//dont change size:30
    int spi_mode;
    int lcd_width;
    int lcd_height;
    int cd_gpio;
    int te_gpio;
    uint32_t ppi;
} se_disp_conf;

int get_secure_display_conf(se_disp_conf* conf);
int secure_display_switch(int on);

#endif //__SE_DISPLAY_H__

