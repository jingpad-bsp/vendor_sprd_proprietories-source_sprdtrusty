#include <string.h>
#include <unistd.h>

#include "sprd_fts_type.h"
#include "sprd_fts_log.h"

#define ENG_TEE_RSP_LEN (128)
#define DIAG_AP_CMD_SOTER_CHECKX 0x02

extern int eng_diag_soter_check(char *buf, int len, char *rsp, int *rsplen);

static int check_handler(char *buf, int len, char *rsp, int rsplen) {
    uint8_t *tee_msg;
    uint32_t tee_msg_len = 0;
    uint8_t tee_rsp[ENG_TEE_RSP_LEN] = {0};
    int tee_rsp_len = 0;
    char *rsp_ptr;
    int ret = -1;
    MSG_HEAD_T *msg_head_ptr = (MSG_HEAD_T*)(buf + 1);

    if (NULL == buf) {
        ENG_LOG("%s: null pointer", __FUNCTION__);
        return -1;
    }

    tee_msg = (uint8_t*)(buf + 1 + sizeof(MSG_HEAD_T) + sizeof(unsigned int));

    ret = eng_diag_soter_check(tee_msg, tee_msg_len, tee_rsp, &tee_rsp_len);
    if (0 != ret) {
        ENG_LOG("%s: eng_diag_soter_check() error ret=%d\n", __FUNCTION__, ret);
        return -1;
    } else {
    	ENG_LOG("%s: eng_diag_soter_check() success\n", __FUNCTION__);
    }

    rsplen = sizeof(MSG_HEAD_T) + sizeof(unsigned int) + tee_rsp_len;

    rsp[0] = 0x7E;
    rsp_ptr = rsp + 1;
    memcpy(rsp_ptr, msg_head_ptr, sizeof(MSG_HEAD_T) + sizeof(unsigned int));
    ((MSG_HEAD_T*)rsp_ptr)->len = rsplen;
    if (tee_rsp_len > 0) {
        memcpy(rsp_ptr + sizeof(MSG_HEAD_T) + sizeof(unsigned int), tee_rsp, tee_rsp_len);
    } else {
        ENG_LOG("%s: TEE return tee_rsp_len error! tee_rsp_len=%d\n", __FUNCTION__, tee_rsp_len);
        return -1;
    }
    rsp[rsplen + 1] = 0x7E;

    return rsplen + 2;
}

void register_this_module(struct eng_callback *reg) {
    ENG_LOG("register_this_module: soter checkx");

    reg->type = 0x5D; //main cmd
    reg->subtype = 0x02; //sub cmd
    reg->diag_ap_cmd = DIAG_AP_CMD_SOTER_CHECKX;
    reg->eng_diag_func = check_handler; // rsp function ptr
    //reg->eng_linuxcmd_func = check_handler_;
}
