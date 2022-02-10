#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>

#include "sprd_fts_type.h"
#include "sprd_fts_log.h"
#include "production_cmd.h"

#define ENG_TEE_RSP_LEN (1024*2)
#define DIAG_AP_CMD_TEE_PRODUCTION 0x001d


static int tee_handler(char *buf, int len, char *rsp, int rsplen){
	uint8_t *tee_msg;
	uint32_t tee_msg_len;
	uint8_t tee_rsp[ENG_TEE_RSP_LEN] = {0};
	uint32_t tee_rsp_len = 0;
	char *rsp_ptr;
	int ret = -1;
	unsigned short status = 0x01;
	TOOLS_DIAG_AP_CNF_T *aprsp;
	MSG_HEAD_T *msg_head_ptr = (MSG_HEAD_T*)(buf + 1);
	TOOLS_DIAG_AP_CMD_T *apbuf = (TOOLS_DIAG_AP_CMD_T *)(buf + 1 + sizeof(MSG_HEAD_T));

	if(NULL == buf){
		ENG_LOG("%s: null pointer",__FUNCTION__);
		return 0;
	}

	tee_msg = (uint8_t*)(buf + 1 + sizeof(MSG_HEAD_T) + sizeof(TOOLS_DIAG_AP_CMD_T));
	tee_msg_len = apbuf->length;

	ret =  TEECex_SendMsg_To_TEE(tee_msg, tee_msg_len, tee_rsp, &tee_rsp_len);

	if(0 != ret) {
		ENG_LOG("%s: TEECex_SendMsg_To_TEE() error ret=%d\n", __FUNCTION__, ret);
	} else {
		ENG_LOG("%s: TEECex_SendMsg_To_TEE() success\n", __FUNCTION__);
		status = 0x00;
	}

	rsplen = sizeof(MSG_HEAD_T) + sizeof(TOOLS_DIAG_AP_CNF_T) + tee_rsp_len;

	rsp[0] = 0x7E;
	rsp_ptr = rsp+1;
	memcpy(rsp+1, msg_head_ptr, sizeof(MSG_HEAD_T));
	((MSG_HEAD_T*)rsp_ptr)->len = rsplen;
	aprsp = (TOOLS_DIAG_AP_CNF_T*)(rsp_ptr + sizeof(MSG_HEAD_T));
	aprsp->length = tee_rsp_len;
	aprsp->status = status;
	if(tee_rsp_len > 0){
		memcpy(rsp_ptr + sizeof(MSG_HEAD_T) + sizeof(TOOLS_DIAG_AP_CNF_T), tee_rsp, tee_rsp_len);
        }else{
		ENG_LOG("%s: TEE return tee_rsp_len error! tee_rsp_len=%d\n", __FUNCTION__, tee_rsp_len);
        }
	rsp[rsplen+1] = 0x7E;

	return rsplen+2;
}


void register_this_module(struct eng_callback *reg)
{
	ENG_LOG("register_this_module_ext :libtee");

	reg->type = 0x62; //main cmd
	reg->subtype = 0x0; //sub cmd
	reg->diag_ap_cmd = DIAG_AP_CMD_TEE_PRODUCTION;
	reg->eng_diag_func = tee_handler; // rsp function ptr
}
