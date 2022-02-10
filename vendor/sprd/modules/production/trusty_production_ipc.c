/*
 * Copyright (c) 2015, Spreadtrum.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "crc16.h"
#include <sys/ioctl.h>
#include <sys/types.h>

#define LOG_TAG "TrustyProduction"
#include <cutils/log.h>

#include <trusty/tipc.h>

#include "tee_production.h"
#include "production_ipc.h"
#include <cutils/properties.h>
#include "rpmb_client.h"
#include "trusty_production_pubefuse.h"

#define TRUSTY_DEVICE_NAME "/dev/trusty-ipc-dev0"

#define MAX_TRANS_SIZE 4024  //for keybox CA transfort to TA
#define KEYBOX_CHECKSUM_LENGTH 2
#define HAS_WRITE_KEYBOX 0x5A5A
#define CHECK_KEYBOX_DEVID 0x5B5B
#define NOT_WRITE_KEYBOX    0x0
#define SUPPORT_MORE_KEYBOX 0x2

#define CHIP_CODE_OFFSET (0)

#define msleep(ms) usleep((ms) * (1000))

extern int rpmb_program_key(uint8_t *key_byte, size_t key_len);
//extern int production_efuse_secure_is_enabled(void);
//extern int production_efuse_secure_enable(void);

static int handle_ = 0;

int trusty_production_connect(void){
    ALOGD("%s enter\n", __func__);
    int rc = tipc_connect(TRUSTY_DEVICE_NAME, PRODUCTION_PORT);
    if (rc < 0) {
        ALOGD("tipc_connect() failed! \n");
        return rc;
    }
    handle_ = rc;
    ALOGD("handle = %d \n", handle_);
    return 0;
}

int trusty_production_call(uint32_t cmd, void * in, uint32_t in_size, uint8_t * out, uint32_t * out_size){
    ALOGD("Enter %s, cmd is %02x, in_size = %d \n", __func__, cmd, in_size);
    if (handle_ == 0) {
        ALOGD("not connected\n");
        return -EINVAL;
    }

    size_t msg_size = in_size + sizeof(production_message);
    production_message *msg = malloc(msg_size) ;
    msg->cmd = cmd;
    msg->msg_code = 0 ;
    memcpy(msg->payload, in, in_size);

    ssize_t rc = write(handle_, msg, msg_size);
    free(msg);

    if (rc < 0) {
        ALOGD("failed to send cmd (%d) to %s: %s\n", cmd,
        PRODUCTION_PORT, strerror(errno));
        return -errno;
    }

    rc = read(handle_, out, *out_size);
    if (rc < 0) {
        ALOGD("failed to retrieve response for cmd (%d) to %s: %s\n",
                cmd, PRODUCTION_PORT, strerror(errno));
        return -errno;
    }

    if ((size_t) rc < sizeof(production_message)) {
        ALOGD("invalid response size (%d)\n", (int) rc);
        return -EINVAL;
    }

    msg = (production_message*) out;

    if ((cmd | PRODUCTION_RESP_BIT) != msg->cmd) {
        ALOGD("invalid command (%d)", msg->cmd);
        return -EINVAL;
    }

    *out_size = ((size_t) rc) - sizeof(production_message);
    ALOGD("CA read rsp from TA, rsp cmd is %x, msg->msg_code is %x, out_size is %d\n", msg->cmd, msg->msg_code, *out_size);
    return msg->msg_code;
}

void trusty_production_disconnect() {
    if (handle_ != 0) {
        tipc_close(handle_);
    }
}

static uint8_t *sec_memcpy_invert(uint8_t *dest, const uint8_t *src, unsigned int count)
{
    char *tmp = dest;
    const char *s = src+count-1;

    while (count--)
        *tmp++ = *s--;
    return dest;
}

static void organize_rsp(uint16_t msg_id, int msg_code, uint8_t* msg_data, uint32_t * out_size, uint8_t* rsp, uint32_t* rsp_len){
    ALOGD("production CA organize_rsp, start!\n");
    uint32_t length=8;
    uint16_t id = 0 ;
    uint8_t flag=RSP_FLAG;
    int return_code = msg_code;
    uint8_t* command_data;
    uint8_t xor_data;
    if(*out_size>0 && msg_data!=NULL){
        length += *out_size;
        command_data = msg_data;
    }
    *rsp_len = length+4;
    ALOGD("production CA organize_rsp, rsp_len is %d, return_code is %x, out_size is %d.\n",*rsp_len, return_code, *out_size);
    switch(msg_id){
        case CMD_SYSTEM_INIT:
            id=RSP_SYSTEM_INIT;
            break;
        case CMD_GET_UID:
            id=RSP_GET_UID;
            break;
        case CMD_SET_RTC:
            id=RSP_SET_RTC;
            break;
        case CMD_SET_ROTPK:
            id=RSP_SET_ROTPK;
            break;
        case CMD_GET_ROTPK:
            id=RSP_GET_ROTPK;
            break;
        case CMD_SYSTEM_CLOSE:
            id=RSP_SYSTEM_CLOSE;
            break;
        case CMD_CHECK_SECURE:
            id=RSP_CHECK_SECURE;
            break;
        case CMD_GET_DEVICE_ID:
             id=RSP_GET_DEVICE_ID;
             break;
        case CMD_SEND_KEYBOX:
             id=RSP_SEND_KEYBOX;
            break;
        case CMD_IFAA_SET_RSA:
            id=RSP_IFAA_SET_RSA;
            break;
        case CMD_SOTER_ATTK_OPS:
            id=RSP_SOTER_ATTK_OPS;
            break;
        case CMD_SEND_WIDEVINE:
            id=RSP_SEND_WIDEVINE;
            break;
        case CMD_CHECK_KEYBOX:
             id=RSP_CHECK_KEYBOX;
            break;
        case CMD_CHECK_WIDEVINE:
            id=RSP_CHECK_WIDEVINE;
            break;
        case CMD_INIT_STORAGE:
             id=RSP_INIT_STORAGE;
            break;
        default:
            id=CMD_DEFAULT_ID;
            ALOGD("%s id(%x) is error!!!\n", __func__, id);
            break;
    }
    ALOGD("%s id is %x\n", __func__, id);
    memcpy(rsp, &length, sizeof(uint32_t));
    memcpy(rsp+4, &id, sizeof(uint16_t));
    memcpy(rsp+6, &flag, sizeof(uint8_t));
    memcpy(rsp+7, &return_code, sizeof(int));
    if(*out_size>0 && msg_data!=NULL){
        memcpy(rsp+11, command_data, *out_size);
    }
    xor_data = rsp[0];
    int i = 0;
    for(i=1;i<*rsp_len-1;i++){
        xor_data ^= rsp[i];
    }
    rsp[*rsp_len-1] = xor_data;
}

static int rpmbserver_start(void){
    ALOGD("Enter %s, \n", __func__);
    char is_running[PROPERTY_VALUE_MAX] = {'\0'};
    int count = 0;

    for(count = 0; count < 1000; count++){
        msleep(1);
        property_get("init.svc.vendor.rpmbsvr", is_running, "");
        if(!strncmp(is_running, "running",7 )){
            ALOGD("property:init.svc.vendor.rpmbsvr:%s\n",is_running);
            return 0;
        }
    }

    return -1;
}


/*
* @device_id:output,to get device id value
* @out_size:output,to get device id length
*/
int get_device_id(uint8_t * device_id, uint32_t * out_size){
    ALOGD("Enter %s, \n", __func__);
    char prop[PROPERTY_VALUE_MAX] = {0};
    char miscdata_path[PROPERTY_VALUE_MAX] = {0};
    char temp_id[SN_LENGTH] = {'\0'};
    int fd = -1;
    off_t curpos, offset;
    int result = PROD_OK;

    if ((NULL == device_id) || (NULL == out_size)){
        ALOGD("%s()->Line:%d; device id is NULL \n", __FUNCTION__, __LINE__);
        *device_id = 0;
        *out_size = 0;
        return PROD_ERROR_GET_DEVICE_ID;
    }

    if(-1 == property_get(PARTITIONPATH, prop, "")){
        ALOGD("%s: get partitionpath fail\n", __FUNCTION__);
        return PROD_ERROR_GET_DEVICE_ID;
    }

    sprintf(miscdata_path, "%smiscdata", prop);
    fd = open(miscdata_path, O_RDONLY);
    if (fd >= 0) {
       ALOGD("%s open Ok miscdata_path = %s ", __FUNCTION__,
                miscdata_path);
    offset = SN_OFFSET;
    curpos = lseek(fd, offset, SEEK_CUR);
    if (curpos == -1) {
        ALOGE("%s()->Line:%d; lseek error\n", __FUNCTION__, __LINE__);
        close(fd);
        return PROD_ERROR_GET_DEVICE_ID;
    }

    result = read(fd, temp_id, SN_LENGTH);
    if (result <= 0) {
    ALOGE("%s()->Line:%d; read SN data error, retcode = %d; \n",
            __FUNCTION__, __LINE__, result);
        close(fd);
        return PROD_ERROR_GET_DEVICE_ID;
    }
    } else {
        ALOGD("%s open fail miscdata_path = %s ", __FUNCTION__,
             miscdata_path);
        close(fd);
        return PROD_ERROR_GET_DEVICE_ID;
    }

    *out_size = strlen((char *)temp_id);
    sprintf(device_id, temp_id, *out_size);
    ALOGD("%s()->Line:%d; device_id = %s out_size =%d \n", __FUNCTION__, __LINE__, (char *)device_id,*out_size);
    close(fd);
    return PROD_OK;
}


uint32_t TEECex_SendMsg_To_TEE(uint8_t* msg, uint32_t msg_len, uint8_t* rsp, uint32_t* rsp_len){
    int result = PROD_OK;

    uint32_t ta_return_size = PRODUCTION_SOTER_MAX_TA_RETURN_BUFFER;
    char brand_value[PROPERTY_VALUE_MAX] = {'\0'};
    char model_value[PROPERTY_VALUE_MAX] = {'\0'};
    uint8_t* tee_out = NULL;
    uint8_t* tmp_out = NULL;
    soter_dev_info_t dev_info;
    uint32_t trans_len = MAX_TRANS_SIZE;
    unsigned short temp_crc_value = 0;
    unsigned short *crc_value = 0;
    int keybox_enable = 0;
    char keybox_prop[PROPERTY_VALUE_MAX] = {'\0'};

    ALOGD("%s production enter\n", __func__);
    result = trusty_production_connect();
    if(result!=0){
        ALOGD("production trusty_production_connect failed with ret = %d", result);
        return PROD_ERROR_UNKNOW;
    }
    /*parse msg, get command_data */
    command_header commandHeader;
    uint8_t* command_data = NULL ;

    uint32_t data_len = 0;

    sec_memcpy_invert(&commandHeader.length,msg,sizeof(uint32_t));
    sec_memcpy_invert(&commandHeader.id,msg+sizeof(uint32_t),sizeof(uint16_t));
    sec_memcpy_invert(&commandHeader.flag,msg+sizeof(uint32_t)+sizeof(uint16_t),sizeof(uint8_t));
    sec_memcpy_invert(&commandHeader.uuid,msg+sizeof(uint32_t)+sizeof(uint16_t)+sizeof(uint8_t),sizeof(uuid_t));
    sec_memcpy_invert(&commandHeader.command_id,msg+sizeof(uint32_t)+sizeof(uint16_t)+sizeof(uint8_t)+sizeof(uuid_t),sizeof(uint32_t));
    ALOGD("commandHeader.length is %x, commandHeader.id is %x, commandHeader.flag is %x, commandHeader.command_id is %x \n",
    commandHeader.length, commandHeader.id, commandHeader.flag, commandHeader.command_id);

    data_len = commandHeader.length-25;
    ALOGD("production CA get commandData len is %d, data is ", data_len);
    if(data_len>0){
        // has command_data
        command_data =(uint8_t*)(msg + 27);
    }
    /*typedef struct _production_message {
      uint32_t cmd;
      int msg_code;
      uint8_t payload[0];
    }production_message;
    because of out_data_size = 64 , payload need 64 Bytes ,struct _production_message need 72 Bytes*/
    uint8_t out[72] = {0};
    uint32_t out_data_size = 64;
    production_message *return_msg;
    uint8_t rpmb_wrong_key = 0;
    ALOGD("production CA parse_msg, then start switch, commandHeader.id is %x\n", commandHeader.id);
    switch(commandHeader.id){
    case CMD_SYSTEM_INIT:// system init
        ALOGD("production CA command_system_init\n");
        //ALOGD("production CA begin to write secure \n");
        //if(!production_efuse_secure_is_enabled())
           // production_efuse_secure_enable();
        //ALOGD("production CA has write secure \n");
        result = trusty_production_call(PRODUCTION_SYSTEM_INIT, command_data, data_len, out, &out_data_size);
        return_msg = (production_message*) out; //return_msg initialize
        if(PROD_ERROR_GET_RPMB == return_msg->msg_code){
            ALOGD("production CA wr_rpmb_key has been provisioned,return_msg->msg_code:%d, result:%d,\n", return_msg->msg_code, result);
            rpmb_wrong_key = PROD_ERROR_GET_RPMB;
            result = PROD_OK;
        }
        if(result == PROD_OK){
            if(rpmbserver_start()){
                ALOGD("production start rpmbserver error !\n");
                char * err_result = "production start rpmbserver error !\n";
                out_data_size = strlen(err_result);
                organize_rsp(commandHeader.id, SPRD_ERROR_START_RPMBSERVER, err_result, &out_data_size, rsp, rsp_len);
                break;
            }
            ALOGD("production CA command_system_init has successed, start wr_rpmb_key!\n");
            // get RPMB key, then write RPMB to EMMC driver
            if ((0 == is_wr_rpmb_key()) && (rpmb_wrong_key != PROD_ERROR_GET_RPMB)){
                result = wr_rpmb_key(return_msg->payload, out_data_size);// payload need 64 Bytes
            }else {
                if(rpmb_wrong_key == PROD_ERROR_GET_RPMB){
                    ALOGD("production CA wr_rpmb_key has been provisioned!\n");
                }else{
                    ALOGD("production CA wr_rpmb_key has written!\n");
                }
                result = 0;
            }
            if(result == 0){
                ALOGD("production CA rpmb_program_key, success!\n");
                if(run_storageproxyd()){
                    ALOGD("production start storageproxyd error !\n");
                    char * err_result = "production start storageproxyd error !\n";
                    out_data_size = strlen(err_result);
                    organize_rsp(commandHeader.id, SPRD_ERROR_START_STORAGEPROXYD, err_result, &out_data_size, rsp, rsp_len);
                    break;
                }
                ALOGD("production start storageproxyd success!\n");
                out_data_size = sizeof(production_message);
                result = trusty_production_call(PRODUCTION_RPMB_BLOCK_INIT, command_data, data_len, out, &out_data_size);
                if(result == 0){
                    ALOGD("production CA init version, success!\n");
                    organize_rsp(commandHeader.id, PROD_OK, NULL, &out_data_size, rsp, rsp_len);
                }else{
                    ALOGD("production CA init version error, result is %x !\n", result);
                    char * err_result = "production CA init version error !\n";
                    out_data_size = strlen(err_result);
                    organize_rsp(commandHeader.id, PROD_ERROR_WR_RPMB, err_result, &out_data_size, rsp, rsp_len);
                    break;
                }
            }else {
                ALOGD("production CA wr_rpmb_key error, result is %x !\n", result);
                char * err_result = "production CA wr rpmb key error !\n";
                out_data_size = strlen(err_result);
                organize_rsp(commandHeader.id, PROD_ERROR_WR_RPMB, err_result, &out_data_size, rsp, rsp_len);
                break;
            }
        }else{
            ALOGD("production CA command_system_init, error!\n");
            if(PROD_ERROR_NOT_WR_HUK == return_msg->msg_code){
                char * err_result = "production not write HUK !\n";
                out_data_size = strlen(err_result);
                organize_rsp(commandHeader.id, return_msg->msg_code, err_result, &out_data_size, rsp, rsp_len);
                break;
            }else{
                organize_rsp(commandHeader.id, return_msg->msg_code, NULL, &out_data_size, rsp, rsp_len);
            }
        }
        break;
    case CMD_GET_UID:// get uid
        ALOGD("production CA command_get_uid\n");
//        result = efuse_uid_read(out, &out_data_size);
        result = production_diag_user_handle(CMD_GET_EFUSEUID, 0, 0, NULL, out, &out_data_size);
        if(result == PROD_OK){
            ALOGD("production CA getUID success ,out:%s!\n",out);
            organize_rsp(commandHeader.id, result, out, &out_data_size, rsp, rsp_len);
        }else{
            ALOGD("production CA getUID failed !\n");
            organize_rsp(commandHeader.id, result, NULL, &out_data_size, rsp, rsp_len);
        }
        break;
    case CMD_SET_RTC:// set RTC
        ALOGD("production CA command_set_rtc\n");
        break;
    case CMD_SET_ROTPK:
        ALOGD("production CA command_set_rotpk\n");
        result = trusty_production_call(PRODUCTION_SET_ROTPK, command_data, data_len, out, &out_data_size);
        return_msg = (production_message*) out;
        if(result == PROD_OK){
            ALOGD("production CA command_set_rotpk success\n");
            organize_rsp(commandHeader.id, return_msg->msg_code, NULL, &out_data_size, rsp, rsp_len);
        }else{
            ALOGD("production CA command_set_rotpk fail\n");
            organize_rsp(commandHeader.id, return_msg->msg_code, NULL, &out_data_size, rsp, rsp_len);
        }
        break;
    case CMD_GET_ROTPK:
        ALOGD("production CA command_get_rotpk\n");
        result = trusty_production_call(PRODUCTION_GET_ROTPK, command_data, data_len, out, &out_data_size);
        return_msg = (production_message*) out;
        if(result == PROD_OK){
            organize_rsp(commandHeader.id, return_msg->msg_code, return_msg->payload, &out_data_size, rsp, rsp_len);
        }else{
            organize_rsp(commandHeader.id, return_msg->msg_code, NULL, &out_data_size, rsp, rsp_len);
        }
        break;
    case CMD_SYSTEM_CLOSE:// system close
        ALOGD("production CA command_system_close\n");
        result = trusty_production_call(PRODUCTION_SYSTEM_CLOSE, command_data, data_len, out, &out_data_size);
        return_msg = (production_message*) out;
        if(result == PROD_OK){
            ALOGD("production CA command_system_close success\n");
            organize_rsp(commandHeader.id, return_msg->msg_code, NULL, &out_data_size, rsp, rsp_len);
        }else{
            ALOGD("production CA command_system_close fail\n");
            organize_rsp(commandHeader.id, return_msg->msg_code, NULL, &out_data_size, rsp, rsp_len);
        }
        break;
    case CMD_CHECK_SECURE:// get lcs
        ALOGD("production CA command_check_secure\n");
        result = trusty_production_call(PRODUCTION_CHECK_SECURE, command_data, data_len, out, &out_data_size);
        return_msg = (production_message*) out;
        int sec_enable = 0;
        out_data_size = 0;
        if(result == PROD_OK){
        //if(production_efuse_secure_is_enabled() && return_msg->payload[0])
            ALOGD("production CA command_check_secure success,return_msg->payload[0]: %d\n", return_msg->payload[0]);
            if(return_msg->payload[0] == 1)
                sec_enable = 1;
            organize_rsp(commandHeader.id, sec_enable, NULL, &out_data_size, rsp, rsp_len);
        }else{
            ALOGD("production CA command_check_secure fail\n");
            organize_rsp(commandHeader.id, sec_enable, NULL, &out_data_size, rsp, rsp_len);
        }
        break;
    case CMD_GET_DEVICE_ID://get device id
        ALOGD("production CA command_get_device_id\n");
        result = get_device_id(out, &out_data_size);
        if(result == PROD_OK){
            ALOGD("production CA get device id success !\n");
            organize_rsp(commandHeader.id, result, out, &out_data_size, rsp, rsp_len);
        }else{
            ALOGD("production CA get device id failed !\n");
            organize_rsp(commandHeader.id, result, NULL, &out_data_size, rsp, rsp_len);
        }
        break;
    case CMD_SEND_KEYBOX://send keybox
        ALOGD("production CA read ro.keybox.id.value value from ANDROID proterty.\n");
        if(-1 == property_get(KEYBOXPROP, keybox_prop, "")){
            ALOGD("production CA read keybox config property value fail.\n");
            char * err_result = "production CA read keybox config property value fail !\n";
            out_data_size = strlen(err_result);
            organize_rsp(commandHeader.id, PROD_ERROR_SEND_KEYB, err_result, &out_data_size, rsp, rsp_len);
            break;
        }
        ALOGD("production CA read keybox config property value success, value: < %s > .\n", keybox_prop);
        result = trusty_production_call(PRODUCTION_CHECK_DEVID, keybox_prop, strlen(keybox_prop), out, &out_data_size);
        return_msg = (production_message*) out;
        if(result != PROD_OK){
            ALOGD("production CA check device id fail.\n");
            organize_rsp(commandHeader.id, CHECK_KEYBOX_DEVID, NULL, &out_data_size, rsp, rsp_len);
            break;
        }
        ALOGD("production CA command_send_keybox,data_len=%d\n",data_len);
        out_data_size = 64;
        result = trusty_production_call(PRODUCTION_CHECK_KEYBOX, command_data, 0, out, &out_data_size);
        return_msg = (production_message*) out;
        if(result == PROD_OK){
            ALOGD("production CA command_check_keybox success before write keybox,return_msg->payload[0]: %d, return_msg->payload[1]: %d\n", return_msg->payload[0], return_msg->payload[1]);
            if((return_msg->payload[0] == NOT_WRITE_KEYBOX) || (return_msg->payload[1] == SUPPORT_MORE_KEYBOX)){
                /*get from PC keybox CRC*/
                crc_value = (unsigned short*)(command_data+data_len - KEYBOX_CHECKSUM_LENGTH);
                /*cal keybox CRC*/
                temp_crc_value = crc16(temp_crc_value, (unsigned char *)command_data, (data_len - KEYBOX_CHECKSUM_LENGTH));
                ALOGD("%s keybox CRC by pass is %d, by cal is:%d\n", __FUNCTION__,*crc_value,temp_crc_value);
                if (*crc_value != temp_crc_value) {
                    ALOGD("%s cmp keybox CRC value Error\n", __FUNCTION__);
                    out_data_size = 0;
                    organize_rsp(commandHeader.id, PROD_ERROR_SEND_KEYB, NULL, &out_data_size, rsp, rsp_len);
                    break;
                }
                ALOGD("%s cmp keybox CRC value success\n", __FUNCTION__);
                //memset(return_msg,0,sizeof(production_message));
                data_len -= KEYBOX_CHECKSUM_LENGTH;
                while(data_len){
                    if(trans_len > data_len)
                        trans_len = data_len;
                    ALOGD("command_send_keybox,trans_len=%d\n",trans_len);
                    memset(out,0,sizeof(out));
                    out_data_size = sizeof(production_message);
                    result = trusty_production_call(PRODUCTION_SEND_KEYBOX, command_data, trans_len, out, &out_data_size);
                    //result = trusty_production_call(PRODUCTION_SEND_KEYBOX, trans_data, trans_len, out, &out_data_size);
                    data_len -= trans_len;
                    command_data += trans_len;
                    return_msg = (production_message*) out;
                    if(result < 0){
                        ALOGD("production CA send keybox fail !\n");
                        organize_rsp(commandHeader.id, return_msg->msg_code, NULL, &out_data_size, rsp, rsp_len);
                        break;
                    }
                }
                //result = trusty_production_call(PRODUCTION_SEND_KEYBOX, command_data, data_len, out, &out_data_size);
                return_msg = (production_message*) out;
                if(result == PROD_OK){
                    ALOGD("production CA send keybox success !\n");
                    organize_rsp(commandHeader.id, return_msg->msg_code, return_msg->payload, &out_data_size, rsp, rsp_len);
                }else{
                    if(CHECK_KEYBOX_DEVID == return_msg->msg_code){
                        ALOGD("production check device id error, send keybox fail !\n");
                        char * err_result = "production check device id error!\n";
                        out_data_size = strlen(err_result);
                        organize_rsp(commandHeader.id, CHECK_KEYBOX_DEVID, err_result, &out_data_size, rsp, rsp_len);
                        result = PROD_OK;//return OK for PC tools to check 0x5B5B
                        break;
                    }
                    ALOGD("production CA send keybox fail !\n");
                    organize_rsp(commandHeader.id, return_msg->msg_code, NULL, &out_data_size, rsp, rsp_len);
                    break;
                }
            }else{
                ALOGD("production CA has written keybox !\n");
                organize_rsp(commandHeader.id, HAS_WRITE_KEYBOX, NULL, &out_data_size, rsp, rsp_len);
                break;
            }
        }else{
            ALOGD("production CA command_check_keybox fail before write keybox\n");
            organize_rsp(commandHeader.id, return_msg->msg_code, NULL, &out_data_size, rsp, rsp_len);
        }
        break;
    case CMD_SEND_WIDEVINE://send widevine keybox
        ALOGD("production CA command_send_widevine,data_len=%d\n",data_len);
        /*get from PC widevine keybox CRC*/
        crc_value = (unsigned short*)(command_data+data_len - KEYBOX_CHECKSUM_LENGTH);
        /*cal widevine keybox CRC*/
        temp_crc_value = crc16(temp_crc_value, (unsigned char *)command_data, (data_len - KEYBOX_CHECKSUM_LENGTH));
        ALOGD("%s keybox CRC by pass is %d, by cal is:%d\n", __FUNCTION__,*crc_value,temp_crc_value);
        if (*crc_value != temp_crc_value) {
            ALOGD("%s cmp keybox CRC value Error\n", __FUNCTION__);
            out_data_size = 0;
            organize_rsp(commandHeader.id, PROD_ERROR_SEND_WIDEVINE, NULL, &out_data_size, rsp, rsp_len);
            break;
        }
        ALOGD("%s cmp keybox CRC value success\n", __FUNCTION__);
        data_len -= KEYBOX_CHECKSUM_LENGTH;
        while(data_len){
            if(trans_len > data_len)
                trans_len = data_len;
            ALOGD("command_send_widevine,trans_len=%d\n",trans_len);
            memset(out,0,sizeof(out));
            out_data_size = sizeof(production_message);
            result = trusty_production_call(PRODUCTION_SEND_WIDEVINE, command_data, trans_len, out, &out_data_size);
            data_len -= trans_len;
            command_data += trans_len;
            return_msg = (production_message*) out;
            if(result < 0){
                organize_rsp(commandHeader.id, return_msg->msg_code, NULL, &out_data_size, rsp, rsp_len);
                break;
            }
        }
        return_msg = (production_message*) out;
        if(result == PROD_OK){
            ALOGD("production CA send widevine keybox success !\n");
            organize_rsp(commandHeader.id, return_msg->msg_code, return_msg->payload, &out_data_size, rsp, rsp_len);
        }else{
            ALOGD("production CA send widevine keybox fail !\n");
            organize_rsp(commandHeader.id, return_msg->msg_code, NULL, &out_data_size, rsp, rsp_len);
        }
        break;
    case CMD_INIT_STORAGE:
        ALOGD("production CA CMD_INIT_STORAGE\n");
        int init_storage = 0;
        if (0 == is_wr_rpmb_key()) {
            ALOGD("rpmb key hasn't been written!\n");
            result = PROD_ERROR_INIT_STORAGE;
            organize_rsp(commandHeader.id, init_storage, NULL, &out_data_size, rsp, rsp_len);
            break;
        }
        if(run_storageproxyd()){
            ALOGD("production start storageproxyd error !\n");
            result = PROD_ERROR_INIT_STORAGE;
            organize_rsp(commandHeader.id, init_storage, NULL, &out_data_size, rsp, rsp_len);
            break;
        }
        ALOGD("production start storageproxyd success !\n");
        init_storage = 1;
        organize_rsp(commandHeader.id, init_storage, NULL, &out_data_size, rsp, rsp_len);
        break;
    case CMD_CHECK_KEYBOX:
        ALOGD("production CA CMD_CHECK_KEYBOX\n");
        if (0 == is_wr_rpmb_key()) {
            ALOGD("rpmb key hasn't been written!\n");
            result = PROD_ERROR_INIT_STORAGE;
            organize_rsp(commandHeader.id, keybox_enable, NULL, &out_data_size, rsp, rsp_len);
            break;
        }
        result = trusty_production_call(PRODUCTION_CHECK_KEYBOX, command_data, data_len, out, &out_data_size);
        return_msg = (production_message*) out;
        if(result == PROD_OK){
            ALOGD("production CA command_check_keybox success,return_msg->payload[0]: %d\n", return_msg->payload[0]);
            if(return_msg->payload[0] == 1)
                keybox_enable = 1;
            organize_rsp(commandHeader.id, keybox_enable, NULL, &out_data_size, rsp, rsp_len);
        }else{
            ALOGD("production CA command_check_keybox fail\n");
            organize_rsp(commandHeader.id, keybox_enable, NULL, &out_data_size, rsp, rsp_len);
        }
        break;
    case CMD_CHECK_WIDEVINE:
        ALOGD("production CA CMD_CHECK_WIDEVINE\n");
        int widevine_enable = 0;
        result = trusty_production_call(PRODUCTION_CHECK_WIDEVINE, command_data, data_len, out, &out_data_size);
        return_msg = (production_message*) out;
        if(result == PROD_OK){
            ALOGD("production CA command_check_widevine success,return_msg->payload[0]: %d\n", return_msg->payload[0]);
            if(return_msg->payload[0] == 1)
                widevine_enable = 1;
            organize_rsp(commandHeader.id, widevine_enable, NULL, &out_data_size, rsp, rsp_len);
        }else{
            ALOGD("production CA command_check_widevine fail\n");
            organize_rsp(commandHeader.id, widevine_enable, NULL, &out_data_size, rsp, rsp_len);
        }
        break;
    case CMD_IFAA_SET_RSA:
        ALOGD("production CA CMD_IFAA_SET_RSA\n");
        result = trusty_production_call(PRODUCTION_SECURE_IFAA, command_data, data_len, out, &out_data_size);
        return_msg = (production_message*) out;
        organize_rsp(commandHeader.id, return_msg->msg_code, NULL, &out_data_size, rsp, rsp_len);
        break;
    case CMD_SOTER_ATTK_OPS:
        ALOGD("production CA CMD_SOTER_ATTK_OPS\n");
        tee_out = (uint8_t *) malloc(PRODUCTION_SOTER_MAX_TA_RETURN_BUFFER);
        tmp_out = (uint8_t *) malloc(PRODUCTION_SOTER_MAX_TA_RETURN_BUFFER);
        memset(tee_out, 0, PRODUCTION_SOTER_MAX_TA_RETURN_BUFFER);
        memset(tmp_out, 0, PRODUCTION_SOTER_MAX_TA_RETURN_BUFFER);

        char pro_platform[PROPERTY_VALUE_MAX] = {'\0'};
        property_get("ro.board.platform", pro_platform, "unknown brand");
        ALOGD("ro.board.platform=%s", pro_platform);
        command_data = pro_platform + CHIP_CODE_OFFSET;
        data_len = strlen(pro_platform) - CHIP_CODE_OFFSET;
        if (data_len > 8) {
            data_len = 8; // max length is 8, truncate if exceed
        }
        ALOGD("command_data=%s(%d)", command_data, data_len);
        trusty_production_call(PRODUCTION_SECURE_SOTER, command_data, data_len, tee_out, &ta_return_size);
        return_msg = (production_message*) tee_out;
        ALOGD("CMD_SOTER_ATTK_OPS result: %d %d %d\n", result, return_msg->msg_code, ta_return_size);

        //set dev_info`s item value
        memset(&dev_info, 0, sizeof(soter_dev_info_t));
        dev_info.nVersion = PRODUCTION_SOTER_VERSION;
        dev_info.nSecLevel = PRODUCTION_SOTER_SEC_LEVEL;
        property_get("ro.product.brand", brand_value, "unknown brand");
        property_get("ro.product.model", model_value, "unknown model");
        if(strlen(brand_value) < PRODUCTION_SOTER_MAX_DEV_INFO_ITEM_LENGTH
                && strlen(model_value) < PRODUCTION_SOTER_MAX_DEV_INFO_ITEM_LENGTH) {
            strcpy(dev_info.szBrand,brand_value);
            strcpy(dev_info.szModel,model_value);
        }
        memcpy(dev_info.szDeviceID, return_msg->payload, PRODUCTION_SOTER_DEV_ID_LENGTH);

        //add message head
        out_data_size = 0;
        memcpy(tmp_out, tee_out, sizeof(production_message));
        out_data_size += sizeof(production_message);
        //add dev_info
        memcpy(tmp_out+out_data_size, &dev_info, sizeof(soter_dev_info_t));
        out_data_size += sizeof(soter_dev_info_t);
        //add attk_info
        memcpy(tmp_out+out_data_size, return_msg->payload+PRODUCTION_SOTER_DEV_ID_LENGTH, ta_return_size-PRODUCTION_SOTER_DEV_ID_LENGTH);
        out_data_size += ta_return_size - PRODUCTION_SOTER_DEV_ID_LENGTH;
        ALOGE("%u, %u, %s, %s, %s, %s, %s\n", dev_info.nVersion, dev_info.nSecLevel, dev_info.szBrand,
                dev_info.szModel, dev_info.szBatch, dev_info.szDeviceID, ((production_message*)tee_out)->payload+32);

        return_msg = (production_message*) tmp_out;
        organize_rsp(commandHeader.id, return_msg->msg_code, return_msg->payload, &out_data_size, rsp, rsp_len);

        free(tee_out);
        free(tmp_out);
        break;
    default:
        ALOGD("command is not supported\n");
        result = PROD_ERROR_UNKNOW;
        break;
    }
    trusty_production_disconnect();
    return result;
}

// add for soter checkX
int eng_diag_soter_check(char *buf, int len, char *rsp, int *rsplen)
{
    int rc = -1, result = -1;
    uint8_t out[32] = {0};
    uint32_t out_size = 32;
    production_message *return_msg;

    ALOGD("%s SOTER checkX enter.\n", __func__);
    // check rpmb_key and storageproxyd first
    if (0 == is_wr_rpmb_key()) {
        ALOGE("%s: rpmb key hasn't been written!\n", __func__);
        result = -PROD_ERROR_INIT_STORAGE;
        goto err;
    }
    if (run_storageproxyd()) {
        ALOGD("%s: start storageproxyd error!\n");
        result = -PROD_ERROR_INIT_STORAGE;
        goto err;
    }

    rc = trusty_production_connect();
    if (rc < 0) {
        ALOGE("trusty_production_connect failed with ret = %d\n", rc);
        result = -PROD_ERROR_UNKNOW;
        goto err;
    }

    rc = trusty_production_call(PRODUCTION_CHECK_SOTER, buf, len, out, &out_size);
    if (rc < 0) {
        ALOGE("trusty_production_call failed with rc = %d\n", rc);
        result = -PROD_ERROR_UNKNOW;
        goto err_close;
    }
    *((int *) rsp) = *((int *)(((production_message *) out)->payload)) == 0 ? 1 : -1;
    *rsplen = sizeof(int);
    result = PROD_OK;

err_close:
    trusty_production_disconnect();
err:
    ALOGD("%s exit, result=%d\n", __func__, result);
    return result;
}

