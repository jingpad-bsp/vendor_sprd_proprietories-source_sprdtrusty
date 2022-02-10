#include "trusty_production_pubefuse.h"
#include "production_ipc.h"


#define LOG_TAG "ProductionReadPubefuse"

extern int production_modules_load(struct list_head *head );

static int TEE_pub_efuse_ops(char * at_cmd, int ops, int block, int value, char *rsp, int* rsplen) {
    //ALOGD("Enter %s, at_cmd is %s\n", __func__, at_cmd);
    printf("Enter %s, at_cmd is %s\n", __func__, at_cmd);

    //char * at_cmd[20];
    int at_find_flg = 0;
    int result = 0;
    production_pubefuse_modules *modules_list = NULL;
    struct list_head *list_find;

    list_for_each(list_find,&production_head){
        printf("production find at cmd %s\n",at_cmd);
        modules_list = list_entry(list_find, production_pubefuse_modules, node);
        if(!strncmp(modules_list->callback.at_cmd, at_cmd, (size_t)strlen(at_cmd))){
            printf("production find at cmd %s\n",at_cmd);
            at_find_flg = 1;
            switch(ops){
                case CMD_GET_EFUSEUID:
                    printf("production get uid \n");
                    result = modules_list->callback.production_pubefuse_func(CMD_GET_EFUSEUID, block, value, rsp, rsplen);
                    printf("%s,efuse_uid_read_dymic = %s, result = %x\n", __FUNCTION__, rsp, result);
                    break;

                case CMD_SET_BLOCK:
                    printf("production write efuse block \n");
                    result = modules_list->callback.production_pubefuse_func(CMD_SET_BLOCK, block, value, rsp, rsplen);
                    printf("%s,efuse block write = %s, result = %x\n", __FUNCTION__, rsp, result);
                    break;

                case CMD_GET_BLOCK:
                    printf("production read efuse block \n");
                    result = modules_list->callback.production_pubefuse_func(CMD_GET_BLOCK, block, value, rsp, rsplen);
                    printf("%s,efuse block read = %s, result = %x\n", __FUNCTION__, rsp, result);
                    break;

                case CMD_ENABLE_SECURE:
                    printf("production enable secure \n");
                    result = modules_list->callback.production_pubefuse_func(CMD_ENABLE_SECURE, 0, 0, NULL, NULL);
                    printf("%s,production enable secure result = %x\n", __FUNCTION__, result);
                    break;

                case CMD_CHECK_SECURE_ENABLE:
                    printf("production check enable secure \n");
                    result = modules_list->callback.production_pubefuse_func(CMD_CHECK_SECURE_ENABLE, 0, 0, NULL, NULL);
                    printf("%s,production check enable secure, result = %x\n", __FUNCTION__, result);
                    break;

                case CMD_DISABLE_PTEST:
                    printf("production disable ptest \n");
                    result = modules_list->callback.production_pubefuse_func(CMD_DISABLE_PTEST, 0, 0, NULL, NULL);
                    printf("%s,production disable ptest, result = %x\n", __FUNCTION__, result);
                    break;

                default:
                    break;

            }
            break;
        }
    }

    if (!at_find_flg){
        return 0;
    }

    return result;
}

static int production_uid_read(char* uid, uint32_t* rsp_len){
    printf("%s enter \n", __FUNCTION__);
    char* pro_cmd = "AT+PRODUCTIONPUBEFUSE";
    char rsp[70] = {'\0'};
    //unsigned char uid_buf[70] = {0};
    int result = 0;
    result = TEE_pub_efuse_ops(pro_cmd, CMD_GET_EFUSEUID, 0, 0, rsp, rsp_len);
    if(result != 0){
        printf("read uid error: %d\n",result);
        return result;
    }
    sprintf(uid,rsp,*rsp_len);	//copy string to uid
    *rsp_len = strlen(rsp);
    printf("%s,efuse_uid_read_dymic = %s, len:%d\n", __FUNCTION__, uid, *rsp_len);
    return result;
}

static int production_efuse_block_read(int block, uint32_t *read_value, uint32_t* rsp_len){
    printf("%s enter \n", __FUNCTION__);
    char* pro_cmd = "AT+PRODUCTIONPUBEFUSE";
    char rsp[50] = {'\0'};
    uint32_t value1 = 0;
    uint32_t value2 = 0;
    unsigned char uid_buf[10] = {0};
    int result = 0;

    result = TEE_pub_efuse_ops(pro_cmd, CMD_GET_BLOCK, block, 0, rsp, rsp_len);
    if(result != 0){
    printf("read first block error: %d\n",result);
    return result;
    }
    sprintf(uid_buf,rsp,*rsp_len);	//copy string to uid_buf
    value1 = (unsigned int)(strtoul(rsp, 0, 16));
    *rsp_len = strlen(rsp);
    printf("%s,read efuse value1 = 0X%08x(%s), len:%d\n", __FUNCTION__, value1, uid_buf, *rsp_len);
    result = TEE_pub_efuse_ops(pro_cmd, CMD_GET_BLOCK, block, 0, rsp, rsp_len);
    if(result != 0){
        printf("read second block error: %d\n",result);
        return result;
    }
    sprintf(uid_buf,rsp,*rsp_len);	//copy string to uid_buf
    value2 = (unsigned int)(strtoul(rsp, 0, 16));
    *rsp_len = strlen(rsp);
    printf("%s,read efuse value2 = 0X%08x(%s), len:%d\n", __FUNCTION__, value2, uid_buf, *rsp_len);

    *read_value = value1 | value2;
    printf("%s,read efuse values 0X%08x\n", __FUNCTION__, *read_value);
    return result;

}

static int production_efuse_block_write(int block, uint32_t write_value, uint32_t* rsp_len){
    printf("%s enter \n", __FUNCTION__);
    char* pro_cmd = "AT+PRODUCTIONPUBEFUSE";
    char rsp[50] = {'\0'};
    int result = 0;

    result = TEE_pub_efuse_ops(pro_cmd, CMD_SET_BLOCK, block, write_value, rsp, rsp_len);
    if(result != 0){
        printf("write efuse block error: %d\n",result);
        return result;
    }
    #if 1
    uint32_t value1 = 0;
    uint32_t value2 = 0;
    uint32_t block_value = 0;
    unsigned char uid_buf[10] = {0};
    result = TEE_pub_efuse_ops(pro_cmd, CMD_GET_BLOCK, block * 2, 0, rsp, rsp_len);
    if(result != 0){
        printf("read first block error: %d\n",result);
        return result;
    }
    sprintf(uid_buf,rsp,*rsp_len);	//copy string to uid_buf
    value1 = (unsigned int)(strtoul(rsp, 0, 16));
    *rsp_len = strlen(rsp);
    printf("%s,read efuse value1 = 0X%08x(%s), len:%d\n", __FUNCTION__, value1, uid_buf, *rsp_len);
    result = TEE_pub_efuse_ops(pro_cmd, CMD_GET_BLOCK, block * 2 + 1, 0, rsp, rsp_len);
    if(result != 0){
        printf("read second block error: %d\n",result);
        return result;
    }
    sprintf(uid_buf,rsp,*rsp_len);	//copy string to uid_buf
    value2 = (unsigned int)(strtoul(rsp, 0, 16));
    *rsp_len = strlen(rsp);
    printf("%s,read efuse value2 = 0X%08x(%s), len:%d\n", __FUNCTION__, value2, uid_buf, *rsp_len);

    block_value = value1 | value2;
    printf("%s,read efuse values 0X%08x\n", __FUNCTION__, block_value);

    #endif
    return result;
}

static int production_efuse_enable_secure(void){
    printf("%s enter \n", __FUNCTION__);
    char* pro_cmd = "AT+PRODUCTIONPUBEFUSE";
    int result = 0;

    result = TEE_pub_efuse_ops(pro_cmd, CMD_ENABLE_SECURE, 0, 0, NULL, NULL);

    return result;

}

/*
* enable: 1
*disable :0 & others
*/
static int production_efuse_check_secure_enable(void){
    printf("%s enter \n", __FUNCTION__);
    char* pro_cmd = "AT+PRODUCTIONPUBEFUSE";
    int result = 0;

    result = TEE_pub_efuse_ops(pro_cmd, CMD_CHECK_SECURE_ENABLE, 0, 0, NULL, NULL);

    return result;

}

static int production_efuse_disable_ptest(void){
    printf("%s enter \n", __FUNCTION__);
    char* pro_cmd = "AT+PRODUCTIONPUBEFUSE";
    int result = 0;

    result = TEE_pub_efuse_ops(pro_cmd, CMD_DISABLE_PTEST, 0, 0, NULL, NULL);

    return result;
}


int production_diag_user_handle(uint32_t cmd, uint32_t block, uint32_t write_value, uint32_t* read_value, char *rsp, uint32_t* rsp_len){
    printf("%s enter ,cmd: %d\n", __FUNCTION__, cmd);

    int result = 1;
    int find_file = 0;

    find_file = production_modules_load(&production_head);
    if(NO_FILE_FOUND == find_file){
        printf("not found file: %d\n",find_file);
        return NO_FILE_FOUND;
    }
	printf("find pub efuse cmd: 0x%x\n", cmd);
    switch(cmd){
        case CMD_GET_EFUSEUID:
            result = production_uid_read(rsp, rsp_len);
            break;

        case CMD_SET_BLOCK:
            result = production_efuse_block_write(block, write_value, rsp_len);
            break;

        case CMD_GET_BLOCK:
            result = production_efuse_block_read(block, read_value, rsp_len);
            break;

        case CMD_ENABLE_SECURE:
            result = production_efuse_enable_secure();
            break;

        case CMD_CHECK_SECURE_ENABLE:
            result = production_efuse_check_secure_enable();
            break;

        case CMD_DISABLE_PTEST:
            result = production_efuse_disable_ptest();
            break;
        }

    return result;
}


