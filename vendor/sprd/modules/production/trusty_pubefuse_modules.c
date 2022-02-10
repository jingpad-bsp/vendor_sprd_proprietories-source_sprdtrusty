#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <dirent.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <cutils/log.h>


#include "trusty_production_efuse_modules.h"
//#include "sprd_pubefuse_api.h"


#ifdef LOG_TAG
#undef LOG_TAG
#endif

#define LOG_TAG "ProductionReadPubefuse"

#define MAX_LEN 50

typedef void (*REGISTER_FUNC)(struct production_pubefuse_callback *register_callback);

#ifdef PRO_ARCH_64
//because engpc can only access 32-bit lib,the /lib64/ just.for.production.producion_test_service---test
//static const char *production_modules_path = "/vendor/lib64/production";
static const char *production_modules_path = "/vendor/lib/production";
#else
static const char *production_modules_path = "/vendor/lib/production";
#endif

production_pubefuse_modules* get_production_modules(struct production_pubefuse_callback p)
{
    ALOGD("%s",__FUNCTION__);
    production_pubefuse_modules *modules = (production_pubefuse_modules*)malloc(sizeof(production_pubefuse_modules));
    if (modules == NULL)
    {
        ALOGD("%s malloc fail...",__FUNCTION__);
        return NULL;
    }
    memset(modules,0,sizeof(production_pubefuse_modules));
    modules->callback.diag_ap_cmd = p.diag_ap_cmd;
    sprintf(modules->callback.at_cmd, "%s", p.at_cmd);
    modules->callback.production_pubefuse_func = p.production_pubefuse_func;
    modules->callback.production_pubefuse_linuxcmd_func = p.production_pubefuse_linuxcmd_func;
	modules->callback.production_pubefuse_rdwr_func = p.production_pubefuse_rdwr_func;

    return modules;
}

int readFileList(const char *basePath, char f_name[][MAX_LEN])
{
    DIR *dir;
    struct dirent *ptr;
    int num = 0;
    ALOGD("%s",__FUNCTION__);

    if ((dir = opendir(basePath)) == NULL)
    {
        ALOGD("Open %s error...%s",basePath,dlerror());
        return 0;
    }

    while ((ptr = readdir(dir)) != NULL && num < MAX_LEN)
    {
        if(ptr->d_type == 8){    ///file
            ALOGD("d_name:%s/%s\n",basePath,ptr->d_name);
            //f_name[num] = ptr->d_name;
            if(strlen(ptr->d_name) < MAX_LEN){
                memcpy(f_name[num], ptr->d_name, strlen(ptr->d_name));
                f_name[num][strlen(ptr->d_name)] = '\0';
            }else{
                ALOGD("File name length overflow");
                return num;
            }
            num ++;
            ALOGD("d_name:%s\n",f_name[num-1]);
        }
    }
    closedir(dir);
    return num;
}


int production_modules_load(struct list_head *head )
{
    REGISTER_FUNC production_register_func = NULL;
    struct production_pubefuse_callback register_callback;
    char path[MAX_LEN]=" ";

    void *handler[MAX_LEN];
    char f_name[MAX_LEN][MAX_LEN];
    //char **p;
    int i = 0;
    //p = f_name;
    production_pubefuse_modules *modules;

    ALOGD("%s",__FUNCTION__);

    INIT_LIST_HEAD(head);
    int num = readFileList(production_modules_path,f_name);
    ALOGD("file num: %d\n",num);
    if(0 == num)
        return NO_FILE_FOUND;

    for (i = 0 ; i < num; i++) {
        snprintf(path, MAX_LEN, "%s/%s",
                        production_modules_path, "libpubefuseapi.so");
        ALOGD("find lib path: %s",path);

        if (access(path, R_OK) == 0){
            handler[i] = dlopen(path,RTLD_LAZY);
            if (handler[i] == NULL){
                ALOGD("%s dlopen fail! %s \n",path,dlerror());
            }else{
                production_register_func = (REGISTER_FUNC)dlsym(handler[i], "register_this_module");
                if(!production_register_func){
                    dlclose(handler[i]);
                    ALOGD("%s dlsym fail! %s\n",path,dlerror());
                    continue;
                }
                production_register_func(&register_callback);

                modules = get_production_modules(register_callback);
                if (modules == NULL){
                    continue;
                }
                list_add_tail(&modules->node, head);
            }
        }
    }
    return 0;
}
