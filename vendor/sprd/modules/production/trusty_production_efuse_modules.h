#ifndef __TRUSTY_PRODUCTION_EFUSE_MODULES_H__
#define __TRUSTY_PRODUCTION_EFUSE_MODULES_H__

#include "trusty_production_list.h"

#ifndef byte
typedef unsigned char  byte;
#endif

#ifndef uchar
typedef unsigned char  uchar;
#endif

#ifndef uint
typedef unsigned int   uint;
#endif // uint

#ifndef ushort
typedef unsigned short ushort;
#endif

#ifndef R_OK
#define R_OK	4
#define W_OK	2
#define X_OK	1
#define F_OK	0
#endif

#define NO_FILE_FOUND (-404)

struct production_pubefuse_callback{
    unsigned short diag_ap_cmd;
    char at_cmd[32];
    int (*production_pubefuse_func)(int ops, int block, int value, char *rsp, int* rsplen);
    int (*production_pubefuse_linuxcmd_func)(char *req, char *rsp);
	int (*production_pubefuse_rdwr_func)(char *req, int ops, int block, char *value);
};


typedef struct production_pubefuse_modules_info
{
    struct  list_head node;
    struct  production_pubefuse_callback callback;
}production_pubefuse_modules;

struct list_head production_head;


#endif
