/*
 *  trusty_faceid_ipc.h
 *
 *  Copyright (C) 2018 Unisoc Inc.
 *  History:
 *      <Date> 2018/09/27
 *      <Name>
 *      Description
 */

#ifndef __TRUSTY_FACEID_IPC_H__
#define __TRUSTY_FACEID_IPC_H__
//__BEGIN_DECLS

int trusty_faceid_connect(void);
int trusty_faceid_call(uint32_t cmd, void *in, uint32_t in_size,
        uint8_t *out, uint32_t *out_size);
void trusty_faceid_disconnect(void);

//__END_DECLS
#endif
