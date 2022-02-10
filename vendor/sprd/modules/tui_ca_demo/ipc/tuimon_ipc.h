#ifndef TUIMONITOR_IPC_H
#define TUIMONITOR_IPC_H

#include <sys/types.h>


#define TRUSTY_DEVICE "/dev/trusty-ipc-dev0"
#define TUI_MONITOR_PORT  "com.android.trusty.tuimonitor"

#define TRAN_BUF_SIZE  256
#define RESP_BUF_SIZE  256


enum tuimonitor_command {
    TUIMON_REQ_SHIFT = 1,
    TUIMON_RESP_BIT  = 1,

    TUIMON_CANCEL_TUI = (0 << TUIMON_REQ_SHIFT),
    TUIMON_KEY_TRANS = (1 << TUIMON_REQ_SHIFT),
    TUIMON_SEC_KEY_REG = (2 << TUIMON_REQ_SHIFT),
    TUIMON_SEC_DISP_REG = (3 << TUIMON_REQ_SHIFT),
    TUIMON_SEC_TP_REG = (4 << TUIMON_REQ_SHIFT),
};

typedef struct {
    uint32_t cmd;
    uint8_t payload[0];
} tuimonitor_message;


int trusty_tuimon_connect(void);
int trusty_tuimon_call(uint32_t cmd, void* in, uint32_t in_size, uint8_t* out, uint32_t* out_size);
void trusty_tuimon_disconnect(void);



#endif //TUIMONITOR_IPC_H

