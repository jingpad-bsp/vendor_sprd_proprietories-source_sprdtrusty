#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tuica.h"
#include "tuica_ipc.h"


const uint32_t SEND_BUF_SIZE = 512;
const uint32_t RECV_BUF_SIZE = 512;


extern int secure_key_config(void);
extern int secure_tp_config(void);
extern int tui_cancel(void);
extern int tui_launch(void* in, uint32_t in_size, uint8_t* out, uint32_t out_size);


typedef enum {
    //GP dialogs
    DLG_ID_START = 0,
    DLG_ID_GP_MSG_INFO = 0,
    DLG_ID_GP_MSG_VALIDATION_1,
    DLG_ID_GP_MSG_VALIDATION_2,
    DLG_ID_GP_MSG_VALIDATION_3,
    DLG_ID_GP_MSG_VALIDATION_4,
    DLG_ID_GP_PIN_ENTRY,
    DLG_ID_GP_LOGIN_ENTRY,

    DLG_ID_GP_MAX,

    //private dialogs add here
    DLG_ID_SECURE_IND_SET,
    DLG_ID_PIN_ENTRY,

    DLG_ID_MAX
} TUIDialogId;

typedef struct {
    TUIDialogId dlgid;
    const char* str;
} LableTxtOfDlg;


LableTxtOfDlg gTypeDlg[DLG_ID_MAX] = {
    { DLG_ID_GP_MSG_INFO,                   "msg" },
    { DLG_ID_GP_MSG_VALIDATION_1,   "msgval1" },
    { DLG_ID_GP_MSG_VALIDATION_2,   "msgval2" },
    { DLG_ID_GP_MSG_VALIDATION_3,   "msgval3" },
    { DLG_ID_GP_MSG_VALIDATION_4,   "msgval4" },
    { DLG_ID_GP_PIN_ENTRY,                  "gppin" },
    { DLG_ID_GP_LOGIN_ENTRY,            "login" },

    { DLG_ID_GP_MAX,            "**" },

    { DLG_ID_SECURE_IND_SET,            "indset" },
    { DLG_ID_PIN_ENTRY,                     "pin" }
};


enum {
    TZ_REQUEST_TUI = 0,
    TZ_CANCEL_TUI,
    TZ_REGIST_SEC_KEY,
    TZ_REGIST_SEC_TP,

    CMD_MAX
};

typedef struct {
    int cmd;
    const char* str_cmd;
} cmdNode;


cmdNode gCmdList[CMD_MAX] = {
    { TZ_REQUEST_TUI,   "display" }
    , { TZ_CANCEL_TUI,   "cancel"}
    , { TZ_REGIST_SEC_KEY,    "seckeyconf" }
    , { TZ_REGIST_SEC_TP,    "sectpconf" }
};


int get_cmd(int argc, char* argv[])
{
    int rc = 0;//default

    if (argc > 1) {
        for (int i = 0; i < CMD_MAX; i++) {
            if (strcmp(argv[1], gCmdList[i].str_cmd) == 0) {
                rc = gCmdList[i].cmd;
                break;
            }
        }
    }

    return rc;
}


int regist_secure_key_to_tee(void)
{
    return secure_key_config();
}

int regist_secure_tp_to_tee(void)
{
    return secure_tp_config();
}

int main(int argc, char* argv[])
{
    int rc = 0;

    int cmd = get_cmd(argc, argv);

    switch (cmd) {
        case TZ_REGIST_SEC_KEY: {
            rc = regist_secure_key_to_tee();
        }
        break;

        case TZ_REGIST_SEC_TP: {
            rc = regist_secure_tp_to_tee();
        }
        break;

        case TZ_REQUEST_TUI: {
            uint8_t recv_buf[RECV_BUF_SIZE];
            uint32_t response_size = RECV_BUF_SIZE;
            uint8_t send_buf[SEND_BUF_SIZE];
            uint32_t request_size = SEND_BUF_SIZE;

            send_buf[0] = 0xff;

            if (argc > 2) {
                for (int i = 0; i < DLG_ID_MAX; i++) {
                    printf("cmd request tui.  argv[%d] : %s\n", i, argv[i]);

                    if (0 == strcmp(argv[2], gTypeDlg[i].str)) {
                        send_buf[0] = (uint8_t)gTypeDlg[i].dlgid;
                        break;
                    }
                }

                if (argc == 3) {
                    send_buf[1] = (uint8_t)atoi(argv[2]);
                }
            }

            rc = tui_launch(send_buf, request_size, recv_buf, response_size);
        }
        break;

        case TZ_CANCEL_TUI: {
            printf("cmd tui cancel ... \n");
            rc = tui_cancel();
        }
        break;

        default:
            break;
    }

    printf("tui main exit ... %d\n", rc);
    return rc;

}

