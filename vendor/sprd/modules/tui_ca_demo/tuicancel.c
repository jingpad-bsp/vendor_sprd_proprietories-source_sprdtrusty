
#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include "tuimon_ipc.h"


void* cancel_tui_thread(void* write_fd)
{
    printf("cancel_tui_thread...\n");
    (void)write_fd;//remove compiling warning

    int rc = trusty_tuimon_connect();

    if (rc < 0) {
        printf("Error connect to tui monitor ta: %d\n", rc);
        return NULL;
    }

    uint32_t cmd = TUIMON_CANCEL_TUI;
    uint8_t recv_buf[RESP_BUF_SIZE];
    uint32_t response_size = RESP_BUF_SIZE;
    uint8_t send_buf[TRAN_BUF_SIZE];
    uint32_t request_size = TRAN_BUF_SIZE;

    memset(send_buf, 0, sizeof(send_buf));
    memset(recv_buf, 0, sizeof(recv_buf));

    send_buf[0] = 1;

    rc = trusty_tuimon_call(cmd, send_buf, request_size, recv_buf, &response_size);

    if (rc >= 0) {
        // TODO:
        printf("trusty_tuimon_call ... ok\n");
    }
    else {
        printf("trusty_tuimon_call error: %d\n", rc);
    }

    trusty_tuimon_disconnect();

    return NULL;
}


int tui_cancel(void)
{
    int rc = 0;
    pthread_t thread_t;

    rc = pthread_create(&thread_t,  NULL,  cancel_tui_thread,  NULL);

    if (rc) {
        printf("thread: tui_cancel_thread creat failed!\n");
        return -2;
    }

    printf("thread:tui_cancel_thread creat OK\n");
    pthread_join(thread_t, NULL);

    return rc;
}


