#include <trusty/tipc.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <linux/input.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <unistd.h>

#include "serializer.h"
#include "tuimon_ipc.h"


#define T_BUF_SIZE  20
#define R_BUF_SIZE  20


static const int TUI_QUIT_KEY = 116; // key PWR. see gpio_key.h

static int session_lock = 0;
int time_left = 0xffff;


__BEGIN_DECLS
int ev_get(struct input_event* ev, int wait_ms);
int ev_init(void);
void ev_exit(void);
__END_DECLS


////////////////////////////////////////////////////////////////////////////////
int send_key_to_ta(int state, int code)
{
    int rc = 0;

    if (session_lock == 1) {
        return -1;
    }

    session_lock = 1;

    uint32_t cmd = TUIMON_KEY_TRANS;
    uint8_t recv_buf[R_BUF_SIZE];
    uint32_t response_size = R_BUF_SIZE;
    uint8_t send_buf[T_BUF_SIZE];
    uint32_t request_size = T_BUF_SIZE;

    memset(send_buf, 0, sizeof(send_buf));
    memset(recv_buf, 0, sizeof(recv_buf));

    // keycode first
    i2a(send_buf, request_size, 0, code, sizeof(code));
    // state then
    i2a(send_buf, request_size, sizeof(code), state, sizeof(state));

    rc = trusty_tuimon_call(cmd, send_buf, request_size, recv_buf, &response_size);

    if (rc >= 0) {
        // TODO:
    }
    else {
        printf("trusty_tuimon_call error: %d\n", rc);
    }

    session_lock = 0;

    return rc;
}


void* input_thread(void* write_fd)
{
    (void)write_fd;//remove compiling warning
    int ret = 0;
    struct input_event ev;

    while (1) {
        ret = ev_get(&ev,  time_left);

        if (ev.type == EV_KEY) {
            printf("input_thread - ret:%d,  ev.type:%d,  ev.code:%d,  ev.value:%d\n",  ret,  ev.type,  ev.code,
                   ev.value);
            send_key_to_ta(ev.value, ev.code);

#if 0

            // for debug
            if (ev.code == TUI_QUIT_KEY && ev.value == 0) {
                printf("captured TUI_QUIT_KEY...\n");
            }

#endif
        }
    }

    return NULL;
}



void key_receiver_stop(void)
{
    ev_exit();
}


int worker_create()
{
    int rc = 0;
    pthread_t key_t;

    if (ev_init() != 0) {
        printf("thread: ev_init() failed!\n");
        return -1;
    }

    rc = pthread_create(&key_t,  NULL,  input_thread,  NULL);

    if (rc) {
        printf("thread: input_thread creat failed!\n");
        return -2;
    }

    printf("thread:input_thread creat OK\n");

    return rc;
}


int key_receiver_start(void)
{
    int rc = 0;

    rc = trusty_tuimon_connect();

    if (rc < 0) {
        printf("Error connect to tui monitor ta: %d\n", rc);
        return -1;
    }

    rc = worker_create();

    if (rc < 0) {
        printf("worker create failed: %d\n", rc);
        trusty_tuimon_disconnect();
        key_receiver_stop();
        return -2;
    }

    return rc;
}

