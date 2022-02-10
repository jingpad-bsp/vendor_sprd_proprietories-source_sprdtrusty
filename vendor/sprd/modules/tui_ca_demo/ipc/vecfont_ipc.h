#ifndef __VECFONT_IPC_H__
#define __VECFONT_IPC_H__


enum vecft_command {
    VECFT_TA_REQ_SHIFT = 1,
    VECFT_TA_RESP_BIT  = 1,
    VECFT_TA_FONT_DATA_PREPARE = (0 << VECFT_TA_REQ_SHIFT),
};


/**
 * vecft_message - Serial header for communicating with ta server
 * @cmd: the command, one of xx, xx. Payload must be a serialized
 *       buffer of the corresponding request object.
 * @payload: start of the serialized command specific payload
 */
struct vecft_message {
    uint32_t cmd;
    uint8_t payload[0];
};


typedef struct {
    int handle;
    char portStr[100];
} vecft_session;

vecft_session* trusty_vecfont_ta_connect(const char* port);
int trusty_vecfont_ta_call(vecft_session* s, uint32_t cmd, uint8_t* in, uint32_t in_size,
                           uint8_t* out, uint32_t* out_size);
void trusty_vecfont_ta_disconnect(vecft_session* session);


#endif //__VECFONT_IPC_H__
