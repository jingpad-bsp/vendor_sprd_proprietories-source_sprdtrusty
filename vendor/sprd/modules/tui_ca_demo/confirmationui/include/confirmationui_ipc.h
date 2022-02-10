__BEGIN_DECLS

#define TRUSTY_DEVICE_NAME "/dev/trusty-ipc-dev0"
#define CONFIRMATIONUI_PORT "com.android.trusty.confirmationui"
#define VECFONTLIB_PORT "com.android.trusty.vecfontlib"

enum confirmationui_command {
    CONFIRMATIONUI_TA_REQ_SHIFT = 1,
    CONFIRMATIONUI_TA_RESP_BIT  = 1,
    CONFIRMATIONUI_TA_LAUNCH    = (0 << CONFIRMATIONUI_TA_REQ_SHIFT),
};

typedef enum {
    ERROR_NONE = 0,
    ERROR_FIRST = 1,
    ERROR_UNKNOWN = 2,
} confirmationui_error_t;


/**
 * confirmationui_message - Serial header for communicating with ta server
 * @cmd: the command, one of xx, xx. Payload must be a serialized
 *       buffer of the corresponding request object.
 * @select: what user selected on confirmation ui dialog.ok or cancel?
 * @payload: start of the serialized command specific payload
 */
struct confirmationui_message {
    uint32_t cmd;
    uint32_t select;
    uint8_t payload[0];
};

int trusty_vectorfont_connect();
int trusty_confirmationui_connect();
int trusty_confirmationui_call(uint32_t cmd, uint8_t* in, uint32_t in_size, uint8_t* out,
                               uint32_t* out_size);
void trusty_confirmationui_disconnect();
void trusty_vectorfont_disconnect();

__END_DECLS
