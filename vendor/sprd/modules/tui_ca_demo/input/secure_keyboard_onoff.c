#include <fcntl.h>
#include <unistd.h>
#include <log/log.h>

#undef LOG_TAG
#define LOG_TAG "sec_key_onoff"


const char* const PWR_KEY_NODE = "/sys/devices/platform/gpio-keys/tui_mode";
const char* const KB_DEVICE_NODE_ON = "/sys/devices/platform/soc/soc:aon/40250000.keypad/enableirq";
const char* const KB_DEVICE_NODE_OFF =
    "/sys/devices/platform/soc/soc:aon/40250000.keypad/disableirq";


/********************************
**  notify GPIO KEYS DRIVER that TUI is gonna on/off,
**  driver will drop PWR key according TUI specification
********************************/
int notify_pwr_key(int tuiOn)
{
    int fd = 0;
    int rc = 0;

    fd = open(PWR_KEY_NODE, O_WRONLY);

    if (fd > 0) {
        const char value = !!tuiOn ? '1' : '0';

        if (write(fd, &value, 1) != 1) {
            rc = -1;
        }

        close(fd);
    }
    else {
        rc = -2;
    }

    ALOGD("notify GPIO key driver that tui status:%d , fd: %d, rc: %d\n", tuiOn, fd, rc);

    return rc;
}



/********************************
**  this function set matrix keys irq not be received by REE.
**  for TUI, matrix keys should only be read by TEE driver.
********************************/
int secure_kb_switch(int on)
{
    int fd = 0;
    int rc = 0;

    const char value = '1';

    if (on) {
        fd = open(KB_DEVICE_NODE_OFF, O_WRONLY);
    }
    else {
        fd = open(KB_DEVICE_NODE_ON, O_WRONLY);
    }

    if (fd > 0) {
        if (write(fd, &value, 1) != 1) {
            rc = -1;
        }

        close(fd);
    }
    else {
        rc = -2;
    }

    ALOGD("secureKb Switch to %d....fd: %d , rc: %d\n", on, fd, rc);

    return rc;
}

