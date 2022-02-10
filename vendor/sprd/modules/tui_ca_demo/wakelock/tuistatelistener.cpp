#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include "tuiwakelock.h"
#include <vendor/sprd/hardware/tuistate/1.0/ITuistate.h>
#include <vendor/sprd/hardware/tuistate/1.0/ITuiStateChangeCallback.h>

#undef LOG_TAG
#define LOG_TAG "tuiStateListener"
#include <log/log.h>


using android::hardware::Void;
using android::hardware::Return;
using android::sp;
using vendor::sprd::hardware::tuistate::V1_0::ITuistate;
using vendor::sprd::hardware::tuistate::V1_0::ITuiStateChangeCallback;


class stateChangedCallback: public ITuiStateChangeCallback
{
public:
    virtual ~stateChangedCallback();
    static stateChangedCallback* getInstance();
    Return<int32_t> stateChange(bool on);
    bool isTuiOn();

private:
    stateChangedCallback();
    bool mTuiState;
    static stateChangedCallback* mCallback;
};

stateChangedCallback::stateChangedCallback() : mTuiState(false) {}
stateChangedCallback::~stateChangedCallback() {}

stateChangedCallback* stateChangedCallback::mCallback = nullptr;
stateChangedCallback* stateChangedCallback::getInstance()
{
    if (mCallback == nullptr) {
        mCallback = new stateChangedCallback();
    }

    return mCallback;
}

bool stateChangedCallback::isTuiOn()
{
    return mTuiState;
}

Return<int32_t> stateChangedCallback::stateChange(bool on)
{
    ALOGD("stateChange . on?%d\n", on);
    mTuiState = on;
    raise(SIGUSR1);
    return int32_t {0};
}


static void sig_handle(int signum)
{
    if (signum == SIGUSR1) {
        android::tuiWakeLock* wl = android::tuiWakeLock::getInstance();
        stateChangedCallback* cb = stateChangedCallback::getInstance();
        bool tuion = cb->isTuiOn();
        ALOGD("sig_handle . tuion(%d)\n", tuion);

        if (tuion) {
            wl->acquire();
        }
        else {
            wl->release();
        }
    }
}


int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;//remove compiling warning

    sp<ITuistate> tuiStateListener = ITuistate::getService();

    if (tuiStateListener == nullptr) {
        ALOGE("hidl service - ITuistate not found!\n");
        return -1;
    }

    sp<android::tuiWakeLock> wl = android::tuiWakeLock::getInstance();
    sp<stateChangedCallback> cb = stateChangedCallback::getInstance();

    if (cb == nullptr) {
        ALOGE("init tui state change callback failed!\n");
        return -2;
    }

    tuiStateListener->listenTuiState(cb);

    signal(SIGUSR1, sig_handle);

    while (1) {
        pause();
    }

    return 0;
}

