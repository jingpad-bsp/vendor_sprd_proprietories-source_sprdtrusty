#include <log/log.h>
#include <vendor/sprd/hardware/tuistate/1.0/ITuistate.h>

using android::sp;
using vendor::sprd::hardware::tuistate::V1_0::ITuistate;


extern "C" int tuiStateNotify(bool tuion)
{
    sp<ITuistate> tuiState = ITuistate::getService();

    if (tuiState == nullptr) {
        ALOGD("hidl service - ITuistate not found!\n");
        return -1;
    }

    tuiState->notify(tuion);

    return 0;
}

