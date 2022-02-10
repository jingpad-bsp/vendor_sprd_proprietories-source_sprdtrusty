#include "tuiwakelock.h"
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <powermanager/PowerManager.h>

#undef LOG_TAG
#define LOG_TAG "tuiWakeLock"
#include <utils/Log.h>


#ifndef CONDITION
#define CONDITION(cond) (__builtin_expect((cond) != 0, 0))
#endif


#ifndef LOG_ALWAYS_FATAL_IF
#define LOG_ALWAYS_FATAL_IF(cond, ...)                                         \
    ((CONDITION(cond))                                                         \
     ? ((void)android_printAssert(#cond, LOG_TAG, ##__VA_ARGS__))          \
     : (void)0)
#endif


#ifdef CHECK
#undef CHECK
#endif

#define CHECK(condition)                                \
    LOG_ALWAYS_FATAL_IF(                                \
            !(condition),                               \
            "%s : %d  %s",                                       \
            __FILE__, __LINE__, " CHECK(" #condition ") failed.")


namespace android
{

tuiWakeLock::tuiWakeLock() :
    mPowerManager(NULL),
    mWakeLockToken(NULL),
    mWakeLockCount(0),
    mDeathRecipient(new PMDeathRecipient(this)) {}

tuiWakeLock::~tuiWakeLock()
{
    if (mPowerManager != NULL) {
        sp<IBinder> binder = IInterface::asBinder(mPowerManager);
        binder->unlinkToDeath(mDeathRecipient);
    }

    clearPowerManager();
}

tuiWakeLock* tuiWakeLock::mWl = nullptr;
tuiWakeLock* tuiWakeLock::getInstance()
{
    if (mWl == nullptr) {
        mWl = new tuiWakeLock();
    }

    return mWl;
}


bool tuiWakeLock::acquire()
{
    ALOGD("acquire ... \n");

    if (mWakeLockCount == 0) {
        CHECK(mWakeLockToken == NULL);

        if (mPowerManager == NULL) {
            // use checkService() to avoid blocking if power service is not up yet
            sp<IBinder> binder = defaultServiceManager()->checkService(String16("power"));

            if (binder == NULL) {
                ALOGW("could not get the power manager service");
            }
            else {
                mPowerManager = interface_cast<IPowerManager>(binder);
                binder->linkToDeath(mDeathRecipient);
            }
        }

        if (mPowerManager != NULL) {
            sp<IBinder> binder = new BBinder();
            int64_t token = IPCThreadState::self()->clearCallingIdentity();
            ALOGD("power manager acquire ... \n");
            status_t status = mPowerManager->acquireWakeLock(
                                  0x1a,//OsProtoEnums.FULL_WAKE_LOCK,
                                  binder, String16("tuiWakeLock"), String16("tui"));

            IPCThreadState::self()->restoreCallingIdentity(token);

            if (status == NO_ERROR) {
                mWakeLockToken = binder;
                mWakeLockCount++;
                return true;
            }
        }
    }
    else {
        ALOGD("add a tui wl ref ... \n");
        mWakeLockCount++;
        return true;
    }

    return false;
}

void tuiWakeLock::release(bool force)
{
    ALOGD("release ... force?%d \n", force);

    if (mWakeLockCount == 0) {
        return;
    }

    if (force) {
        // Force wakelock release below by setting reference count to 1.
        mWakeLockCount = 1;
    }

    if (--mWakeLockCount == 0) {
        CHECK(mWakeLockToken != NULL);

        if (mPowerManager != NULL) {
            int64_t token = IPCThreadState::self()->clearCallingIdentity();
            ALOGD("power manager release ....\n");
            mPowerManager->releaseWakeLock(mWakeLockToken, 0 /* flags */);
            IPCThreadState::self()->restoreCallingIdentity(token);
        }

        mWakeLockToken.clear();
    }
}

void tuiWakeLock::clearPowerManager()
{
    ALOGD("clearPowerManager. going to release ... \n");
    release(true);
    mPowerManager.clear();
}

void tuiWakeLock::PMDeathRecipient::binderDied(const wp<IBinder> &who __unused)
{
    ALOGD("PMS binderDied ... \n");

    if (mWakeLock != NULL) {
        mWakeLock->clearPowerManager();
    }
}

}  // namespace android
