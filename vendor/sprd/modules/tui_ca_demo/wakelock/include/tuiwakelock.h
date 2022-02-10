#ifndef TUI_WAKELOCK_H_
#define TUI_WAKELOCK_H_

#include <powermanager/IPowerManager.h>
#include <utils/RefBase.h>


#define DISALLOW_EVIL_CONSTRUCTORS(name) \
    name(const name &); \
    name &operator=(const name &)


namespace android
{

class tuiWakeLock : public RefBase
{

public:
    // returns true if wakelock was acquired
    bool acquire();
    void release(bool force = false);

    virtual ~tuiWakeLock();
    static tuiWakeLock* getInstance();

private:
    tuiWakeLock();
    sp<IPowerManager> mPowerManager;
    sp<IBinder>       mWakeLockToken;
    uint32_t          mWakeLockCount;
    static tuiWakeLock* mWl;

    class PMDeathRecipient : public IBinder::DeathRecipient
    {
    public:
        explicit PMDeathRecipient(tuiWakeLock* wakeLock) : mWakeLock(wakeLock) {}
        virtual ~PMDeathRecipient() {}

        // IBinder::DeathRecipient
        virtual void binderDied(const wp<IBinder> &who);

    private:
        PMDeathRecipient(const PMDeathRecipient &);
        PMDeathRecipient &operator= (const PMDeathRecipient &);

        tuiWakeLock* mWakeLock;
    };

    const sp<PMDeathRecipient> mDeathRecipient;

    void clearPowerManager();

    DISALLOW_EVIL_CONSTRUCTORS(tuiWakeLock);
};

}  // namespace android

#endif  // TUI_WAKELOCK_H_
