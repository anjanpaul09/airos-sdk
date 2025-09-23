#include <stdbool.h>
#include <stdio.h>
#include <errno.h>

#include "target.h"
#include "ioctl80211.h"

#define MODULE_ID LOG_MODULE_ID_TARGET


/******************************************************************************
 *  TARGET definitions
 *****************************************************************************/

struct ev_loop *target_mainloop;

bool target_init(target_init_opt_t opt, struct ev_loop *loop)
{
    switch (opt) {
        case TARGET_INIT_MGR_SM:
            if (ioctl80211_init(loop, true) != IOCTL_STATUS_OK) {
                return false;
            }
            break;
        case TARGET_INIT_MGR_BM:
#ifdef CONFIG_PLATFORM_QCA_QSDK
            if (ioctl80211_init(loop, false) != IOCTL_STATUS_OK) {
                return false;
            }
#endif
            break;
        default:
            break;
    }

    target_mainloop = loop;
    return true;
}

bool target_close(target_init_opt_t opt, struct ev_loop *loop)
{
    return true;
}
