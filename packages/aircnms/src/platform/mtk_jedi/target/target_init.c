#include <stdbool.h>
#include <stdio.h>
#include <errno.h>

#include "target.h"
//#include "ioctljedi.h"
#include "../ioctljedi/inc/ioctljedi.h"

#define MODULE_ID LOG_MODULE_ID_TARGET


/******************************************************************************
 *  TARGET definitions
 *****************************************************************************/

struct ev_loop *target_mainloop;

bool target_init(target_init_opt_t opt, struct ev_loop *loop)
{
    switch (opt) {
        case TARGET_INIT_MGR_SM:
            if (ioctljedi_init(loop, true) != IOCTL_STATUS_OK) {
                return false;
            }
            break;
        default:
            break;
    }

    target_mainloop = loop;
    target_mainloop = loop;
    return true;
}

bool target_close(target_init_opt_t opt, struct ev_loop *loop)
{
    return true;
}
