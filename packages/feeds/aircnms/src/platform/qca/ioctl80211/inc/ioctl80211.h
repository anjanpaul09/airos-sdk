#ifndef IOCTL80211_H_INCLUDED
#define IOCTL80211_H_INCLUDED

#include <sys/socket.h>
#include <linux/types.h>
#include <linux/wireless.h>
#include <pthread.h>

#ifdef CONFIG_PLATFORM_QCA_QSDK110
#include <cfg80211_nlwrapper_api.h>
#endif

#include "ioctl80211_api.h"

static inline
int ioctl80211_get_iwp(struct iw_event *iwe, struct iw_point *iwp)
{
    struct {
        __u16 length;
        __u16 flags;
        char payload[0];
    } *ptr;

    ptr = (void *)iwe + IW_EV_LCP_LEN;
    iwp->pointer = ptr->payload;
    iwp->length = ptr->length;
    iwp->flags = ptr->flags;

    if (iwp->length > (iwe->len - IW_EV_POINT_LEN)) {
        return (-1);
    }

    return (0);
}

#endif /* IOCTL80211_H_INCLUDED */
