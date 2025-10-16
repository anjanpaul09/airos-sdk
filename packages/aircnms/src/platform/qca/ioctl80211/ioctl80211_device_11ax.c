#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>

#include "log.h"

#include "ioctl80211.h"
#include "ioctl80211_device.h"

#define MODULE_ID LOG_MODULE_ID_IOCTL
#define OSYNC_IOCTL_LIB 4

#include "osync_nl80211_11ax.h"
/******************************************************************************
 *                          DEVICE STATS
 *****************************************************************************/

/******************************************************************************
 *  PROTECTED definitions
 *****************************************************************************/

static
ioctl_status_t ioctl80211_device_temp_get(
        radio_entry_t              *radio_cfg,
        dpp_device_temp_t          *temp)
{
    char                            buf[128];
    int                             err;

    err = readcmd(buf, sizeof(buf), 0, "cat /sys/class/net/%s/thermal/temp",
                  radio_cfg->phy_name);
    if (err) {
        LOGW("%s: readcmd() failed: %d (%s)", radio_cfg->phy_name,
                errno, strerror(errno));
        return IOCTL_STATUS_ERROR;
    }

    LOG(TRACE, "Probed get_therm %x", atoi(buf));

    temp->type = radio_cfg->type;
    temp->value = atoi(buf);

    LOG(TRACE,
            "Parsed device %s temp %d",
            radio_get_name_from_type(temp->type),
            temp->value);
    return IOCTL_STATUS_OK;
}

static
ioctl_status_t ioctl80211_device_txchainmask_get(
        radio_entry_t              *radio_cfg,
        dpp_device_txchainmask_t   *txchainmask)
{
	return nl80211_device_txchainmask_get(radio_cfg, txchainmask);
}


/******************************************************************************
 *  PUBLIC definitions
 *****************************************************************************/

ioctl_status_t ioctl80211_device_temp_results_get(
        radio_entry_t              *radio_cfg,
        dpp_device_temp_t          *temp)
{
    ioctl_status_t                  status;

    status =
        ioctl80211_device_temp_get(
                radio_cfg,
                temp);
    if (IOCTL_STATUS_OK != status)
    {
        return IOCTL_STATUS_ERROR;
    }

    return IOCTL_STATUS_OK;
}

ioctl_status_t ioctl80211_device_txchainmask_results_get(
        radio_entry_t              *radio_cfg,
        dpp_device_txchainmask_t   *txchainmask)
{
    ioctl_status_t                  status;

    status =
        ioctl80211_device_txchainmask_get(
                radio_cfg,
                txchainmask);
    if (IOCTL_STATUS_OK != status)
    {
        return IOCTL_STATUS_ERROR;
    }

    return IOCTL_STATUS_OK;
}
