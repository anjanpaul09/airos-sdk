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
    int32_t                         rc;
    struct iwreq                    request;

    memset (&request, 0, sizeof(request));

    rc = ioctl80211_get_priv_ioctl(radio_cfg->if_name, "get_therm", &request.u.mode);
    if (!rc) {
        LOG(WARNING, "failed to get temperature: ioctl not found");
        return IOCTL_STATUS_ERROR;
    }

    LOG(TRACE, "Probed get_therm ioctl %x", request.u.mode);

    rc =
        ioctl80211_request_send(
                ioctl80211_fd_get(),
                radio_cfg->if_name,
                IEEE80211_IOCTL_GETPARAM,
                &request);
    if (0 > rc)
    {
        LOG(ERR,
                "Parsing device stats (Failed to retrieve %s temp %s '%s')",
                radio_get_name_from_type(radio_cfg->type),
                radio_cfg->if_name,
                strerror(errno));
        return IOCTL_STATUS_ERROR;
    }

    temp->type = radio_cfg->type;
    temp->value = request.u.mode;

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
    int32_t                         rc;
    struct iwreq                    request;

    memset (&request, 0, sizeof(request));

    rc = ioctl80211_get_priv_ioctl(radio_cfg->phy_name, "get_txchainsoft", &request.u.mode);
    if (!rc) {
        LOG(DEBUG, "failed to get txchainsoft: ioctl not found, trying get_txchainmask");

        rc = ioctl80211_get_priv_ioctl(radio_cfg->phy_name, "get_txchainmask", &request.u.mode);
        if (!rc) {
            LOG(WARNING, "failed to get txchainmask: ioctl not found");
            return IOCTL_STATUS_ERROR;
        }
    }

    LOG(TRACE, "Probed get_txchainsofti %x %s", request.u.mode, radio_cfg->phy_name);

    rc =
        ioctl80211_request_send(
                ioctl80211_fd_get(),
                radio_cfg->phy_name,
                IEEE80211_IOCTL_GETPARAM,
                &request);
    if (0 > rc)
    {
        LOG(ERR,
                "Parsing device stats (Failed to retrieve %s txchainmask %s '%s')",
                radio_get_name_from_type(radio_cfg->type),
                radio_cfg->phy_name,
                strerror(errno));
        return IOCTL_STATUS_ERROR;
    }

    txchainmask->type = radio_cfg->type;
    txchainmask->value = request.u.mode;

    LOG(TRACE,
            "Parsed device %s temp %d",
            radio_get_name_from_type(txchainmask->type),
            txchainmask->value);
    return IOCTL_STATUS_OK;
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
