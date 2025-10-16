#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <inttypes.h>
#include <sys/vfs.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include "log.h"
#include "os.h"
#include "os_nif.h"
#include "os_regex.h"
#include "os_types.h"
#include "os_util.h"
#include "target.h"
#include "util.h"

#include "ioctl80211_jedi.h"
#include "report.h"
//Anjan
#include "MT7621.h"

#define MODULE_ID LOG_MODULE_ID_TARGET

bool target_stats_clients_get(client_report_data_t *client_list);
bool target_stats_vif_get(vif_record_t *record);
bool target_stats_neighbor_get(neighbor_report_data_t *report);
/******************************************************************************
 *  INTERFACE definitions
 *****************************************************************************/
bool target_is_radio_interface_ready(char *phy_name)
{
    bool rc;
    rc = os_nif_is_interface_ready(phy_name);
    if (true != rc)
    {
        return false;
    }

    return true;
}

bool target_is_interface_ready(char *if_name)
{
    bool rc;
    rc = os_nif_is_interface_ready(if_name);
    if (true != rc)
    {
        return false;
    }

    return true;
}

/******************************************************************************
 *  CLIENT definitions
 *****************************************************************************/

bool target_stats_clients_get(client_report_data_t *client_list)
{
    ioctl_status_t rc;
    rc = ioctl80211_jedi_client_list_get(client_list);
    if (IOCTL_STATUS_OK != rc)
    {
        return false;
    }

    return true;
}

/******************************************************************************
 *  VIF definitions
 *****************************************************************************/
#define MAX_LINE_LENGTH 100

bool target_stats_vif_get(vif_record_t *record)
{
    return ioctl80211_jedi_stats_vif_get(record);
}

/******************************************************************************
 *  NEIGHBORS definitions
 *****************************************************************************/

bool target_stats_neighbor_get(neighbor_report_data_t *report)
{
    ioctl_status_t rc;

    rc = ioctl80211_jedi_scan_results_get(report);
    if (IOCTL_STATUS_OK != rc)
    {
        return false;
    }

    return true;
}

