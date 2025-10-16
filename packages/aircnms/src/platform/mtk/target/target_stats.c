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
#include <linux/wireless.h>

#include "log.h"
#include "os.h"
#include "os_nif.h"
#include "os_regex.h"
#include "os_types.h"
#include "os_util.h"
#include "target.h"
#include "util.h"

#include "nl80211.h"
#include "target_nl80211.h"

#include "nl80211_stats.h"
#include "nl80211_client.h"
#include "nl80211_survey.h"
#include "nl80211_scan.h"
#include "nl80211_device.h"

#include "report.h"
//Anjan
#include "MT7621.h"

#define MODULE_ID LOG_MODULE_ID_TARGET

//bool nl80211_stats_vif_get(dpp_vif_record_t *record);
/******************************************************************************
 *  INTERFACE definitions
 *****************************************************************************/

static bool
check_interface_exists(char *if_name)
{
    struct dirent *i;
    DIR *d;

    if (WARN_ON(!(d = opendir("/sys/class/net"))))
        return false;

    while ((i = readdir(d)))
        if (strcmp(i->d_name, if_name) == 0) {
            closedir(d);
            return true;
        }

    closedir(d);
    return false;
}


static bool
check_radio_exists(char *phy_name)
{
    struct dirent *i;
    DIR *d;

    if (WARN_ON(!(d = opendir(CONFIG_MAC80211_WIPHY_PATH))))
        return false;

    while ((i = readdir(d)))
        if (strcmp(i->d_name, phy_name) == 0) {
            closedir(d);
            return true;
        }

    closedir(d);
    return false;
}


bool target_is_radio_interface_ready(char *phy_name)
{
    bool rc;
    rc = check_radio_exists(phy_name);
    if (true != rc)
    {
        return false;
    }

    return true;
}

bool target_is_interface_ready(char *if_name)
{
    bool rc;
    rc = check_interface_exists(if_name);
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
    bool ret;

    ret = nl80211_stats_clients_get(client_list);

    return ret;
}

/******************************************************************************
 *  NEIGHBORS definitions
 *****************************************************************************/

bool target_stats_neighbor_get(neighbor_report_data_t *scan_results)
{
    return nl80211_stats_scan_get(scan_results);
}

/******************************************************************************
 *  VIF definitions
 *****************************************************************************/
#define MAX_LINE_LENGTH 100

bool target_stats_vif_get(vif_record_t *record)
{
    return nl80211_stats_vif_get(record);
}
