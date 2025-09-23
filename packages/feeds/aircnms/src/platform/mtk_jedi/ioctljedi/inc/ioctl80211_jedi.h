#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <stdint.h>  
#include <ev.h>

#include "report.h"

typedef enum
{
    IOCTL_STATUS_ERROR        = -1,
    IOCTL_STATUS_OK           = 0,
    IOCTL_STATUS_NOSUPPORT    = 1
} ioctl_status_t;

ioctl_status_t ioctl80211_jedi_client_list_get(client_report_data_t *client_list);
ioctl_status_t ioctl80211_jedi_scan_results_get(neighbor_report_data_t *report); 
bool ioctl80211_jedi_stats_vif_get(vif_record_t *record);
bool ioctl80211_jedi_stats_vap_get(vif_record_t *record);
