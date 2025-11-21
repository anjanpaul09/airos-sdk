#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include "log.h"
#include "info_events.h"
#include "netev_info_events.h"

// Forward declaration - target_info_vif_get is defined in platform/mtk/target/target_stats.c
bool target_info_vif_get(vif_info_event_t *vif_info);

/* Get current timestamp in milliseconds */
static uint64_t get_timestamp_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* Send VIF info event by calling target_info_vif_get */
bool netev_send_vif_info(void)
{
    vif_info_event_t vif_info = {0};
    uint64_t timestamp_ms = get_timestamp_ms();
    
    // Call target function to fill VIF info
    if (!target_info_vif_get(&vif_info)) {
        LOG(ERR, "Failed to get VIF info from target");
        return false;
    }
    
    // Send VIF info event
    if (!netev_send_vif_info_event(&vif_info, timestamp_ms)) {
        LOG(ERR, "Failed to send VIF info event");
        return false;
    }
    
    LOG(INFO, "Sent VIF info event: n_radio=%d n_vif=%d n_ethernet=%d", 
        vif_info.n_radio, vif_info.n_vif, vif_info.n_ethernet);
    
    return true;
}

