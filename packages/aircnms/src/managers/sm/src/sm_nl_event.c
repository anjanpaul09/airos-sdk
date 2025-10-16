#include <limits.h>
#include <stdio.h>
//#include <signal.h>
#include <sys/ioctl.h>
#include <linux/nl80211.h>
#include <fcntl.h>

#include <stdint.h>  
#include "airdpi/air_ioctl.h"
#include "os_time.h"
#include "os_nif.h"
//#include "dppline.h"
#include "log.h"

#include "unixcomm.h"
#include "sm.h"
#include "ext_event.h"

#define STATS_MQTT_BUF_SZ        (128*1024)    // 128 KB
#define SM_NL_EV_INTERVAL 1.0

static struct ev_timer  sm_nlev_timer;
static double           sm_nlev_timer_interval = SM_NL_EV_INTERVAL;
static uint8_t          sm_nlev_buf[STATS_MQTT_BUF_SZ];

bool sm_ext_event_trigger_report_request(radio_entry_t *radio_cfg, sm_stats_request_t *request);

void sm_nlev_get_curr_client(void)
{
    kill(getpid(), SIGUSR1);
}

void sm_nlev_timer_handler(struct ev_loop *loop, ev_timer *timer, int revents)
{
    (void)loop;
    (void)timer;
    (void)revents;
    sm_ext_event_t *nl;

    if (!ds_dlist_is_empty(&g_ext_event_list)) {
        LOG(INFO, "STA: NL EVENT RECEIVED.....\n");
    }

    while (!ds_dlist_is_empty(&g_ext_event_list)) {
        nl = ds_dlist_head(&g_ext_event_list);

        if (nl->event == NL80211_CMD_NEW_STATION) {
            LOG(INFO, " STA ADD, MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                        nl->mac[0], nl->mac[1], nl->mac[2], nl->mac[3], nl->mac[4], nl->mac[5]);
            usleep(1000*1000);
            sm_nlev_get_curr_client();
        } else if (nl->event == NL80211_CMD_DEL_STATION) {
            LOG(INFO, " STA DEL, MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                        nl->mac[0], nl->mac[1], nl->mac[2], nl->mac[3], nl->mac[4], nl->mac[5]);
            usleep(1000*1000);
            sm_nlev_get_curr_client();
        }
        ds_dlist_remove_head(&g_ext_event_list);
        free(nl);
    }

    return;
}

bool sm_nl_event_monitor(void)
{
    ev_timer_init(&sm_nlev_timer, sm_nlev_timer_handler, sm_nlev_timer_interval, sm_nlev_timer_interval);

    sm_nlev_timer.data = NULL;

    ev_timer_start(EV_DEFAULT, &sm_nlev_timer);

    return true;
}
