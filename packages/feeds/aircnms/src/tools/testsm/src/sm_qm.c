#include <limits.h>
#include <stdio.h>

#include "os_time.h"
#include "os_nif.h"
#include "dppline.h"
#include "log.h"

#include "qm_conn.h"
#include "sm.h"

#define SM_QM_INTERVAL 1.0
/* Global MQTT instance */
static struct ev_timer  sm_mqtt_timer;
static double           sm_mqtt_timer_interval = SM_QM_INTERVAL;
static uint8_t          sm_mqtt_buf[STATS_MQTT_BUF_SZ];


void sm_debug_dpp_report(long mlen, void *mbuf)
{
    Sts__Report *rpt = NULL;

    // have stats, unpack
    rpt = sts__report__unpack(NULL, mlen, mbuf);
    

    if (rpt->n_device) {
        int n_device = rpt->n_device;
        printf("Ankit: n-device = %d\n", n_device);
    }

    if (rpt->n_clients) {
        int n_client = rpt->n_clients;
        for (int i = 0; i < rpt->n_clients; i++){
            Sts__ClientReport *cr = NULL;
            cr = rpt->clients[i];

            char band[8];
            if(cr->band == STS__RADIO_BAND_TYPE__BAND2G) {
                strcpy(band, "BAND2G");
            } else if(cr->band == STS__RADIO_BAND_TYPE__BAND5G) {
                strcpy(band, "BAND5G");
            } else if(cr->band == STS__RADIO_BAND_TYPE__BAND5GL) {
                strcpy(band, "BAND5GL");
            } else if(cr->band == STS__RADIO_BAND_TYPE__BAND5GU) {
                strcpy(band, "BAND5GU");
            } else if(cr->band == STS__RADIO_BAND_TYPE__BAND6G) {
                strcpy(band, "BAND6G");
            } 
            
            printf("Ankit:client band = %s\n", band);
            int n_client_list = cr->n_client_list;
            printf("Ankit: n-clients = %d\n", n_client_list);
        }
    }

    if (rpt->n_vif) {
        int n_vif = rpt->n_vif;
        for (int i = 0; i < n_vif; i++){
            Sts__VifStatReport *vr = NULL;
            vr = rpt->vif[i];
            int n_radio_list = vr->n_radio_list;
            int n_vif_list = vr->n_vif_list;
            printf("Ankit: n-radio = %d , n-vif = %d \n", n_radio_list, n_vif_list);
        }
    }

    if (rpt->n_neighbors) {
        int n_neighbor = rpt->n_neighbors;
        printf("Ankit: n-neighbor = %d\n", n_neighbor);
    }
    
    if (rpt) sts__report__free_unpacked(rpt, NULL);
}

static
bool sm_mqtt_publish(long mlen, void *mbuf)
{
    qm_response_t res;
    bool ret;
    strcpy(res.tag, "stats");
    ret = qm_conn_send_stats(mbuf, mlen, &res);
    return ret;
}

void sm_mqtt_timer_handler(struct ev_loop *loop, ev_timer *timer, int revents)
{
    (void)loop;
    (void)timer;
    (void)revents;

    static bool qm_err = false;
    uint32_t buf_len;
    #define UCI_BUF_LEN 256
    char buf[UCI_BUF_LEN];
    size_t len;
    int rc;
    int aircnms_status;

    memset(buf, 0, sizeof(buf));
    rc = cmd_buf("uci get aircnms.@aircnms[0].online", buf, (size_t)UCI_BUF_LEN);
    len = strlen(buf);
    if (len == 0) {
        LOGI("%s: No uci found", __func__);
        return;
    }
    sscanf(buf, "%d", &aircnms_status);

    if (dpp_get_queue_elements() <= 0) {
        return;
    }

    printf("total element in sm datapipeline = %d\n", dpp_get_queue_elements());
    while (dpp_get_queue_elements() > 0) {
        printf("Ankit: removing head\n");
        dppline_remove_head();
    }
    return;

    LOG(DEBUG, "Total %d elements queued for transmission.\n", dpp_get_queue_elements());
   
    if (!qm_conn_get_status(NULL)) {
        if (!qm_err) {
            LOG(INFO, "Cannot connect to QM (QM not running?)");
        }

        while (dpp_get_queue_elements() > 0) {
            dppline_remove_head();
        }
        LOG(INFO, "qm dead, total element in sm datapipeline = %d\n", dpp_get_queue_elements());
        qm_err = true;
        return;
    }
    qm_err = false;
    while (dpp_get_queue_elements() > 0) {
        if (!dpp_get_report(sm_mqtt_buf, sizeof(sm_mqtt_buf), &buf_len)) {
            LOGE("DPP: Get report failed.\n");
            break;
        }
        if (buf_len <= 0) continue;
        if (aircnms_status == 1) {
            sm_debug_dpp_report(buf_len, sm_mqtt_buf);    
            if (!sm_mqtt_publish(buf_len, sm_mqtt_buf)) {
                LOGE("Publish report failed.\n");
                break;
            }
        }
    }
}

bool sm_mqtt_init(void)
{
    ev_timer_init(&sm_mqtt_timer, sm_mqtt_timer_handler, sm_mqtt_timer_interval, sm_mqtt_timer_interval);

    sm_mqtt_timer.data = NULL;

    ev_timer_start(EV_DEFAULT, &sm_mqtt_timer);

    return true;
}
