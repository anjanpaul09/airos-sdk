#ifndef SM_H_INCLUDED
#define SM_H_INCLUDED

#include <stdbool.h>
#include <jansson.h>
#include <ev.h>
#include <sys/time.h>
#include <syslog.h>
#include "sm_conn.h"

#include "log.h"

#include "ds.h"
#include "ds_tree.h"

#include "os_nif.h"

#include "dppline.h"

#define SM_MAX_QUEUE_DEPTH (200)
#define SM_MAX_QUEUE_SIZE_BYTES (2*1024*1024)

struct schema_Wifi_VIF_State {
    char uuid[37];
};

struct schema_Wifi_Stats_Config {
    char radio_type[128 + 1];
    char report_type[128 + 1];
    char stats_type[128 + 1];
    char survey_type[128 + 1];
    int channel_list[64];
    int channel_list_len;
    char uuid[37];
    bool survey_type_exists;
    int reporting_interval;
    int reporting_count;
    int sampling_interval;
    int survey_interval_ms;
};

struct schema_Wifi_Radio_State {
    char uuid[37];
};

struct sm_cxt {
    struct          ev_io nl_watcher;
    int             nl_fd;
    int             monitor_id;
    int             tx_sm_band;
    int             rx_sm_band;
};

static inline char *sm_timestamp_ms_to_date (uint64_t   timestamp_ms)
{
    struct tm      *dt;
    time_t          t = timestamp_ms / 1000;
    static char     b[32];

    dt = localtime((time_t *)&t);

    memset (b, 0, sizeof(b));
    strftime(b, sizeof(b), "%F %T%z", dt);

    return b;
}

#define REQUEST_PARAM_UPDATE(TYPE, VAR, FMT) \
    if (request_ctx->VAR != request->VAR) \
    { \
        LOG(DEBUG, \
            "Updated %s %s "#VAR" "FMT" -> "FMT"", \
            radio_get_name_from_cfg(radio_cfg), \
            TYPE, \
            request_ctx->VAR, \
            request->VAR); \
        request_ctx->VAR = request->VAR; \
    }

#define REQUEST_VAL_UPDATE(TYPE, VAR, FMT) \
    if (request_ctx->VAR != request->VAR) \
    { \
        LOG(DEBUG, \
            "Updated %s "#VAR" "FMT" -> "FMT"", \
            TYPE, \
            request_ctx->VAR, \
            request->VAR); \
        request_ctx->VAR = request->VAR; \
    }

#define SM_SANITY_CHECK_TIME(timestamp_ms, reporting_timestamp, report_ts) \
    sm_sanity_check_report_timestamp( \
            __FUNCTION__, \
            timestamp_ms, \
            reporting_timestamp, \
            report_ts)


typedef struct
{
    uint32_t                        chan_list[RADIO_MAX_CHANNELS];
    uint32_t                        chan_num;
    uint32_t                        chan_index;
} sm_chan_list_t;

typedef struct
{
    radio_type_t                    radio_type;
    report_type_t                   report_type;
    radio_scan_type_t               scan_type;
    int                             sampling_interval;
    int                             reporting_interval;
    int                             reporting_count;
    int                             scan_interval;
    int                             threshold_util;
    int                             threshold_max_delay;
    int                             threshold_pod_qty;
    int                             threshold_pod_num;
    bool                            mac_filter;
    uint64_t                        reporting_timestamp;
    sm_chan_list_t                  radio_chan_list;
} sm_stats_request_t;

typedef struct sm_item
{
    sm_request_t req;
    char *topic;
    size_t size;
    void *buf;
    time_t timestamp;
    ds_dlist_node_t qnode;
} sm_item_t;

typedef struct sm_queue
{
    ds_dlist_t queue;
    int length;
    int size;
} sm_queue_t;

extern sm_queue_t g_sm_queue;
extern char *g_sm_log_buf;
extern int   g_sm_log_buf_size;
extern int   g_sm_log_drop_count;
extern bool  sm_log_enabled;

/* functions */
bool sm_setup_monitor(void);
int sm_cancel_monitor(void);

int sm_init_nl(struct sm_cxt *cxt);

bool sm_mqtt_init(void);
void sm_mqtt_set(const char *broker, const char *port, const char *topic, const char *qos, int compress);
void sm_mqtt_stop(void);


/******************************************************************************
 *  SCAN SCHED definitions
 *****************************************************************************/
typedef void (*sm_scan_cb_t)(
        void                       *scan_ctx,
        int                         status);

typedef struct {
    radio_entry_t                  *radio_cfg;
    uint32_t                       *chan_list;
    uint32_t                        chan_num;
    radio_scan_type_t               scan_type;
    int32_t                         dwell_time;
    sm_scan_cb_t                    scan_cb;
    void                           *scan_ctx;
    dpp_neighbor_report_data_t     *scan_results;
} sm_scan_request_t;

typedef struct {
    sm_scan_request_t               scan_request;
    ds_dlist_node_t                 node;
} sm_scan_ctx_t;

bool sm_scan_schedule(sm_scan_request_t *scan_request);
bool sm_scan_schedule_immediate(sm_scan_request_t *scan_request);

bool sm_scan_schedule_init();

bool sm_scan_schedule_stop (
        radio_entry_t              *radio_cfg,
        radio_scan_type_t           scan_type);


/******************************************************************************
 *  CLIENT REPORT definitions
 *****************************************************************************/
bool sm_client_report_request(
        radio_entry_t              *radio_cfg,
        sm_stats_request_t         *request);
bool sm_client_report_radio_change(
        radio_entry_t              *radio_cfg);

typedef enum
{
	STS_REPORT_NEIGHBOR,
    STS_REPORT_CLIENT,
    STS_REPORT_DEVICE,
    STS_REPORT_VIF,
    STS_REPORT_MAX,
    STS_REPORT_ERROR = STS_REPORT_MAX
} sm_report_type_t;

typedef struct
{
    struct schema_Wifi_Radio_State  schema;
    bool                            init;
    radio_entry_t                   config;

    ds_tree_node_t                  node;
} sm_radio_state_t;

typedef struct
{
    struct schema_Wifi_VIF_State    schema;

    ds_tree_node_t                  node;
} sm_vif_state_t;

typedef struct
{
    struct schema_Wifi_Stats_Config schema;
    sm_report_type_t                sm_report_type;
    report_type_t                   report_type;
    radio_type_t                    radio_type;
    radio_scan_type_t               scan_type;

    ds_tree_node_t                  node;
} sm_stats_config_t;

ds_tree_t *sm_radios_get();


void sm_sanity_check_report_timestamp(
        const char *log_prefix,
        uint64_t    timestamp_ms,
        uint64_t   *reporting_timestamp,
        uint64_t   *report_ts);

#endif /* SM_H_INCLUDED */
