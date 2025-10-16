#ifndef SM_H_INCLUDED
#define SM_H_INCLUDED

#include <stdbool.h>
#include <jansson.h>
#include <ev.h>
#include <sys/time.h>
#include <syslog.h>
#include "unixcomm.h"
#include <time.h>  
#include "log.h"

#include "ds.h"
#include "ds_tree.h"

#include "os_nif.h"

//#include "dppline.h"
#include "report.h"

#define RADIO_COUNTRY_CODE_LEN          8
#define RADIO_NAME_LEN                  32

#define TIME_NSEC_IN_SEC   1000000000
#define TIME_USEC_IN_SEC   1000000
#define TIME_MSEC_IN_SEC   1000
#define TIME_NSEC_PER_MSEC (TIME_NSEC_IN_SEC / TIME_MSEC_IN_SEC)
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
    radio_type_t                    type;
    uint32_t                        chan;
    uint32_t                        tx_power;
    char                            cntry_code[RADIO_COUNTRY_CODE_LEN];
    char                            phy_name[RADIO_NAME_LEN];
    char                            if_name[RADIO_NAME_LEN];
} radio_entry_t;

typedef struct
{
    radio_type_t                    radio_type;
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
} sm_stats_request_t;

typedef struct sm_item
{
    // Minimal request for internal queueing only
    struct { uint32_t data_size; uint32_t data_type; } req;
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

// Legacy direct send removed

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
    int channel_list[64];
    int channel_list_len;
    bool survey_type_exists;
    int reporting_interval;
    int reporting_count;
    int sampling_interval;
    int survey_interval_ms;
    sm_report_type_t                sm_report_type;
    radio_type_t                    radio_type;
} sm_stats_config_t;

ds_tree_t *sm_radios_get();



void sm_sanity_check_report_timestamp(
        const char *log_prefix,
        uint64_t    timestamp_ms,
        uint64_t   *reporting_timestamp,
        uint64_t   *report_ts);


static inline uint64_t timespec_to_timestamp(const struct timespec *ts)
{
    return (uint64_t)ts->tv_sec * TIME_MSEC_IN_SEC + ts->tv_nsec / TIME_NSEC_PER_MSEC;
}

static inline uint64_t get_timestamp(void)
{
    struct timespec                 ts;

    memset (&ts, 0, sizeof (ts));
    if(clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
    {
        return 0;
    }
    else
        return timespec_to_timestamp(&ts);
}


bool sm_put_device(device_report_data_t *rpt);
bool sm_put_vif(vif_report_data_t *rpt);
bool sm_put_client(client_report_data_t *rpt);
bool sm_put_neighbor(neighbor_report_data_t *rpt);

bool sm_neighbor_report_request(sm_stats_request_t *request);
bool sm_client_report_request(radio_entry_t *radiocfg, sm_stats_request_t *request);
bool sm_device_report_request(sm_stats_request_t *request);
bool sm_vif_report_request(sm_stats_request_t *request);

bool sm_queue_msg_process();
bool sm_process_msg(sm_item_t *qi);
void sm_queue_init();
typedef struct { uint32_t response; uint32_t error; uint32_t qdrop; } sm_response_t;
bool sm_queue_put(sm_item_t **qitem, sm_response_t *res);

// Minimal enums for queue decisions
enum { SM_DATA_LOG = 3 };
enum { SM_RESPONSE_ERROR = 0 };
enum { SM_ERROR_QUEUE = 103 };
void sm_queue_item_free(sm_item_t *qi);


bool sm_mqtt_publish(long mlen, void *mbuf);
#endif /* SM_H_INCLUDED */
