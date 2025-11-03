#ifndef NETSTATS_H_INCLUDED
#define NETSTATS_H_INCLUDED

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
#include "memutil.h"

#include "os_nif.h"

#include "stats_report.h"

struct netstats_cxt;  // Forward declaration

#define RADIO_COUNTRY_CODE_LEN          8
#define RADIO_NAME_LEN                  32

#define TIME_NSEC_IN_SEC   1000000000
#define TIME_USEC_IN_SEC   1000000
#define TIME_MSEC_IN_SEC   1000
#define TIME_NSEC_PER_MSEC (TIME_NSEC_IN_SEC / TIME_MSEC_IN_SEC)
#define NETSTATS_MAX_QUEUE_DEPTH (200)
#define NETSTATS_MAX_QUEUE_SIZE_BYTES (2*1024*1024)


static inline char *netstats_timestamp_ms_to_date (uint64_t   timestamp_ms)
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

#define NETSTATS_SANITY_CHECK_TIME(timestamp_ms, reporting_timestamp, report_ts) \
    netstats_sanity_check_report_timestamp( \
            __FUNCTION__, \
            timestamp_ms, \
            reporting_timestamp, \
            report_ts)


typedef struct
{
    int                             sampling_interval;
    int                             reporting_interval;
    int                             reporting_count;
    uint64_t                        reporting_timestamp;
} netstats_request_t;

typedef struct netstats_item
{
    // Minimal request for internal queueing only
    struct { uint32_t data_size; uint32_t data_type; } req;
    char *topic;
    size_t size;
    void *buf;
    time_t timestamp;
    ds_dlist_node_t qnode;
} netstats_item_t;

typedef struct netstats_queue
{
    ds_dlist_t queue;
    int length;
    int size;
} netstats_queue_t;

extern netstats_queue_t g_netstats_queue;
extern char *g_netstats_log_buf;
extern int   g_netstats_log_buf_size;
extern int   g_netstats_log_drop_count;
extern bool  netstats_log_enabled;

/* functions */
bool netstats_setup_monitor(void);
int netstats_cancel_monitor(void);

int netstats_init_nl(struct netstats_cxt *cxt);

bool netstats_mqtt_init(void);
void netstats_mqtt_set(const char *broker, const char *port, const char *topic, const char *qos, int compress);
void netstats_mqtt_stop(void);

void netstats_sanity_check_report_timestamp(
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


size_t netstats_put_device(device_report_data_t *rpt);
size_t netstats_put_vif(vif_report_data_t *rpt);
size_t netstats_put_client(client_report_data_t *rpt);

// Initialization functions
bool netstats_initiate_stats(void);
bool netstats_init_device_stats_send(void);
bool netstats_nl_event_monitor(void);
bool netstats_dequeue_timer_init(void);
bool netstats_init_neighbor_stats(void);

// UBUS functions
// Unified initialization - combines both TX and RX
bool netstats_ubus_service_init(void);
void netstats_ubus_service_cleanup(void);

// Legacy functions - kept for backward compatibility (deprecated, use unified functions above)
bool netstats_ubus_tx_service_init(void);
void netstats_ubus_tx_service_cleanup(void);
bool netstats_ubus_rx_service_init(void);
void netstats_ubus_rx_service_cleanup(void);

// Stats publishing
void netstats_publish_stats(netstats_item_t *qi);
size_t netstats_put_neighbor(neighbor_report_data_t *rpt);

// Platform-specific function declarations
extern int target_stats_device_get(device_record_t *device_entry);

bool netstats_neighbor_report_request(netstats_request_t *request);
bool netstats_client_report_request(netstats_request_t *request);
bool netstats_device_report_request(netstats_request_t *request);
bool netstats_vif_report_request(netstats_request_t *request);

bool netstats_queue_msg_process();
bool netstats_process_msg(netstats_item_t *qi);
void netstats_queue_init();
typedef struct { uint32_t response; uint32_t error; uint32_t qdrop; } netstats_response_t;
bool netstats_queue_put(netstats_item_t **qitem, netstats_response_t *res);

// Minimal enums for queue decisions
enum { NETSTATS_DATA_LOG = 3 };
enum { NETSTATS_RESPONSE_ERROR = 0 };
enum { NETSTATS_ERROR_QUEUE = 103 };
void netstats_queue_item_free(netstats_item_t *qi);


bool netstats_mqtt_publish(long mlen, void *mbuf);
#endif /* NETSTATS_H_INCLUDED */
