#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <ev.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <zlib.h>
#include "cgw.h"
#include "report.h"
#include "cgw_state_mgr.h"
#include "cgw_registration_attempt.h"
#include "info_events.h"
#include "log.h"

static struct ubus_context *ctx = NULL;
static struct ev_loop *loop = NULL;
static ev_io ubus_watcher;
static ev_async registration_result_watcher;
static pthread_mutex_t registration_worker_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t registration_worker_thread;
static bool registration_worker_created;
static bool registration_worker_running;
static bool registration_result_pending;
static cgw_registration_attempt_snapshot_t registration_pending_snapshot;
static uint64_t mqtt_event_sequence;

typedef struct {
    char attempt_id[CGW_ATTEMPT_ID_LEN];
} registration_worker_arg_t;

#define IPC_BUFFER_SIZE 8064
#define MAX_UBUS_METHODS 2

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

// Helper function to get message type string from enum
static const char* get_stats_type_str(NETSTATS_STATS_TYPE type)
{
    switch (type) {
        case NETSTATS_T_NEIGHBOR: return "neighbor";
        case NETSTATS_T_CLIENT: return "client";
        case NETSTATS_T_DEVICE: return "device";
        case NETSTATS_T_VIF: return "vif";
        default: return "unknown";
    }
}

// Helper function to peek at message type from compressed data
static NETSTATS_STATS_TYPE peek_stats_type(const uint8_t *compressed_data, size_t compressed_size)
{
    if (!compressed_data || compressed_size == 0) {
        return 0;
    }
    
    // Use a reasonable buffer size - most messages decompress to < 8KB
    // We only need first few bytes for type, so this should be sufficient
    uint8_t decompressed_data[8192];
    uLongf decompressed_size = sizeof(decompressed_data);
    
    int ret = uncompress(decompressed_data, &decompressed_size, compressed_data, compressed_size);
    if (ret != Z_OK) {
        // Decompression failed - data might be corrupted or buffer too small
        // This is not critical, we'll still process it correctly later
        return 0;
    }
    
    if (decompressed_size < sizeof(NETSTATS_STATS_TYPE)) {
        return 0; // Not enough data after decompression
    }
    
    NETSTATS_STATS_TYPE type;
    memcpy(&type, decompressed_data, sizeof(type));
    
    // Validate type is in valid range
    if (type >= NETSTATS_T_NEIGHBOR && type <= NETSTATS_T_VIF) {
        return type;
    }
    
    return 0; // Invalid type
}

// Helper function to peek at neighbor entries count from compressed data
static int peek_neighbor_entries(const uint8_t *compressed_data, size_t compressed_size)
{
    if (!compressed_data || compressed_size == 0) {
        return -1;
    }
    
    // Decompress enough to read type, size, and neighbor data header
    uint8_t decompressed_data[8192];
    uLongf decompressed_size = sizeof(decompressed_data);
    
    int ret = uncompress(decompressed_data, &decompressed_size, compressed_data, compressed_size);
    if (ret != Z_OK) {
        return -1;
    }
    
    size_t offset = 0;
    
    // Read type
    if (offset + sizeof(NETSTATS_STATS_TYPE) > decompressed_size) {
        return -1;
    }
    NETSTATS_STATS_TYPE type;
    memcpy(&type, decompressed_data + offset, sizeof(type));
    offset += sizeof(type);
    
    if (type != NETSTATS_T_NEIGHBOR) {
        return -1; // Not a neighbor message
    }
    
    // Read size
    if (offset + sizeof(int) > decompressed_size) {
        return -1;
    }
    int stats_size;
    memcpy(&stats_size, decompressed_data + offset, sizeof(stats_size));
    offset += sizeof(stats_size);
    
    // Read neighbor_report_data_t header (timestamp_ms + n_entry)
    if (offset + sizeof(uint64_t) + sizeof(int) > decompressed_size) {
        return -1;
    }
    
    offset += sizeof(uint64_t); // Skip timestamp_ms
    int n_entry;
    memcpy(&n_entry, decompressed_data + offset, sizeof(n_entry));
    
    return n_entry;
}


void cgw_ubus_emit_mqtt_event(bool connected, int rc, const char *reason_code)
{
    struct blob_buf b = {};

    if (!ctx)
        return;
    mqtt_event_sequence++;
    blob_buf_init(&b, 0);
    blobmsg_add_string(&b, "schema", "air.cgwd.mqtt.v1");
    blobmsg_add_u8(&b, "connected", connected);
    blobmsg_add_string(&b, "reason_code", reason_code ? reason_code : "UNKNOWN");
    blobmsg_add_u32(&b, "broker_rc", (uint32_t)(rc < 0 ? 0 : rc));
    blobmsg_add_u64(&b, "sequence", mqtt_event_sequence);
    ubus_send_event(ctx, "air.cgwd.mqtt", b.head);
    blob_buf_free(&b);
}

static int ubus_mqtt_reconnect_handler(struct ubus_context *ubus,
                                       struct ubus_object *obj,
                                       struct ubus_request_data *req,
                                       const char *method,
                                       struct blob_attr *msg)
{
    cgw_mqtt_reconnect_result_t result;
    struct blob_buf b = {};
    uint32_t retry_after = 0;
    const char *code;

    (void)obj; (void)method; (void)msg;
    result = cgw_mqtt_request_reconnect(&retry_after);
    code = result == CGW_MQTT_RECONNECT_ACCEPTED ? "ACCEPTED" :
           result == CGW_MQTT_RECONNECT_THROTTLED ? "THROTTLED" : "NOT_READY";
    blob_buf_init(&b, 0);
    blobmsg_add_string(&b, "schema", "air.cgwd.mqtt.reconnect.v1");
    blobmsg_add_u8(&b, "accepted", result == CGW_MQTT_RECONNECT_ACCEPTED);
    blobmsg_add_string(&b, "code", code);
    blobmsg_add_u32(&b, "retry_after", retry_after);
    ubus_send_reply(ubus, req, b.head);
    blob_buf_free(&b);
    return 0;
}

static int ubus_get_state_handler(struct ubus_context *ctx,
                                  struct ubus_object *obj,
                                  struct ubus_request_data *req,
                                  const char *method,
                                  struct blob_attr *msg)
{
    struct blob_buf b = {};
    blob_buf_init(&b, 0);

    device_state_t s = get_device_state();

    // Map enum → human-readable string
    const char *state_str = "unknown";
    switch (s) {
        case DEVICE_STATE_DISCOVERY:     state_str = "discovery"; break;
        case DEVICE_STATE_NOT_REGISTERED: state_str = "not_registered"; break;
        case DEVICE_STATE_REGISTERED:     state_str = "registered"; break;
    }

    blobmsg_add_string(&b, "state", state_str);
    blobmsg_add_u32(&b, "state_code", s);

    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
    return 0;
}

static void registration_add_snapshot(struct blob_buf *b,
                                      const cgw_registration_attempt_snapshot_t *snapshot)
{
    blobmsg_add_string(b, "schema", "air.cgwd.registration.v1");
    blobmsg_add_string(b, "attempt_id", snapshot->attempt_id);
    blobmsg_add_string(b, "state", cgw_attempt_state_string(snapshot->state));
    blobmsg_add_string(b, "result",
                       (snapshot->state == CGW_ATTEMPT_COMPLETE ||
                        snapshot->state == CGW_ATTEMPT_CANCELLED) ?
                       cgw_registration_result_string(snapshot->result) : "NONE");
    blobmsg_add_u32(b, "generation", (uint32_t)snapshot->generation);
}

static void registration_result_cb(EV_P_ ev_async *w, int revents)
{
    cgw_registration_attempt_snapshot_t snapshot;
    struct blob_buf b = {};
    bool pending;

    (void)loop;
    (void)w;
    (void)revents;
    pthread_mutex_lock(&registration_worker_lock);
    pending = registration_result_pending;
    snapshot = registration_pending_snapshot;
    registration_result_pending = false;
    pthread_mutex_unlock(&registration_worker_lock);
    if (!pending || !ctx)
        return;
    blob_buf_init(&b, 0);
    registration_add_snapshot(&b, &snapshot);
    ubus_send_event(ctx, "air.cgwd.registration", b.head);
    blob_buf_free(&b);
}

static void *registration_worker_main(void *arg)
{
    registration_worker_arg_t *worker = arg;
    cgw_registration_attempt_snapshot_t snapshot;

    cgw_run_registration_attempt(worker->attempt_id);
    cgw_registration_attempt_snapshot(&snapshot);
    pthread_mutex_lock(&registration_worker_lock);
    registration_pending_snapshot = snapshot;
    registration_result_pending = true;
    registration_worker_running = false;
    pthread_mutex_unlock(&registration_worker_lock);
    ev_async_send(EV_DEFAULT, &registration_result_watcher);
    free(worker);
    return NULL;
}

static void registration_worker_reap(void)
{
    pthread_t thread;
    bool join = false;

    pthread_mutex_lock(&registration_worker_lock);
    if (registration_worker_created && !registration_worker_running) {
        thread = registration_worker_thread;
        registration_worker_created = false;
        join = true;
    }
    pthread_mutex_unlock(&registration_worker_lock);
    if (join)
        pthread_join(thread, NULL);
}

enum { REG_CANCEL_ATTEMPT_ID, __REG_CANCEL_MAX };
static const struct blobmsg_policy registration_cancel_policy[__REG_CANCEL_MAX] = {
    [REG_CANCEL_ATTEMPT_ID] = { .name = "attempt_id", .type = BLOBMSG_TYPE_STRING },
};

static int ubus_registration_start_handler(struct ubus_context *ubus,
                                           struct ubus_object *obj,
                                           struct ubus_request_data *req,
                                           const char *method,
                                           struct blob_attr *msg)
{
    registration_worker_arg_t *worker;
    struct blob_buf b = {};
    char attempt_id[CGW_ATTEMPT_ID_LEN] = {0};
    bool reused = false;
    int rc;

    (void)obj; (void)method; (void)msg;
    blob_buf_init(&b, 0);
    if (get_device_state() == DEVICE_STATE_REGISTERED) {
        blobmsg_add_string(&b, "schema", "air.cgwd.registration.start.v1");
        blobmsg_add_u8(&b, "accepted", false);
        blobmsg_add_string(&b, "code", "ALREADY_ENROLLED");
        ubus_send_reply(ubus, req, b.head);
        blob_buf_free(&b);
        return 0;
    }
    registration_worker_reap();
    if (!cgw_registration_attempt_begin(attempt_id, sizeof(attempt_id), &reused)) {
        blob_buf_free(&b);
        return UBUS_STATUS_UNKNOWN_ERROR;
    }
    if (!reused) {
        worker = calloc(1, sizeof(*worker));
        if (!worker) {
            cgw_registration_attempt_complete(attempt_id, CGW_REG_RESULT_TEMPORARY_FAILURE);
            blob_buf_free(&b);
            return UBUS_STATUS_UNKNOWN_ERROR;
        }
        snprintf(worker->attempt_id, sizeof(worker->attempt_id), "%s", attempt_id);
        pthread_mutex_lock(&registration_worker_lock);
        registration_worker_running = true;
        rc = pthread_create(&registration_worker_thread, NULL,
                            registration_worker_main, worker);
        if (rc == 0)
            registration_worker_created = true;
        else
            registration_worker_running = false;
        pthread_mutex_unlock(&registration_worker_lock);
        if (rc != 0) {
            free(worker);
            cgw_registration_attempt_complete(attempt_id, CGW_REG_RESULT_TEMPORARY_FAILURE);
            blob_buf_free(&b);
            return UBUS_STATUS_UNKNOWN_ERROR;
        }
    }
    blobmsg_add_string(&b, "schema", "air.cgwd.registration.start.v1");
    blobmsg_add_u8(&b, "accepted", true);
    blobmsg_add_string(&b, "code", reused ? "IN_PROGRESS" : "ACCEPTED");
    blobmsg_add_string(&b, "attempt_id", attempt_id);
    ubus_send_reply(ubus, req, b.head);
    blob_buf_free(&b);
    return 0;
}

static int ubus_registration_cancel_handler(struct ubus_context *ubus,
                                            struct ubus_object *obj,
                                            struct ubus_request_data *req,
                                            const char *method,
                                            struct blob_attr *msg)
{
    struct blob_attr *tb[__REG_CANCEL_MAX] = {};
    struct blob_buf b = {};
    cgw_cancel_result_t result;
    const char *attempt_id;

    (void)obj; (void)method;
    if (!msg)
        return UBUS_STATUS_INVALID_ARGUMENT;
    blobmsg_parse(registration_cancel_policy, __REG_CANCEL_MAX, tb,
                  blob_data(msg), blob_len(msg));
    if (!tb[REG_CANCEL_ATTEMPT_ID])
        return UBUS_STATUS_INVALID_ARGUMENT;
    attempt_id = blobmsg_get_string(tb[REG_CANCEL_ATTEMPT_ID]);
    result = cgw_registration_attempt_cancel(attempt_id);
    blob_buf_init(&b, 0);
    blobmsg_add_string(&b, "schema", "air.cgwd.registration.cancel.v1");
    blobmsg_add_u8(&b, "accepted", result == CGW_CANCEL_ACCEPTED);
    blobmsg_add_string(&b, "code", cgw_cancel_result_string(result));
    blobmsg_add_string(&b, "attempt_id", attempt_id);
    ubus_send_reply(ubus, req, b.head);
    blob_buf_free(&b);
    return 0;
}

/*
 * Versioned, credential-safe status contract for the onboarding coordinator.
 * Enrollment and transport are deliberately separate: a registered device can
 * be disconnected from MQTT, and an MQTT configuration can exist before a
 * connection is established.
 */
static int ubus_status_handler(struct ubus_context *ctx,
                               struct ubus_object *obj,
                               struct ubus_request_data *req,
                               const char *method,
                               struct blob_attr *msg)
{
    struct blob_buf b = {};
    device_state_t state;
    const char *state_str;
    int queue_depth;
    cgw_registration_attempt_snapshot_t attempt;

    (void)obj;
    (void)method;
    (void)msg;

    state = get_device_state();
    switch (state) {
        case DEVICE_STATE_DISCOVERY:
            state_str = "DISCOVERY";
            break;
        case DEVICE_STATE_NOT_REGISTERED:
            state_str = "NOT_REGISTERED";
            break;
        case DEVICE_STATE_REGISTERED:
            state_str = "REGISTERED";
            break;
        default:
            state_str = "UNKNOWN";
            break;
    }

    cgw_registration_attempt_snapshot(&attempt);
    queue_depth = cgw_queue_length();
    if (queue_depth < 0)
        queue_depth = 0;

    blob_buf_init(&b, 0);
    blobmsg_add_string(&b, "schema", "air.cgwd.status.v1");
    blobmsg_add_string(&b, "enrollment_state", state_str);
    blobmsg_add_u32(&b, "enrollment_state_code", (uint32_t)state);
    blobmsg_add_u8(&b, "registered", state == DEVICE_STATE_REGISTERED);
    blobmsg_add_u8(&b, "mqtt_configured", cgw_mqtt_config_valid());
    blobmsg_add_u8(&b, "mqtt_connected", cgw_mqtt_is_connected());
    blobmsg_add_u64(&b, "mqtt_event_sequence", mqtt_event_sequence);
    blobmsg_add_u8(&b, "device_id_present", air_dev.device_id[0] != '\0');
    blobmsg_add_u8(&b, "serial_present", air_dev.serial_num[0] != '\0');
    blobmsg_add_u32(&b, "queue_depth", (uint32_t)queue_depth);
    blobmsg_add_string(&b, "registration_attempt_state",
                       cgw_attempt_state_string(attempt.state));
    blobmsg_add_string(&b, "registration_attempt_id", attempt.attempt_id);
    blobmsg_add_string(&b, "registration_result",
                       (attempt.state == CGW_ATTEMPT_COMPLETE ||
                        attempt.state == CGW_ATTEMPT_CANCELLED) ?
                       cgw_registration_result_string(attempt.result) : "NONE");
    blobmsg_add_u32(&b, "registration_generation", (uint32_t)attempt.generation);

    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
    return 0;
}

static int ubus_netstats_handler(struct ubus_context* ctx, struct ubus_object* obj,
                              struct ubus_request_data* req, const char* method,
                              struct blob_attr* msg) 
{
    (void)ctx;
    (void)obj;
    (void)req;
    (void)method;
    
    if (!msg) {
        return -1;
    }
    
    // === Define parsing policy ===
    enum {
        DATA,
        SIZE,
        __MAX
    };
    static const struct blobmsg_policy policy[__MAX] = {
        [DATA] = { .name = "data", .type = BLOBMSG_TYPE_UNSPEC },
        [SIZE] = { .name = "size", .type = BLOBMSG_TYPE_INT32 },
    };

    struct blob_attr *tb[__MAX];
    blobmsg_parse(policy, __MAX, tb, blob_data(msg), blob_len(msg));

    if (!tb[DATA] || !tb[SIZE]) {
        LOG(ERR, "Missing expected fields in message");
        return -1;
    }

    int size = blobmsg_get_u32(tb[SIZE]);
    void *data = blobmsg_data(tb[DATA]);
    int len = blobmsg_data_len(tb[DATA]);

    LOG(DEBUG, "Declared size: %d | Actual data length: %d", size, len);

    // SECURITY_FIX: Issue #1 - NULL pointer check
    if (!data) {
        LOG(ERR, "SECURITY_FIX: NULL data pointer from blobmsg_data");
        return -1;
    }

    // SECURITY_FIX: Issue #9 - Size mismatch validation
    if (size != len) {
        LOG(ERR, "SECURITY_FIX: Size mismatch attack detected - declared=%d actual=%d", size, len);
        return -1;
    }

    // SECURITY_FIX: Issue #12 - Resource exhaustion protection
    #define MAX_UBUS_MESSAGE_SIZE (2 * 1024 * 1024)  // 2MB limit
    if (size == 0 || size > MAX_UBUS_MESSAGE_SIZE) {
        LOG(ERR, "SECURITY_FIX: Invalid message size: %d (max=%d)", size, MAX_UBUS_MESSAGE_SIZE);
        return -1;
    }

    // Try to peek at message type for logging
    // Use actual blobmsg data length (len) for decompression, not declared size
    const char *msgtype_str = "unknown";
    int entries = -1;
    if (data && len > 0) {
        NETSTATS_STATS_TYPE type = peek_stats_type((const uint8_t *)data, len);
        if (type > 0 && type <= NETSTATS_T_VIF) {
            msgtype_str = get_stats_type_str(type);
            // For neighbor messages, also peek at entries count
            if (type == NETSTATS_T_NEIGHBOR) {
                entries = peek_neighbor_entries((const uint8_t *)data, len);
            }
        }
    }

    // Log message received from netstatsd (format matches NETSTATS)
    // Use declared size for msglen (compressed size as sent by netstatsd)
    if (entries >= 0) {
        LOG(INFO, "NETSTATSD->CGWD: msgtype=%s entries=%d msglen=%d", msgtype_str, entries, size);
    } else {
        LOG(INFO, "NETSTATSD->CGWD: msgtype=%s msglen=%d", msgtype_str, size);
    }

    // Enqueue into QM queue and signal MQTT worker
    cgw_item_t *qi = CALLOC(1, sizeof(cgw_item_t));
    if (!qi) {
        LOG(ERR, "Failed to allocate cgw_item_t");
        return -1;
    }
    
    // Fill request metadata
    qi->req.data_type = DATA_STATS;
    if (data && len && size > 0) {
        qi->buf = MALLOC(size);
        if (!qi->buf) {
            LOG(ERR, "Failed to allocate data buffer");
            cgw_queue_item_free(qi);
            return -1;
        }
        memcpy(qi->buf, data, size);
        qi->size = size;
    }
        {
            cgw_response_t res = {0};
            if (!cgw_queue_put(&qi, &res)) {
                LOG(ERR, "Queue put failed: error=%u", res.error);
                if (qi) cgw_queue_item_free(qi);
            }
        }
    return 0;
}

static int ubus_conf_handler(struct ubus_context* ctx, struct ubus_object* obj,
                              struct ubus_request_data* req, const char* method,
                              struct blob_attr* msg) 
{
    (void)ctx;
    (void)obj;
    (void)req;
    (void)method;
    
    if (!msg) {
        return -1;
    }
    
    // === Define parsing policy ===
    enum {
        DATA,
        SIZE,
        __MAX
    };
    static const struct blobmsg_policy policy[__MAX] = {
        [DATA] = { .name = "data", .type = BLOBMSG_TYPE_UNSPEC },
        [SIZE] = { .name = "size", .type = BLOBMSG_TYPE_INT32 },
    };

    struct blob_attr *tb[__MAX];
    blobmsg_parse(policy, __MAX, tb, blob_data(msg), blob_len(msg));

    if (!tb[DATA] || !tb[SIZE]) {
        LOG(ERR, "Missing expected fields in message");
        return -1;
    }

    int size = blobmsg_get_u32(tb[SIZE]);
    void *data = blobmsg_data(tb[DATA]);
    int len = blobmsg_data_len(tb[DATA]);

    LOG(DEBUG, "Declared size: %d | Actual data length: %d", size, len);

    // SECURITY_FIX: Issue #1 - NULL pointer check
    if (!data) {
        LOG(ERR, "SECURITY_FIX: NULL data pointer in conf_handler");
        return -1;
    }

    // SECURITY_FIX: Size validation
    if (size != len || size == 0 || size > MAX_UBUS_MESSAGE_SIZE) {
        LOG(ERR, "SECURITY_FIX: Invalid size in conf_handler: declared=%d actual=%d", size, len);
        return -1;
    }

    // Enqueue into QM queue and signal MQTT worker
    cgw_item_t *qi = CALLOC(1, sizeof(cgw_item_t));
    if (!qi) {
        LOG(ERR, "Failed to allocate cgw_item_t");
        return -1;
    }
    
    // Fill request metadata
    qi->req.data_type = DATA_CONF;
    if (data && len && size > 0) {
        qi->buf = MALLOC(size);
        if (!qi->buf) {
            LOG(ERR, "Failed to allocate data buffer");
            cgw_queue_item_free(qi);
            return -1;
        }
        memcpy(qi->buf, data, size);
        qi->size = size;
    }
    cgw_response_t res = {0};
    if (!cgw_queue_put(&qi, &res)) {
        LOG(ERR, "Queue put failed: error=%u", res.error);
        if (qi) cgw_queue_item_free(qi);
        return -1;
    }
    return 0;
}

static int ubus_event_handler(struct ubus_context* ctx, struct ubus_object* obj,
                              struct ubus_request_data* req, const char* method,
                              struct blob_attr* msg) 
{
    (void)ctx;
    (void)obj;
    (void)req;
    (void)method;
    
    if (!msg) {
        return -1;
    }
    
    // === Define parsing policy ===
    enum {
        DATA,
        SIZE,
        __MAX
    };
    static const struct blobmsg_policy policy[__MAX] = {
        [DATA] = { .name = "data", .type = BLOBMSG_TYPE_UNSPEC },
        [SIZE] = { .name = "size", .type = BLOBMSG_TYPE_INT32 },
    };

    struct blob_attr *tb[__MAX];
    blobmsg_parse(policy, __MAX, tb, blob_data(msg), blob_len(msg));

    if (!tb[DATA] || !tb[SIZE]) {
        LOG(ERR, "Missing expected fields in message");
        return -1;
    }

    int size = blobmsg_get_u32(tb[SIZE]);
    void *data = blobmsg_data(tb[DATA]);
    int len = blobmsg_data_len(tb[DATA]);

    LOG(DEBUG, "Declared size: %d | Actual data length: %d", size, len);

    // SECURITY_FIX: Issue #1 - NULL pointer check
    if (!data) {
        LOG(ERR, "SECURITY_FIX: NULL data pointer in event_handler");
        return -1;
    }

    // SECURITY_FIX: Size validation
    if (size != len || size == 0 || size > MAX_UBUS_MESSAGE_SIZE) {
        LOG(ERR, "SECURITY_FIX: Invalid size in event_handler: declared=%d actual=%d", size, len);
        return -1;
    }

    // Enqueue into QM queue and signal MQTT worker
    cgw_item_t *qi = CALLOC(1, sizeof(cgw_item_t));
    if (!qi) {
        LOG(ERR, "Failed to allocate cgw_item_t");
        return -1;
    }
    
    // Fill request metadata
    qi->req.data_type = DATA_EVENT;
    if (data && len && size > 0) {
        qi->buf = MALLOC(size);
        if (!qi->buf) {
            LOG(ERR, "Failed to allocate data buffer");
            cgw_queue_item_free(qi);
            return -1;
        }
        memcpy(qi->buf, data, size);
        qi->size = size;
    }
    cgw_response_t res = {0};
    if (!cgw_queue_put(&qi, &res)) {
        LOG(ERR, "Queue put failed: error=%u", res.error);
        if (qi) cgw_queue_item_free(qi);
        return -1;
    }
    return 0;
}

static int ubus_netaction_handler(struct ubus_context* ctx, struct ubus_object* obj,
                                struct ubus_request_data* req, const char* method,
                                struct blob_attr* msg) 
{
    (void)ctx;
    (void)obj;
    (void)req;
    (void)msg;
    
    LOG(DEBUG, "Received ubus URGENT request '%s'", method);

    return 0;
}

static int ubus_netinfo_handler(struct ubus_context* ctx, struct ubus_object* obj,
                                struct ubus_request_data* req, const char* method,
                                struct blob_attr* msg) 
{
    (void)ctx;
    (void)obj;
    (void)req;
    (void)method;
    
    if (!msg) {
        return -1;
    }
    
    // === Define parsing policy ===
    enum {
        DATA,
        SIZE,
        __MAX
    };
    static const struct blobmsg_policy policy[__MAX] = {
        [DATA] = { .name = "data", .type = BLOBMSG_TYPE_UNSPEC },
        [SIZE] = { .name = "size", .type = BLOBMSG_TYPE_INT32 },
    };

    struct blob_attr *tb[__MAX];
    blobmsg_parse(policy, __MAX, tb, blob_data(msg), blob_len(msg));

    if (!tb[DATA] || !tb[SIZE]) {
        LOG(ERR, "Missing expected fields in netinfo message");
        return -1;
    }

    int size = blobmsg_get_u32(tb[SIZE]);
    void *data = blobmsg_data(tb[DATA]);
    int len = blobmsg_data_len(tb[DATA]);

    LOG(DEBUG, "netinfo: Declared size: %d | Actual data length: %d", size, len);

    // SECURITY_FIX: Issue #1 - NULL pointer check
    if (!data) {
        LOG(ERR, "SECURITY_FIX: NULL data pointer in netinfo_handler");
        return -1;
    }

    // SECURITY_FIX: Size validation
    if (size != len || size == 0 || size > MAX_UBUS_MESSAGE_SIZE) {
        LOG(ERR, "SECURITY_FIX: Invalid size in netinfo_handler: declared=%d actual=%d", size, len);
        return -1;
    }

    // Determine info event type for logging
    const char *msgtype_str = "unknown";
    if (data && len >= sizeof(info_event_type_t)) {
        // SECURITY_FIX: Issue #8 - Use memcpy for unaligned access
        info_event_type_t info_type;
        memcpy(&info_type, data, sizeof(info_type));
        switch (info_type) {
            case INFO_EVENT_CLIENT:
                msgtype_str = "client_info";
                break;
            case INFO_EVENT_VIF:
                msgtype_str = "vif_info";
                break;
            case INFO_EVENT_DEVICE:
                msgtype_str = "device_info";
                break;
            case INFO_EVENT_CLIENT_HISTORY:
                msgtype_str = "client_history";
                break;
            default:
                msgtype_str = "unknown_info";
                break;
        }
    }

    LOG(INFO, "NETEVD->CGWD: msgtype=%s msglen=%d", msgtype_str, size);

    // Enqueue into QM queue and signal MQTT worker
    cgw_item_t *qi = CALLOC(1, sizeof(cgw_item_t));
    if (!qi) {
        LOG(ERR, "Failed to allocate cgw_item_t");
        return -1;
    }
    
    // Fill request metadata
    qi->req.data_type = DATA_INFO_EVENT;
    if (data && len && size > 0) {
        qi->buf = MALLOC(size);
        if (!qi->buf) {
            LOG(ERR, "Failed to allocate data buffer");
            cgw_queue_item_free(qi);
            return -1;
        }
        memcpy(qi->buf, data, size);
        qi->size = size;
        LOG(DEBUG, "netinfo: Enqueued event size=%zu", qi->size);
    } else {
        LOG(ERR, "netinfo: Invalid data: data=%p len=%d size=%d", data, len, size);
        cgw_queue_item_free(qi);
        return -1;
    }
    cgw_response_t res = {0};
    if (!cgw_queue_put(&qi, &res)) {
        LOG(ERR, "Queue put failed: error=%u", res.error);
        if (qi) cgw_queue_item_free(qi);
        return -1;
    }
    LOG(DEBUG, "netinfo: Successfully enqueued info event");
    return 0;
}

static void ubus_io_cb(EV_P_ struct ev_io *w, int revents)
{
    if (!ctx)
        return;

    // Process ubus messages
    ubus_handle_event(ctx);
}

#if 0
static const ubus_method method_table[] = {
    {
        .name = "netstats",
        .handler = ubus_netstats_handler,
        .policy = NULL,
    },
    {
        .name = "netaction",
        .handler = ubus_netaction_handler,
        .policy = NULL,
    }
};
#endif

bool cgw_ubus_service_init()
{
    static struct ubus_object obj;
    static struct ubus_object_type obj_type = { .name = "cgw" };

    loop = EV_DEFAULT;
    ctx = ubus_connect(NULL);
    if (!ctx) {
        LOG(ERR, "Failed to connect to ubus");
        return false;
    }

    LOG(INFO, "Connected to ubus");

    obj.name = "cgwd";
    obj.type = &obj_type;
    // Ten methods, indices 0-9.
    static struct ubus_method methods[10];
    methods[0].name = "netstats";
    methods[0].handler = ubus_netstats_handler;
    methods[0].policy = NULL;
    methods[1].name = "netinfo";
    methods[1].handler = ubus_netinfo_handler;
    methods[1].policy = NULL;
    methods[2].name = "netaction";
    methods[2].handler = ubus_netaction_handler;
    methods[2].policy = NULL;
    methods[3].name = "get.cgwd.state";
    methods[3].handler = ubus_get_state_handler;
    methods[3].policy = NULL;
    methods[4].name = "cmdexec.event";
    methods[4].handler = ubus_event_handler;
    methods[4].policy = NULL;
    methods[5].name = "cmdexec.config";
    methods[5].handler = ubus_conf_handler;
    methods[5].policy = NULL;
    methods[6].name = "status";
    methods[6].handler = ubus_status_handler;
    methods[6].policy = NULL;
    methods[7].name = "registration.start";
    methods[7].handler = ubus_registration_start_handler;
    methods[7].policy = NULL;
    methods[8].name = "registration.cancel";
    methods[8].handler = ubus_registration_cancel_handler;
    methods[8].policy = registration_cancel_policy;
    methods[8].n_policy = __REG_CANCEL_MAX;
    methods[9].name = "mqtt.reconnect";
    methods[9].handler = ubus_mqtt_reconnect_handler;
    methods[9].policy = NULL;
    obj.methods = methods;
    obj.n_methods = 10;

    ev_async_init(&registration_result_watcher, registration_result_cb);
    ev_async_start(loop, &registration_result_watcher);

    if (ubus_add_object(ctx, &obj) != 0) {
        ev_async_stop(loop, &registration_result_watcher);
        LOG(ERR, "Failed to add ubus object");
        ubus_free(ctx);
        ctx = NULL;
        return false;
    }

    // Get the ubus socket FD
    int fd = ctx->sock.fd;
    if (fd < 0) {
        LOG(ERR, "Invalid ubus fd");
        ev_async_stop(loop, &registration_result_watcher);
        ubus_free(ctx);
        ctx = NULL;
        return false;
    }

    // Register libev watcher for ubus socket
    ev_io_init(&ubus_watcher, ubus_io_cb, fd, EV_READ);
    ev_io_start(loop, &ubus_watcher);

    LOG(INFO, "UBus integrated with libev loop");

    return true;
}

void cgw_ubus_service_cleanup(void)
{
    /* ------------------ CLEANUP ------------------ */

    {
        cgw_registration_attempt_snapshot_t snapshot;
        pthread_t thread;
        bool join = false;
        cgw_registration_attempt_snapshot(&snapshot);
        if (cgw_registration_attempt_is_cancellable(snapshot.attempt_id))
            cgw_registration_attempt_cancel(snapshot.attempt_id);
        pthread_mutex_lock(&registration_worker_lock);
        if (registration_worker_created) {
            thread = registration_worker_thread;
            registration_worker_created = false;
            join = true;
        }
        pthread_mutex_unlock(&registration_worker_lock);
        if (join)
            pthread_join(thread, NULL);
    }
    if (loop) {
        ev_async_stop(loop, &registration_result_watcher);
        ev_io_stop(loop, &ubus_watcher);
    }

    if (ctx) {
        ubus_free(ctx);
        ctx = NULL;
    }
}

