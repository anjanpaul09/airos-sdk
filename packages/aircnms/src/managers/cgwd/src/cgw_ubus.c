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
#include <zlib.h>
#include "cgw.h"
#include "report.h"
#include "cgw_state_mgr.h"
#include "info_events.h"
#include "log.h"

static struct ubus_context *ctx = NULL;
static struct ev_loop *loop = NULL;
static ev_io ubus_watcher;

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

    loop = EV_DEFAULT;
    ctx = ubus_connect(NULL);
    if (!ctx) {
        LOG(ERR, "Failed to connect to ubus");
        return false;
    }

    LOG(INFO, "Connected to ubus");

    obj.name = "cgwd";
    obj.type = &(struct ubus_object_type){.name = "cgw"};
    // Array size should be 6 to hold 6 methods (indices 0-5)
    static struct ubus_method methods[6];
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
    obj.methods = methods;
    obj.n_methods = 6;

    if (ubus_add_object(ctx, &obj) != 0) {
        LOG(ERR, "Failed to add ubus object");
        ubus_free(ctx);
        ctx = NULL;
        return false;
    }

    // Get the ubus socket FD
    int fd = ctx->sock.fd;
    if (fd < 0) {
        LOG(ERR, "Invalid ubus fd");
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

    if (loop) {
        ev_io_stop(loop, &ubus_watcher);
    }
    
    if (ctx) {
        ubus_free(ctx);
        ctx = NULL;
    }
}

