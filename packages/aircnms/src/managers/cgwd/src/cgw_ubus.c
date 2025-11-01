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
#include "cgw.h"
#include "report.h"
#include "unixcomm.h"
#include "cgw_state_mgr.h"
#include "log.h"

static struct ubus_context *ctx = NULL;
static struct ev_loop *loop = NULL;
static ev_io ubus_watcher;

#define IPC_BUFFER_SIZE 8064
#define MAX_UBUS_METHODS 2

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

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
                unixcomm_log_error("Queue put failed: error=%u", res.error);
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
    // Fix: Array size should be 5 to hold 5 methods (indices 0-4)
    static struct ubus_method methods[5];
    methods[0].name = "netstats";
    methods[0].handler = ubus_netstats_handler;
    methods[0].policy = NULL;
    methods[1].name = "netaction";
    methods[1].handler = ubus_netaction_handler;
    methods[1].policy = NULL;
    methods[2].name = "get.cgwd.state";
    methods[2].handler = ubus_get_state_handler;
    methods[2].policy = NULL;
    methods[3].name = "cmdexec.event";
    methods[3].handler = ubus_event_handler;
    methods[3].policy = NULL;
    methods[4].name = "cmdexec.config";
    methods[4].handler = ubus_conf_handler;
    methods[4].policy = NULL;
    obj.methods = methods;
    obj.n_methods = 5;

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

