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
#include "netconf.h"

static struct ubus_context *ctx = NULL;
static struct ev_loop *loop = NULL;
static ev_io ubus_watcher;

#define IPC_BUFFER_SIZE 8064
#define MAX_UBUS_METHODS 2

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

static int ubus_netconf_config_handler(struct ubus_context* ctx, struct ubus_object* obj,
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
        [SIZE] = { .name = "size", .type = BLOBMSG_TYPE_INT32 }
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

    printf("  📦 Declared size: %d | Actual data length: %d\n",
                size, len);

        // Enqueue into QM queue and signal MQTT worker
        netconf_item_t *qi = CALLOC(1, sizeof(netconf_item_t));
        if (!qi) {
            return -1;
        }

        // Fill request metadata
        qi->req.data_type = NETCONF_DATA_CONF;
        if (data && len) {
            qi->buf = MALLOC(size);
            if (!qi->buf) {
                netconf_queue_item_free(qi);
            }
            memcpy(qi->buf, data, size);
            qi->size = size;
        }
        {
            netconf_response_t res = {0};
            if (!netconf_queue_put(&qi, &res)) {
                if (qi) netconf_queue_item_free(qi);
            }
        }
    return 0;
}

static int ubus_netconf_acl_handler(struct ubus_context* ctx, struct ubus_object* obj,
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
        [SIZE] = { .name = "size", .type = BLOBMSG_TYPE_INT32 }
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

    printf("  📦 Declared size: %d | Actual data length: %d\n",
                size, len);

        // Enqueue into QM queue and signal MQTT worker
        netconf_item_t *qi = CALLOC(1, sizeof(netconf_item_t));
        if (!qi) {
            LOG(ERR, "Failed to allocate netconf_item_t");
            return -1;
        }

        // Fill request metadata
        qi->req.data_type = NETCONF_DATA_ACL;
        if (data && len) {
            qi->buf = MALLOC(size);
            if (!qi->buf) {
                unixcomm_log_error("Failed to allocate data buffer");
                netconf_queue_item_free(qi);
            }
            memcpy(qi->buf, data, size);
            qi->size = size;
        }
        {
            netconf_response_t res = {0};
            if (!netconf_queue_put(&qi, &res)) {
                unixcomm_log_error("Queue put failed: error=%u", res.error);
                if (qi) netconf_queue_item_free(qi);
            }
        }
    return 0;
}

static int ubus_netconf_rl_handler(struct ubus_context* ctx, struct ubus_object* obj,
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
        [SIZE] = { .name = "size", .type = BLOBMSG_TYPE_INT32 }
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

    printf("  📦 Declared size: %d | Actual data length: %d\n",
                size, len);

        // Enqueue into QM queue and signal MQTT worker
        netconf_item_t *qi = CALLOC(1, sizeof(netconf_item_t));
        if (!qi) {
            LOG(ERR, "Failed to allocate netconf_item_t");
            return -1;
        }

        // Fill request metadata
        qi->req.data_type = NETCONF_DATA_RL;
        if (data && len) {
            qi->buf = MALLOC(size);
            if (!qi->buf) {
                netconf_queue_item_free(qi);
            }
            memcpy(qi->buf, data, size);
            qi->size = size;
        }
        {
            netconf_response_t res = {0};
            if (!netconf_queue_put(&qi, &res)) {
                if (qi) netconf_queue_item_free(qi);
            }
        }
    return 0;
}


static void ubus_io_cb(EV_P_ struct ev_io *w, int revents)
{
    if (!ctx)
        return;

    // Process ubus messages
    ubus_handle_event(ctx);
}

bool netconf_ubus_service_init()
{
    static struct ubus_object obj;

    loop = EV_DEFAULT;
    ctx = ubus_connect(NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to connect to ubus\n");
        return false;
    }

    printf("Connected to ubus\n");

    obj.name = "netconfd";
    obj.type = &(struct ubus_object_type){.name = "netconfd"};
    static struct ubus_method methods[4];
    methods[0].name = "set.cgwd.conf";            // cloud config
    methods[0].handler = ubus_netconf_config_handler;
    methods[0].policy = NULL;
    methods[1].name = "set.cgwd.acl";             // acl
    methods[1].handler = ubus_netconf_acl_handler;
    methods[1].policy = NULL;
    methods[2].name = NULL;
    methods[2].name = "set.cgwd.rl";              // ratelimit
    methods[2].handler = ubus_netconf_rl_handler;
    methods[2].policy = NULL;
    obj.methods = methods;
    obj.n_methods = 3;

    if (ubus_add_object(ctx, &obj) != 0) {
        fprintf(stderr, "Failed to add ubus object\n");
        ubus_free(ctx);
        ctx = NULL;
        return false;
    }

    // Get the ubus socket FD
    int fd = ctx->sock.fd;
    if (fd < 0) {
        fprintf(stderr, "Invalid ubus fd\n");
        return false;
    }

    // Register libev watcher for ubus socket
    ev_io_init(&ubus_watcher, ubus_io_cb, fd, EV_READ);
    ev_io_start(loop, &ubus_watcher);

    printf("UBus integrated with libev loop ✅\n");

    return true;
}

void netconf_ubus_service_cleanup(void)
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

