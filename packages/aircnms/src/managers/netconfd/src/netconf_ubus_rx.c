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
#include <stdint.h>
#include "netconf.h"

static struct ubus_context *ctx = NULL;
static struct ev_loop *loop = NULL;
static ev_io ubus_watcher;

#define IPC_BUFFER_SIZE 8064
#define MAX_UBUS_METHODS 2

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

enum {
    RL_INTERFACE,
    RL_INTERFACE_UPLINK,
    RL_INTERFACE_DOWNLINK,
    __RL_INTERFACE_MAX
};

enum {
    RL_CLIENT_MAC,
    RL_CLIENT_UPLINK,
    RL_CLIENT_DOWNLINK,
    __RL_CLIENT_MAX
};

static const struct blobmsg_policy rl_interface_policy[__RL_INTERFACE_MAX] = {
    [RL_INTERFACE] = { .name = "interface", .type = BLOBMSG_TYPE_STRING },
    [RL_INTERFACE_UPLINK] = { .name = "uplink", .type = BLOBMSG_TYPE_INT32 },
    [RL_INTERFACE_DOWNLINK] = { .name = "downlink", .type = BLOBMSG_TYPE_INT32 },
};

static const struct blobmsg_policy rl_client_policy[__RL_CLIENT_MAX] = {
    [RL_CLIENT_MAC] = { .name = "mac", .type = BLOBMSG_TYPE_STRING },
    [RL_CLIENT_UPLINK] = { .name = "uplink", .type = BLOBMSG_TYPE_INT32 },
    [RL_CLIENT_DOWNLINK] = { .name = "downlink", .type = BLOBMSG_TYPE_INT32 },
};

static bool parse_macaddr(const char *macstr, uint8_t mac[6])
{
    unsigned int octets[6];

    if (!macstr)
        return false;

    if (sscanf(macstr, "%02x:%02x:%02x:%02x:%02x:%02x",
               &octets[0], &octets[1], &octets[2],
               &octets[3], &octets[4], &octets[5]) != 6) {
        return false;
    }

    for (int i = 0; i < 6; i++) {
        if (octets[i] > 0xff)
            return false;
        mac[i] = (uint8_t)octets[i];
    }

    return true;
}

static int rl_rate_from_attr(struct blob_attr *attr)
{
    return attr ? (int)blobmsg_get_u32(attr) : 0;
}

static int ubus_reply_rate_limit(struct ubus_context *ctx,
                                 struct ubus_request_data *req,
                                 bool success,
                                 const char *target_type,
                                 const char *target,
                                 int uplink,
                                 int downlink,
                                 const char *message)
{
    struct blob_buf b = {0};

    blob_buf_init(&b, 0);
    blobmsg_add_u8(&b, "success", success);
    blobmsg_add_string(&b, "targetType", target_type);
    blobmsg_add_string(&b, "target", target ? target : "");
    blobmsg_add_u32(&b, "uplink", uplink);
    blobmsg_add_u32(&b, "downlink", downlink);
    blobmsg_add_string(&b, "message", message);
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);

    return UBUS_STATUS_OK;
}

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

    // Log message received
    LOG(INFO, "MSG_RECV type=CONF msglen=%d", size);

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

    // Log message received
    LOG(INFO, "MSG_RECV type=ACL msglen=%d", size);

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

    // Log message received
    LOG(INFO, "MSG_RECV type=RL msglen=%d", size);

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

static int ubus_netconf_rl_interface_handler(struct ubus_context *ctx,
                                             struct ubus_object *obj,
                                             struct ubus_request_data *req,
                                             const char *method,
                                             struct blob_attr *msg)
{
    struct blob_attr *tb[__RL_INTERFACE_MAX];
    const char *ifname;
    int uplink;
    int downlink;
    bool success;

    (void)obj;
    (void)method;

    if (!msg)
        return UBUS_STATUS_INVALID_ARGUMENT;

    blobmsg_parse(rl_interface_policy, __RL_INTERFACE_MAX, tb,
                  blob_data(msg), blob_len(msg));

    if (!tb[RL_INTERFACE]) {
        return ubus_reply_rate_limit(ctx, req, false, "interface", "",
                                     0, 0, "missing interface");
    }

    ifname = blobmsg_get_string(tb[RL_INTERFACE]);
    uplink = rl_rate_from_attr(tb[RL_INTERFACE_UPLINK]);
    downlink = rl_rate_from_attr(tb[RL_INTERFACE_DOWNLINK]);

    if (uplink < 0 || downlink < 0) {
        return ubus_reply_rate_limit(ctx, req, false, "interface", ifname,
                                     uplink, downlink, "rate must be >= 0");
    }

    success = air_ifname_rate_limit((char *)ifname, uplink, downlink);
    return ubus_reply_rate_limit(ctx, req, success, "interface", ifname,
                                 uplink, downlink,
                                 success ? "applied" : "failed");
}

static int ubus_netconf_rl_client_handler(struct ubus_context *ctx,
                                          struct ubus_object *obj,
                                          struct ubus_request_data *req,
                                          const char *method,
                                          struct blob_attr *msg)
{
    struct blob_attr *tb[__RL_CLIENT_MAX];
    const char *macstr;
    uint8_t mac[6];
    int uplink;
    int downlink;
    bool success;

    (void)obj;
    (void)method;

    if (!msg)
        return UBUS_STATUS_INVALID_ARGUMENT;

    blobmsg_parse(rl_client_policy, __RL_CLIENT_MAX, tb,
                  blob_data(msg), blob_len(msg));

    if (!tb[RL_CLIENT_MAC]) {
        return ubus_reply_rate_limit(ctx, req, false, "client", "",
                                     0, 0, "missing mac");
    }

    macstr = blobmsg_get_string(tb[RL_CLIENT_MAC]);
    uplink = rl_rate_from_attr(tb[RL_CLIENT_UPLINK]);
    downlink = rl_rate_from_attr(tb[RL_CLIENT_DOWNLINK]);

    if (!parse_macaddr(macstr, mac)) {
        return ubus_reply_rate_limit(ctx, req, false, "client", macstr,
                                     uplink, downlink, "invalid mac");
    }

    if (uplink < 0 || downlink < 0) {
        return ubus_reply_rate_limit(ctx, req, false, "client", macstr,
                                     uplink, downlink, "rate must be >= 0");
    }

    success = air_user_rate_limit(mac, uplink, downlink);
    return ubus_reply_rate_limit(ctx, req, success, "client", macstr,
                                 uplink, downlink,
                                 success ? "applied" : "failed");
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
    static struct ubus_object_type object_type;

    loop = EV_DEFAULT;
    ctx = ubus_connect(NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to connect to ubus\n");
        return false;
    }

    printf("Connected to ubus\n");

    obj.name = "netconfd";
    object_type.name = "netconfd";
    obj.type = &object_type;
    static struct ubus_method methods[5];
    methods[0].name = "set.cgwd.conf";            // cloud config
    methods[0].handler = ubus_netconf_config_handler;
    methods[0].policy = NULL;
    methods[0].n_policy = 0;
    methods[1].name = "set.cgwd.acl";             // acl
    methods[1].handler = ubus_netconf_acl_handler;
    methods[1].policy = NULL;
    methods[1].n_policy = 0;
    methods[2].name = "set.cgwd.rl";              // ratelimit
    methods[2].handler = ubus_netconf_rl_handler;
    methods[2].policy = NULL;
    methods[2].n_policy = 0;
    methods[3].name = "rate.limit.interface";
    methods[3].handler = ubus_netconf_rl_interface_handler;
    methods[3].policy = rl_interface_policy;
    methods[3].n_policy = ARRAY_SIZE(rl_interface_policy);
    methods[4].name = "rate.limit.client";
    methods[4].handler = ubus_netconf_rl_client_handler;
    methods[4].policy = rl_client_policy;
    methods[4].n_policy = ARRAY_SIZE(rl_client_policy);
    object_type.methods = methods;
    object_type.n_methods = ARRAY_SIZE(methods);
    obj.methods = methods;
    obj.n_methods = ARRAY_SIZE(methods);

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
