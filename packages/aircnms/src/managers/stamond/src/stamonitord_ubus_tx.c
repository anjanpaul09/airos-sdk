#include <libubus.h>
#include <libubox/blobmsg.h>
#include <ev.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "stamonitord.h"
#include "log.h"
#include "info_events.h"
#include "stamonitord_history.h"
#include "dhcp_fp.h"

/* Shared ubus context */
static struct ubus_context *g_stamonitord_ubus_ctx = NULL;
static struct ev_io g_stamonitord_ubus_watcher;
static struct ubus_object g_stamonitord_ubus_object;
static bool g_stamonitord_ubus_object_added = false;

enum {
    CLIENT_IDENTITY_MACADDR,
    __CLIENT_IDENTITY_MAX
};

static const struct blobmsg_policy client_identity_policy[__CLIENT_IDENTITY_MAX] = {
    [CLIENT_IDENTITY_MACADDR] = { .name = "macaddr", .type = BLOBMSG_TYPE_STRING },
};

static bool parse_macaddr(const char *macaddr_str, uint8_t macaddr[6])
{
    unsigned int b[6];

    if (!macaddr_str || !macaddr)
        return false;

    if (sscanf(macaddr_str, "%02x:%02x:%02x:%02x:%02x:%02x",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
        return false;

    for (int i = 0; i < 6; i++) {
        if (b[i] > 0xff)
            return false;
        macaddr[i] = (uint8_t)b[i];
    }

    return true;
}

static int ubus_client_identity_handler(struct ubus_context *ctx,
                                        struct ubus_object *obj,
                                        struct ubus_request_data *req,
                                        const char *method,
                                        struct blob_attr *msg)
{
    struct blob_attr *tb[__CLIENT_IDENTITY_MAX];
    uint8_t macaddr[6] = {0};
    char ipaddr[IPADDR_MAX_LEN] = {0};
    char hostname[HOSTNAME_MAX_LEN] = {0};
    char dhcp_options[128] = {0};
    char dhcp_vendor[64] = {0};
    char osinfo[256] = "unknown";
    struct blob_buf b = {};
    bool found;

    (void)obj;
    (void)method;

    blobmsg_parse(client_identity_policy, __CLIENT_IDENTITY_MAX, tb,
                  blob_data(msg), blob_len(msg));

    if (!tb[CLIENT_IDENTITY_MACADDR] ||
        !parse_macaddr(blobmsg_get_string(tb[CLIENT_IDENTITY_MACADDR]), macaddr)) {
        return UBUS_STATUS_INVALID_ARGUMENT;
    }

    found = stamonitord_history_lookup_client_identity(macaddr,
                                                       ipaddr,
                                                       sizeof(ipaddr),
                                                       hostname,
                                                       sizeof(hostname),
                                                       dhcp_options,
                                                       sizeof(dhcp_options),
                                                       dhcp_vendor,
                                                       sizeof(dhcp_vendor));

    if (!found)
        return UBUS_STATUS_NOT_FOUND;

    if (dhcp_options[0]) {
        char *os_info = get_os_info(dhcp_options,
                                    dhcp_vendor[0] ? dhcp_vendor : NULL);
        if (os_info && os_info[0])
            snprintf(osinfo, sizeof(osinfo), "%s", os_info);
    }

    blob_buf_init(&b, 0);
    blobmsg_add_string(&b, "hostname", hostname[0] ? hostname : "unknown");
    blobmsg_add_string(&b, "ipAddress", ipaddr[0] ? ipaddr : "0.0.0.0");
    blobmsg_add_string(&b, "osInfo", osinfo);
    blobmsg_add_string(&b, "clientType", "wireless");
    blobmsg_add_u8(&b, "found", true);
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);

    return UBUS_STATUS_OK;
}

static void ubus_io_cb(EV_P_ struct ev_io *w, int revents)
{
    (void)loop;
    (void)w;
    (void)revents;

    if (g_stamonitord_ubus_ctx)
        ubus_handle_event(g_stamonitord_ubus_ctx);
}

static bool stamonitord_register_ubus_object(void)
{
    static struct ubus_method methods[] = {
        UBUS_METHOD("client.identity", ubus_client_identity_handler, client_identity_policy),
    };
    static struct ubus_object_type object_type =
        UBUS_OBJECT_TYPE("stamond", methods);

    g_stamonitord_ubus_object.name = "stamond";
    g_stamonitord_ubus_object.type = &object_type;
    g_stamonitord_ubus_object.methods = methods;
    g_stamonitord_ubus_object.n_methods = sizeof(methods) / sizeof(methods[0]);

    if (ubus_add_object(g_stamonitord_ubus_ctx, &g_stamonitord_ubus_object) != 0) {
        LOG(ERR, "Failed to add stamond ubus object");
        return false;
    }

    g_stamonitord_ubus_object_added = true;

    if (g_stamonitord_ubus_ctx->sock.fd < 0) {
        LOG(ERR, "Invalid stamond ubus fd");
        return false;
    }

    ev_io_init(&g_stamonitord_ubus_watcher, ubus_io_cb,
               g_stamonitord_ubus_ctx->sock.fd, EV_READ);
    ev_io_start(EV_DEFAULT, &g_stamonitord_ubus_watcher);

    return true;
}

/* Helper: callback for ubus responses */
static void response_callback(struct ubus_request *req, int type, struct blob_attr *msg)
{
    (void)req;
    (void)type;
    if (!msg) {
        LOG(DEBUG, "No response received");
        return;
    }
    // Response handling if needed
}

/* Helper: call a ubus method */
static int call_ubus_method(const char *object, const char *method, struct blob_buf *b)
{
    uint32_t id;
    int ret;

    if (!g_stamonitord_ubus_ctx) {
        LOG(ERR, "UBus context not initialized");
        return -1;
    }

    ret = ubus_lookup_id(g_stamonitord_ubus_ctx, object, &id);
    if (ret) {
        LOG(ERR, "Failed to find object '%s': %s", object, ubus_strerror(ret));
        return ret;
    }

    LOG(DEBUG, "Calling %s.%s", object, method);
    ret = ubus_invoke(g_stamonitord_ubus_ctx, id, method,
                      b ? b->head : NULL,
                      response_callback, NULL, 3000);

    if (ret) {
        LOG(ERR, "ubus_invoke failed: %s", ubus_strerror(ret));
    }

    return ret;
}

/* Publish info event to cgwd via netinfo method */
void stamonitord_publish_info_event(void *buf, size_t size)
{
    int online_status;
    
    // Check if we're online before attempting
    online_status = air_check_online_status();
    if (!online_status) {
        LOG(INFO, "AIRCNMS status is offline, Stamonitord skipping info");
        return;
    }

    if (!buf || size == 0) {
        LOG(ERR, "Invalid parameters in stamonitord_publish_info_event");
        return;
    }

    // Log event type for debugging
    if (size >= sizeof(info_event_type_t)) {
        info_event_type_t event_type = *(info_event_type_t *)buf;
        LOG(INFO, "Publishing info event type=%d size=%zu to cgwd.netinfo", event_type, size);
    } else {
        LOG(ERR, "Event buffer too small: size=%zu", size);
        return;
    }

    struct blob_buf b = {};
    blob_buf_init(&b, 0);
    
    blobmsg_add_field(&b, BLOBMSG_TYPE_UNSPEC, "data", buf, size);
    blobmsg_add_u32(&b, "size", size);

    int ret = call_ubus_method("cgwd", "netinfo", &b);
    if (ret != 0) {
        LOG(ERR, "Failed to send info event to cgwd.netinfo: %d", ret);
    } else {
        LOG(DEBUG, "Successfully sent info event to cgwd.netinfo");
    }

    blob_buf_free(&b);
}

/* Initialize ubus TX service */
bool stamonitord_ubus_tx_service_init(void)
{
    if (g_stamonitord_ubus_ctx) {
        LOG(DEBUG, "UBus context already initialized");
        return true;
    }

    g_stamonitord_ubus_ctx = ubus_connect(NULL);
    if (!g_stamonitord_ubus_ctx) {
        LOG(ERR, "Failed to connect to ubus");
        return false;
    }

    if (!stamonitord_register_ubus_object()) {
        ubus_free(g_stamonitord_ubus_ctx);
        g_stamonitord_ubus_ctx = NULL;
        return false;
    }

    LOG(INFO, "stamonitord: Connected to ubus");
    return true;
}

/* Cleanup ubus TX service */
void stamonitord_ubus_tx_service_cleanup(void)
{
    if (g_stamonitord_ubus_ctx) {
        ev_io_stop(EV_DEFAULT, &g_stamonitord_ubus_watcher);
        if (g_stamonitord_ubus_object_added) {
            ubus_remove_object(g_stamonitord_ubus_ctx, &g_stamonitord_ubus_object);
            g_stamonitord_ubus_object_added = false;
        }
        ubus_free(g_stamonitord_ubus_ctx);
        g_stamonitord_ubus_ctx = NULL;
    }
}
