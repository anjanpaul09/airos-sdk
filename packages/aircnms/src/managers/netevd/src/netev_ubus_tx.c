#include <libubus.h>
#include <libubox/blobmsg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "info_events.h"

/* Shared ubus context */
static struct ubus_context *g_netev_ubus_ctx = NULL;

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

    if (!g_netev_ubus_ctx) {
        LOG(ERR, "UBus context not initialized");
        return -1;
    }

    ret = ubus_lookup_id(g_netev_ubus_ctx, object, &id);
    if (ret) {
        LOG(ERR, "Failed to find object '%s': %s", object, ubus_strerror(ret));
        return ret;
    }

    LOG(DEBUG, "Calling %s.%s", object, method);
    ret = ubus_invoke(g_netev_ubus_ctx, id, method,
                      b ? b->head : NULL,
                      response_callback, NULL, 3000);

    if (ret) {
        LOG(ERR, "ubus_invoke failed: %s", ubus_strerror(ret));
    }

    return ret;
}

/* Publish info event to cgwd via netinfo method */
void netev_publish_info_event(void *buf, size_t size)
{
    if (!buf || size == 0) {
        LOG(ERR, "Invalid parameters in netev_publish_info_event");
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
bool netev_ubus_tx_service_init(void)
{
    if (g_netev_ubus_ctx) {
        LOG(DEBUG, "UBus context already initialized");
        return true;
    }

    g_netev_ubus_ctx = ubus_connect(NULL);
    if (!g_netev_ubus_ctx) {
        LOG(ERR, "Failed to connect to ubus");
        return false;
    }

    LOG(INFO, "netevd: Connected to ubus for TX");
    return true;
}

/* Cleanup ubus TX service */
void netev_ubus_tx_service_cleanup(void)
{
    if (g_netev_ubus_ctx) {
        ubus_free(g_netev_ubus_ctx);
        g_netev_ubus_ctx = NULL;
    }
}

