#include <libubus.h>
#include <libubox/blobmsg_json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "netstats.h"
#include "log.h"

static struct ubus_context *ctx = NULL;

/* ---------------------------------------------------
 * Helper: callback for ubus responses
 * --------------------------------------------------- */
static void response_callback(struct ubus_request *req, int type, struct blob_attr *msg)
{
    if (!msg) {
        LOG(DEBUG, "No response received");
        return;
    }

    char *str = blobmsg_format_json(msg, true);
    if (str) {
        LOG(DEBUG, "Response: %s", str);
        free(str);
    }
}

/* ---------------------------------------------------
 * Helper: call a ubus method
 * --------------------------------------------------- */
static int call_ubus_method(const char *object, const char *method, struct blob_buf *b)
{
    uint32_t id;
    int ret;

    if (!ctx) {
        LOG(ERR, "UBus context not initialized");
        return -1;
    }

    ret = ubus_lookup_id(ctx, object, &id);
    if (ret) {
        LOG(ERR, "Failed to find object '%s': %s", object, ubus_strerror(ret));
        return ret;
    }

    LOG(DEBUG, "Calling %s.%s", object, method);
    ret = ubus_invoke(ctx, id, method,
                      b ? b->head : NULL,
                      response_callback, NULL, 3000);

    if (ret) {
        LOG(ERR, "ubus_invoke failed: %s", ubus_strerror(ret));
    }

    return ret;
}

/* ---------------------------------------------------
 * Method 1: netstats (no args)
 * --------------------------------------------------- */
void netstats_publish_stats(netstats_item_t *qi)
{
    if (!qi || !qi->buf || qi->size == 0) {
        LOG(ERR, "Invalid netstats_item_t in netstats_publish_stats");
        return;
    }

    struct blob_buf b = {};
    blob_buf_init(&b, 0);
    
    blobmsg_add_field(&b, BLOBMSG_TYPE_UNSPEC, "data", qi->buf, qi->size);
    blobmsg_add_u32(&b, "size", qi->size);

    call_ubus_method("cgwd", "netstats", &b);

    blob_buf_free(&b);
}

/* ---------------------------------------------------
 * Method 2: netaction (with JSON args)
 * --------------------------------------------------- */
#if 0  // Test function - disabled but kept for reference
static void test_netaction(void)
{
    struct blob_buf b = {};
    blob_buf_init(&b, 0);

    blobmsg_add_string(&b, "iface", "br-lan");
    blobmsg_add_string(&b, "action", "restart");

    call_ubus_method("cgwd", "netaction", &b);
    blob_buf_free(&b);
}
#endif

/* ---------------------------------------------------
 * Method 3: get_state (no args)
 * --------------------------------------------------- */
void test_get_state(void)
{
    call_ubus_method("cgwd", "get_state", NULL);
}

/* ---------------------------------------------------
 * Main
 * --------------------------------------------------- */
bool netstats_ubus_tx_service_init()
{
    ctx = ubus_connect(NULL);
    if (!ctx) {
        LOG(ERR, "Failed to connect to ubus");
        return false;
    }

    LOG(INFO, "Connected to ubus");

    return true;
}

void netstats_ubus_tx_service_cleanup()
{
    if (ctx) {
        ubus_free(ctx);
        ctx = NULL;
    }
}
