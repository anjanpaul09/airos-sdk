#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <libubox/uloop.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>

#include "libeventd.h"
#include "eventd_internal.h"
#include "log.h"

static struct ubus_context *g_ubus_ctx;

bool eventd_ubus_is_ready(void)
{
    return g_ubus_ctx != NULL;
}

static void eventd_ubus_result_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    char *str;

    (void)req;
    (void)type;

    if (!msg)
        return;

    str = blobmsg_format_json(msg, true);
    if (str) {
        LOG(DEBUG, "eventd ubus response: %s", str);
        free(str);
    }
}

static int eventd_ubus_invoke(const char *method, struct blob_buf *b)
{
    uint32_t id;
    int ret;

    if (!method || !b) {
        LOG(ERR, "eventd: invalid ubus invoke parameters");
        return -EINVAL;
    }

    if (!g_ubus_ctx) {
        LOG(ERR, "eventd: ubus not initialized");
        return -ENODEV;
    }

    ret = ubus_lookup_id(g_ubus_ctx, EVENTD_UBUS_SERVICE, &id);
    if (ret) {
        LOG(ERR, "eventd: failed to lookup %s: %s",
            EVENTD_UBUS_SERVICE, ubus_strerror(ret));
        return ret;
    }

    ret = ubus_invoke(g_ubus_ctx, id, method, b->head,
                      eventd_ubus_result_cb, NULL, EVENTD_UBUS_TIMEOUT_MS);
    if (ret) {
        LOG(ERR, "eventd: failed to invoke %s: %s", method, ubus_strerror(ret));
        return ret;
    }

    return 0;
}

int eventd_lib_init(void)
{
    if (g_ubus_ctx)
        return 0;

    g_ubus_ctx = ubus_connect(NULL);
    if (!g_ubus_ctx) {
        LOG(ERR, "eventd: failed to connect to ubus");
        return -ENODEV;
    }

    if (g_ubus_ctx->sock.fd < 0) {
        LOG(ERR, "eventd: invalid ubus socket fd");
        ubus_free(g_ubus_ctx);
        g_ubus_ctx = NULL;
        return -ENODEV;
    }

    return 0;
}

void eventd_lib_cleanup(void)
{
    if (g_ubus_ctx) {
        ubus_free(g_ubus_ctx);
        g_ubus_ctx = NULL;
    }
}

bool eventd_mqtt_publish(size_t mlen, const void *mbuf)
{
    struct blob_buf b = {};
    int ret;
    bool success = false;

    if (!mbuf || mlen == 0) {
        LOG(ERR, "eventd: invalid message buffer or length");
        return false;
    }

    blob_buf_init(&b, 0);

    if (blobmsg_add_field(&b, BLOBMSG_TYPE_UNSPEC, "data", mbuf, mlen) != 0) {
        LOG(ERR, "eventd: failed to add data field to blob");
        goto cleanup;
    }

    if (blobmsg_add_u32(&b, "size", (uint32_t)mlen) != 0) {
        LOG(ERR, "eventd: failed to add size field to blob");
        goto cleanup;
    }

    if (blobmsg_add_u32(&b, "type", 1) != 0) {
        LOG(ERR, "eventd: failed to add type field to blob");
        goto cleanup;
    }

    ret = eventd_ubus_invoke(EVENTD_CMDEXEC_METHOD, &b);
    if (ret != 0) {
        LOG(ERR, "eventd: cmdexec.event invoke failed: %d", ret);
        goto cleanup;
    }

    success = true;
    LOG(DEBUG, "eventd: published MQTT message (size: %zu)", mlen);

cleanup:
    blob_buf_free(&b);
    return success;
}
