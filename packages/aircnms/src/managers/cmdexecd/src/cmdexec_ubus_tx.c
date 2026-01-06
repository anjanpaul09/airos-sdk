#include <libubox/uloop.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>
#include <ev.h>
#include <stdio.h>
#include <string.h>
#include "cmdexec.h"

static struct ubus_context *ctx = NULL;

// Callback function to handle the response
static void call_result_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    char *str;
    
    if (!msg) {
        printf("No response received\n");
        return;
    }
    
    str = blobmsg_format_json(msg, true);
    printf("Response: %s\n", str);
    free(str);
}

/**
 * Call a method on the cmdexecd ubus service
 * @param method Method name to invoke
 * @param b Blob buffer containing parameters
 * @return 0 on success, negative error code on failure
 */
int call_cmdexec_method(const char *method, struct blob_buf *b) {
    uint32_t id;
    int ret;

    // Validate inputs
    if (!method || !b) {
        LOG(ERR, "Invalid parameters to call_cmdexec_method");
        return -EINVAL;
    }

    if (!ctx) {
        LOG(ERR, "UBus context not initialized");
        return -ENODEV;
    }

    // Lookup service
    ret = ubus_lookup_id(ctx, "cgwd", &id);
    if (ret) {
        LOG(ERR, "Failed to lookup %s", ubus_strerror(ret));
        return ret;
    }

    // Synchronous invoke with timeout
    ret = ubus_invoke(ctx, id, method, b->head, call_result_cb, NULL, UBUS_TIMEOUT_MS);
    if (ret) {
        LOG(ERR, "Failed to invoke %s: %s", method, ubus_strerror(ret));
        return ret;
    }

    return 0;
}

bool cmdexec_ubus_tx_service_init()
{

    ctx = ubus_connect(NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to connect to ubus\n");
        return false;
    }

    // Get the ubus socket FD
    int fd = ctx->sock.fd;
    if (fd < 0) {
        fprintf(stderr, "Invalid ubus fd\n");
        return false;
    }
    
    return true;
}

void cmdexec_ubus_tx_service_cleanup(void)
{
    /* ------------------ CLEANUP ------------------ */

    if (ctx) {
        ubus_free(ctx);
        ctx = NULL;
    }
}
