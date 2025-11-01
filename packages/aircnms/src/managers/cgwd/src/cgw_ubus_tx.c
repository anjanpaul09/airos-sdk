#include <libubox/uloop.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>
#include <ev.h>
#include <stdio.h>
#include <string.h>
#include "log.h"

static struct ubus_context *ctx = NULL;

// Callback function to handle the response
static void call_result_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    char *str;
    
    if (!msg) {
        LOG(DEBUG, "No response received");
        return;
    }
    
    str = blobmsg_format_json(msg, true);
    if (str) {
        LOG(DEBUG, "Response: %s", str);
        free(str);
    }
}

// Function to call a ubus method
int call_netconfd_method(const char *method, struct blob_buf *b)
{
    uint32_t id;
    int ret;
    
    if (!ctx) {
        LOG(ERR, "UBus context not initialized");
        return -1;
    }

    // Look up the object ID
    ret = ubus_lookup_id(ctx, "netconfd", &id);
    if (ret) {
        LOG(ERR, "Failed to lookup netconfd: %s", ubus_strerror(ret));
        return ret;
    }
    
    LOG(DEBUG, "Calling method: %s", method);
    
    // Invoke the method
    ret = ubus_invoke(ctx, id, method, b->head, call_result_cb, NULL, 3000);
    if (ret) {
        LOG(ERR, "Failed to invoke %s: %s", method, ubus_strerror(ret));
        return ret;
    }
    
    return 0;
}

int call_netconfd_sync(const char *method, struct blob_buf *b)
{
    uint32_t id;
    int ret;
    
    if (!ctx) {
        LOG(ERR, "UBus context not initialized");
        return -1;
    }

    ret = ubus_lookup_id(ctx, "netconfd", &id);
    if (ret) {
        LOG(ERR, "Failed to lookup netconfd: %s", ubus_strerror(ret));
        return ret;
    }
    
    LOG(DEBUG, "Calling method (sync): %s", method);
    
    // Synchronous invoke - waits for response
    ret = ubus_invoke(ctx, id, method, b->head, call_result_cb, NULL, 3000);
    if (ret) {
        LOG(ERR, "Failed to invoke %s: %s", method, ubus_strerror(ret));
        return ret;
    }
    
    return 0;
}

int call_cmdexec_method(const char *method, struct blob_buf *b)
{
    uint32_t id;
    int ret;
    
    if (!ctx) {
        LOG(ERR, "UBus context not initialized");
        return -1;
    }

    ret = ubus_lookup_id(ctx, "cmdexecd", &id);
    if (ret) {
        LOG(ERR, "Failed to lookup cmdexecd: %s", ubus_strerror(ret));
        return ret;
    }
    
    // Synchronous invoke - waits for response
    ret = ubus_invoke(ctx, id, method, b->head, call_result_cb, NULL, 3000);
    if (ret) {
        LOG(ERR, "Failed to invoke %s: %s", method, ubus_strerror(ret));
        return ret;
    }
    
    return 0;
}

int call_netstats_method(const char *method, struct blob_buf *b)
{
    uint32_t id;
    int ret;
    
    if (!ctx) {
        LOG(ERR, "UBus context not initialized");
        return -1;
    }

    ret = ubus_lookup_id(ctx, "netstatsd", &id);
    if (ret) {
        LOG(ERR, "Failed to lookup netstatsd: %s", ubus_strerror(ret));
        return ret;
    }
    
    // Synchronous invoke - waits for response
    ret = ubus_invoke(ctx, id, method, b->head, call_result_cb, NULL, 3000);
    if (ret) {
        LOG(ERR, "Failed to invoke %s: %s", method, ubus_strerror(ret));
        return ret;
    }
    
    return 0;
}

bool cgw_ubus_rx_service_init()
{

    ctx = ubus_connect(NULL);
    if (!ctx) {
        LOG(ERR, "Failed to connect to ubus");
        return false;
    }

    LOG(INFO, "Connected to ubus");

    // Get the ubus socket FD
    int fd = ctx->sock.fd;
    if (fd < 0) {
        LOG(ERR, "Invalid ubus fd");
        ubus_free(ctx);
        ctx = NULL;
        return false;
    }
    LOG(INFO, "UBus integrated with libev loop");
    
    return true;
}

void cgw_ubus_rx_service_cleanup()
{
    /* ------------------ CLEANUP ------------------ */

    if (ctx) {
        ubus_free(ctx);
    }
    
}
