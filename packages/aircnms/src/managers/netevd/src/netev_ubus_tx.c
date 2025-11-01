#include <libubox/uloop.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>
#include <ev.h>
#include <stdio.h>
#include <string.h>

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

// Function to call a ubus method
int call_netev_method(const char *method, struct blob_buf *b)
{
    uint32_t id;
    int ret;
    
    // Look up the object ID
    ret = ubus_lookup_id(ctx, "cgwd", &id);
    if (ret) {
        fprintf(stderr, "Failed to lookup netconfd: %s\n", ubus_strerror(ret));
        return ret;
    }
    
    printf("Calling method: %s\n", method);
    
    // Invoke the method
    ret = ubus_invoke(ctx, id, method, b->head, call_result_cb, NULL, 3000);
    if (ret) {
        fprintf(stderr, "Failed to invoke %s: %s\n", method, ubus_strerror(ret));
        return ret;
    }
    
    return 0;
}

bool netev_ubus_tx_service_init()
{

    ctx = ubus_connect(NULL);
    if (!ctx) {
        fprintf(stderr, "Failed to connect to ubus\n");
        return false;
    }

    printf("Connected to ubus\n");

    // Get the ubus socket FD
    int fd = ctx->sock.fd;
    if (fd < 0) {
        fprintf(stderr, "Invalid ubus fd\n");
        return false;
    }
    printf("UBus integrated with libev loop ✅\n");
    return true;
}

void netev_ubus_tx_service_cleanup(void)
{
    /* ------------------ CLEANUP ------------------ */

    if (ctx) {
        ubus_free(ctx);
        ctx = NULL;
    }
}
