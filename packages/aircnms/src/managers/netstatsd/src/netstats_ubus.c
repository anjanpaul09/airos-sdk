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

#include "netstats.h"
#include "log.h"

/* ---------------------------------------------------
 * Shared context and state
 * --------------------------------------------------- */
struct ubus_context *g_netstats_ubus_ctx = NULL;
static struct ev_loop *loop = NULL;
static ev_io ubus_watcher;

/* ===================================================
 * TX (Transmit) Functionality
 * =================================================== */

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

    if (!g_netstats_ubus_ctx) {
        LOG(ERR, "UBus context not initialized");
        return -1;
    }

    ret = ubus_lookup_id(g_netstats_ubus_ctx, object, &id);
    if (ret) {
        LOG(ERR, "Failed to find object '%s': %s", object, ubus_strerror(ret));
        return ret;
    }

    LOG(DEBUG, "Calling %s.%s", object, method);
    ret = ubus_invoke(g_netstats_ubus_ctx, id, method,
                      b ? b->head : NULL,
                      response_callback, NULL, 3000);

    if (ret) {
        LOG(ERR, "ubus_invoke failed: %s", ubus_strerror(ret));
    }

    return ret;
}

/* ---------------------------------------------------
 * Method: netstats (publish stats)
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
 * Method: get_state (test function)
 * --------------------------------------------------- */
void test_get_state(void)
{
    call_ubus_method("cgwd", "get_state", NULL);
}

/* ===================================================
 * RX (Receive) Functionality
 * =================================================== */

/* ---------------------------------------------------
 * Handler for incoming ubus commands
 * --------------------------------------------------- */
static int ubus_netstats_cmd_handler(struct ubus_context* ctx, struct ubus_object* obj,
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
    (void)size;  // May be used in future
    int len = blobmsg_data_len(tb[DATA]);
    (void)len;  // May be used in future

    LOG(DEBUG, "Declared size: %d | Actual data length: %d", size, len);
    netstats_init_neighbor_stats();
    return 0;
}

/* ---------------------------------------------------
 * libev callback for ubus socket events
 * --------------------------------------------------- */
static void ubus_io_cb(EV_P_ struct ev_io *w, int revents)
{
    if (!g_netstats_ubus_ctx)
        return;

    // Process ubus messages
    ubus_handle_event(g_netstats_ubus_ctx);
}

/* ---------------------------------------------------
 * Internal RX service initialization
 * --------------------------------------------------- */
static bool netstats_ubus_rx_service_init_internal(void)
{
    static struct ubus_object obj;

    // Context should already be initialized by unified init function
    if (!g_netstats_ubus_ctx) {
        LOG(ERR, "UBus context not initialized");
        return false;
    }

    loop = EV_DEFAULT;

    obj.name = "netstatsd";
    obj.type = &(struct ubus_object_type){.name = "netstats"};
    static struct ubus_method methods[4];
    methods[0].name = "neighbor.trigger";            // cloud config
    methods[0].handler = ubus_netstats_cmd_handler;
    methods[0].policy = NULL;
    obj.methods = methods;
    obj.n_methods = 1;

    if (ubus_add_object(g_netstats_ubus_ctx, &obj) != 0) {
        LOG(ERR, "Failed to add ubus object");
        return false;
    }

    // Get the ubus socket FD
    int fd = g_netstats_ubus_ctx->sock.fd;
    if (fd < 0) {
        LOG(ERR, "Invalid ubus fd");
        return false;
    }

    // Register libev watcher for ubus socket
    ev_io_init(&ubus_watcher, ubus_io_cb, fd, EV_READ);
    ev_io_start(loop, &ubus_watcher);

    LOG(INFO, "UBus RX service initialized and integrated with libev loop");

    return true;
}

/* ---------------------------------------------------
 * Internal RX service cleanup
 * --------------------------------------------------- */
static void netstats_ubus_rx_service_cleanup_internal(void)
{
    if (loop) {
        ev_io_stop(loop, &ubus_watcher);
    }
}

/* ===================================================
 * Unified Service API
 * =================================================== */

/* ---------------------------------------------------
 * Unified UBUS Service Initialization
 * Combines both TX and RX initialization
 * --------------------------------------------------- */
bool netstats_ubus_service_init(void)
{
    // Connect to ubus (shared context for both TX and RX)
    g_netstats_ubus_ctx = ubus_connect(NULL);
    if (!g_netstats_ubus_ctx) {
        LOG(ERR, "Failed to connect to ubus");
        return false;
    }

    LOG(INFO, "Connected to ubus");

    // Initialize RX service (register objects, methods, and libev integration)
    if (!netstats_ubus_rx_service_init_internal()) {
        LOG(ERR, "Failed to initialize UBUS RX service");
        ubus_free(g_netstats_ubus_ctx);
        g_netstats_ubus_ctx = NULL;
        return false;
    }

    LOG(INFO, "UBus service initialized (TX and RX)");

    return true;
}

/* ---------------------------------------------------
 * Unified UBUS Service Cleanup
 * --------------------------------------------------- */
void netstats_ubus_service_cleanup(void)
{
    // Cleanup RX service (stop libev watcher)
    netstats_ubus_rx_service_cleanup_internal();

    // Free shared ubus context
    if (g_netstats_ubus_ctx) {
        ubus_free(g_netstats_ubus_ctx);
        g_netstats_ubus_ctx = NULL;
    }

    LOG(INFO, "UBus service cleaned up");
}

/* ===================================================
 * Legacy API (for backward compatibility)
 * =================================================== */

/* ---------------------------------------------------
 * Legacy TX functions - kept for backward compatibility
 * --------------------------------------------------- */
bool netstats_ubus_tx_service_init(void)
{
    // This is now handled by netstats_ubus_service_init
    // Keep for backward compatibility, but should not be called separately
    if (!g_netstats_ubus_ctx) {
        LOG(WARNING, "netstats_ubus_tx_service_init called but context not initialized. Use netstats_ubus_service_init instead.");
        return false;
    }
    return true;
}

void netstats_ubus_tx_service_cleanup(void)
{
    // This is now handled by netstats_ubus_service_cleanup
    // Keep for backward compatibility
}

/* ---------------------------------------------------
 * Legacy RX functions - kept for backward compatibility
 * --------------------------------------------------- */
bool netstats_ubus_rx_service_init(void)
{
    // This is now handled by netstats_ubus_service_init
    // Keep for backward compatibility, but should not be called separately
    if (!g_netstats_ubus_ctx) {
        LOG(WARNING, "netstats_ubus_rx_service_init called but context not initialized. Use netstats_ubus_service_init instead.");
        return false;
    }
    
    // If context exists, try to initialize RX part
    return netstats_ubus_rx_service_init_internal();
}

void netstats_ubus_rx_service_cleanup(void)
{
    // This is now handled by netstats_ubus_service_cleanup
    // Keep for backward compatibility
    netstats_ubus_rx_service_cleanup_internal();
}

