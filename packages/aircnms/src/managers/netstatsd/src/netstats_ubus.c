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
 * Handler for neighbor scan trigger command
 * --------------------------------------------------- */
static int ubus_neighbor_scan_handler(struct ubus_context* ctx, struct ubus_object* obj,
                              struct ubus_request_data* req, const char* method,
                              struct blob_attr* msg) 
{
    (void)obj;
    (void)method;
    (void)msg;
    
    extern bool target_stats_neighbor_get(neighbor_report_data_t *report);
    neighbor_report_data_t report = {0};
    
    LOG(INFO, "NEIGHBOR_SCAN: Triggered via ubus");
    
    // Trigger neighbor scan
    bool status = target_stats_neighbor_get(&report);
    
    // Prepare response
    struct blob_buf b = {};
    blob_buf_init(&b, 0);
    
    if (status && report.n_entry > 0) {
        blobmsg_add_u32(&b, "status", 0);  // Success
        blobmsg_add_u32(&b, "entries", report.n_entry);
        blobmsg_add_u64(&b, "timestamp_ms", report.timestamp_ms);
        
        // Add neighbor entries as array
        struct blob_attr *neighbors = blobmsg_open_array(&b, "neighbors");
        for (int i = 0; i < report.n_entry; i++) {
            struct blob_attr *entry = blobmsg_open_table(&b, NULL);
            
            int32_t rssi = report.record[i].rssi;
            // Fix for unsigned wraparound
            if (rssi > 1000) {
                rssi = (int32_t)((uint32_t)rssi - UINT32_MAX - 1);
            }
            
            blobmsg_add_string(&b, "bssid", report.record[i].bssid);
            blobmsg_add_string(&b, "ssid", report.record[i].ssid[0] ? report.record[i].ssid : "");
            blobmsg_add_u32(&b, "rssi", (uint32_t)rssi);
            blobmsg_add_u32(&b, "channel", report.record[i].channel);
            blobmsg_add_u32(&b, "width", report.record[i].chan_width);
            blobmsg_add_u32(&b, "radio_type", report.record[i].radio_type);
            blobmsg_add_u64(&b, "tsf", report.record[i].tsf);
            
            blobmsg_close_table(&b, entry);
        }
        blobmsg_close_array(&b, neighbors);
    } else {
        blobmsg_add_u32(&b, "status", -1);  // Error
        blobmsg_add_string(&b, "error", status ? "No neighbors found" : "Scan failed");
        blobmsg_add_u32(&b, "entries", 0);
    }
    
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
    
    LOG(INFO, "NEIGHBOR_SCAN: Completed entries=%d", report.n_entry);
    
    return 0;
}

/* ---------------------------------------------------
 * Handler for incoming ubus commands (legacy)
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
    methods[0].name = "neighbor.trigger";            // legacy trigger (starts periodic reporting)
    methods[0].handler = ubus_netstats_cmd_handler;
    methods[0].policy = NULL;
    methods[1].name = "neighbor.scan";              // trigger immediate scan and return results
    methods[1].handler = ubus_neighbor_scan_handler;
    methods[1].policy = NULL;
    obj.methods = methods;
    obj.n_methods = 2;

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

