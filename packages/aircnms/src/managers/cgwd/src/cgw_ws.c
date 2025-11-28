#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libwebsockets.h>
#include <jansson.h>
#include <ev.h>
#include <signal.h>
#include <unistd.h>
#include "cgw.h"
#include "cgw_state_mgr.h"
#include "log.h"

//wss://api.cloud.netstream.net.in/ws/
#define WEBSOCKET_URL "api.cloud.netstream.net.in"
#define WEBSOCKET_PORT 443
#define WEBSOCKET_PATH "/ws/AIR1231212"
#define UCI_BUF_LEN 256

// Global variables for WebSocket context and timers
static struct lws_context *ws_context = NULL;
static struct lws *ws_wsi = NULL;
static ev_timer ws_service_timer;
static ev_timer ws_reconnect_timer;
static struct ev_loop *ws_loop = NULL; // Will be set to the provided loop
static bool ws_connected = false; // Track connection state

static int callback_websocket(struct lws *wsi, enum lws_callback_reasons reason,
                             void *user, void *in, size_t len) {
    switch (reason) {
        case LWS_CALLBACK_CLIENT_ESTABLISHED:
            LOG(INFO, "Connected to ws://%s", WEBSOCKET_URL);
            // Stop the reconnect timer since we're now connected
            ev_timer_stop(ws_loop, &ws_reconnect_timer);
            // Start the service timer for ongoing WebSocket operations
            //ev_timer_start(ws_loop, &ws_service_timer);
            // Mark as connected to prevent reconnection loops
            ws_connected = true;
            lws_callback_on_writable(wsi);
            break;

        case LWS_CALLBACK_CLIENT_RECEIVE:
            LOG(DEBUG, "Received message: %.*s", (int)len, (char *)in);
            {
                json_error_t error;
                json_t *data = json_loadb(in, len, 0, &error);
                if (data) {
                    char *json_str = json_dumps(data, JSON_INDENT(2));
                    if (json_str) {
                        LOG(DEBUG, "Parsed JSON: %s", json_str);
                        free(json_str);
                    }
                    json_decref(data);
                    // TODO: Add logic here (e.g., save to DB, call API, etc.)
                } else {
                    LOG(INFO, "Received non-JSON message: %.*s", (int)len, (char *)in);
                    ws_cleanup();
                    set_device_state(DEVICE_STATE_DISCOVERY);
                    //qm_restart_process();
                }
            }
            break;

        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
            LOG(ERR, "Connection lost: %s. Reconnecting...", in ? (char *)in : "unknown error");
            // Stop service timer and start reconnect timer
            ev_timer_stop(ws_loop, &ws_service_timer);
            ws_connected = false; // Mark as disconnected
            //ev_timer_start(ws_loop, &ws_reconnect_timer);
            break;

        case LWS_CALLBACK_CLIENT_CLOSED:
            LOG(INFO, "Connection closed. Reconnecting...");
            // Stop service timer and start reconnect timer
            ev_timer_stop(ws_loop, &ws_service_timer);
            ws_connected = false; // Mark as disconnected
            //ev_timer_start(ws_loop, &ws_reconnect_timer);
            break;

        default:
            break;
    }
    return 0;
}

static struct lws_protocols ws_protocols[] = {
    {
        "websocket",
        callback_websocket,
        0,
        1024, // rx_buffer_size
    },
    { NULL, NULL, 0, 0 } // terminator
};

static void ws_service_cb(EV_P_ ev_timer *w, int revents) {
    if (ws_context) {
        lws_service(ws_context, 0); // Non-blocking poll
    }
}

static void ws_reconnect_cb(EV_P_ ev_timer *w, int revents)
{
    if (ws_connected) {
        LOG(DEBUG, "Already connected, skipping reconnection attempt");
        return;
    }

    /* ------------------------------------------------------------------ */
    /* Step 1: Get Serial Number from UCI                                 */
    /* ------------------------------------------------------------------ */

    char serial[64] = {0};

    if (cmd_buf("uci get aircnms.@aircnms[0].serial_num", serial, sizeof(serial)) != 0 ||
        strlen(serial) == 0)
    {
        LOG(ERR, "Failed to get serial number from UCI. Using fallback serial");
        strncpy(serial, "AIR1231234", sizeof(serial) - 1);
    }
    serial[strcspn(serial, "\n")] = 0;     // strip newline

    char websocket_path[128];
    snprintf(websocket_path, sizeof(websocket_path), "/ws/%s", serial);

    LOG(DEBUG, "Reconnection attempt – websocket path: %s", websocket_path);

    /* ------------------------------------------------------------------ */
    /* Step 2: Stop timers before rebuild                                 */
    /* ------------------------------------------------------------------ */

    ev_timer_stop(ws_loop, &ws_service_timer);
    ev_timer_stop(ws_loop, w);

    /* ------------------------------------------------------------------ */
    /* Step 3: Destroy previous context                                   */
    /* ------------------------------------------------------------------ */

    if (ws_context) {
        LOG(DEBUG, "Destroying previous LWS context");
        lws_context_destroy(ws_context);
        ws_context = NULL;
    }

    /* ------------------------------------------------------------------ */
    /* Step 4: Create new context + vhost                                 */
    /* Note: You MUST create a VHOST when using SSL in client mode        */
    /* ------------------------------------------------------------------ */

    struct lws_context_creation_info info;
    memset(&info, 0, sizeof(info));

    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = ws_protocols;

    ws_context = lws_create_context(&info);
    if (!ws_context) {
        LOG(ERR, "Failed to create LWS context. Retrying in 5 sec...");
        ev_timer_again(ws_loop, w);
        return;
    }

    LOG(DEBUG, "New LWS context created");

    /* ------------------------------------------------------------------ */
    /* Step 5: Setup connection info                                      */
    /* ------------------------------------------------------------------ */

    struct lws_client_connect_info ccinfo;
    memset(&ccinfo, 0, sizeof(ccinfo));

    ccinfo.context  = ws_context;
    ccinfo.address  = WEBSOCKET_URL;
    ccinfo.port     = WEBSOCKET_PORT;
    ccinfo.path     = websocket_path;

    ccinfo.host     = WEBSOCKET_URL;
    ccinfo.origin   = WEBSOCKET_URL;

    ccinfo.ssl_connection = LCCSCF_USE_SSL |
                            LCCSCF_ALLOW_INSECURE;  // remove if CA is real

    ccinfo.protocol = ws_protocols[0].name;

    /* ⚠ IMPORTANT: userdata must point to persistent memory */
    ccinfo.userdata = strdup(websocket_path);   // free in close callback

    ws_wsi = lws_client_connect_via_info(&ccinfo);

    if (!ws_wsi) {
        LOG(ERR, "Failed to connect to %s. Retrying in 5 sec...", websocket_path);
        lws_context_destroy(ws_context);
        ws_context = NULL;

        ev_timer_again(ws_loop, w);
        return;
    }

    LOG(DEBUG, "WebSocket connection initiated to %s", websocket_path);

    /* ------------------------------------------------------------------ */
    /* Step 6: Start service timer                                        */
    /* ------------------------------------------------------------------ */

    ev_timer_start(ws_loop, &ws_service_timer);
}


// Initialize WebSocket client
int ws_init(void) {
    ws_loop = EV_DEFAULT; // Store the provided loop

    // Initialize timers
    ev_timer_init(&ws_service_timer, ws_service_cb, 0.1, 0.1); // Poll every 100ms
    // Initialize reconnect timer (one-shot, not repeating)
    ev_timer_init(&ws_reconnect_timer, ws_reconnect_cb, 1.0, 0.0);

    // Reset connection state
    ws_connected = false;

    // Start initial connection
    ws_reconnect_cb(ws_loop, &ws_reconnect_timer, 0);

    return 0;
}

// Cleanup WebSocket client
void ws_cleanup(void) {
    ev_timer_stop(ws_loop, &ws_service_timer);
    ev_timer_stop(ws_loop, &ws_reconnect_timer);
    if (ws_context) {
        lws_context_destroy(ws_context);
        ws_context = NULL;
    }
    ws_connected = false; // Reset connection state
    LOG(INFO, "WebSocket listener stopped");
}

