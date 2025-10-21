#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libwebsockets.h>
#include <jansson.h>
#include <ev.h>
#include <signal.h>
#include <unistd.h>
#include "qm.h"
#include "qm_device_state.h"

#define WEBSOCKET_URL "69.30.254.180"
#define WEBSOCKET_PORT 8003
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
            printf("✅ Connected to ws://%s\n", WEBSOCKET_URL);
            // Stop the reconnect timer since we're now connected
            ev_timer_stop(ws_loop, &ws_reconnect_timer);
            // Start the service timer for ongoing WebSocket operations
            //ev_timer_start(ws_loop, &ws_service_timer);
            // Mark as connected to prevent reconnection loops
            ws_connected = true;
            lws_callback_on_writable(wsi);
            break;

        case LWS_CALLBACK_CLIENT_RECEIVE:
            printf("📩 Received message: %.*s\n", (int)len, (char *)in);
            {
                json_error_t error;
                json_t *data = json_loadb(in, len, 0, &error);
                if (data) {
                    char *json_str = json_dumps(data, JSON_INDENT(2));
                    printf("📩 Parsed JSON: %s\n", json_str);
                    free(json_str);
                    json_decref(data);
                    // TODO: Add logic here (e.g., save to DB, call API, etc.)
                } else {
                    printf("⚠️ Received non-JSON message: %.*s\n", (int)len, (char *)in);
                    ws_cleanup();
                    set_device_state(DEVICE_STATE_DISCOVERY);
                    //qm_restart_process();
                }
            }
            break;

        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
            printf("⚠️ Connection lost: %s. Reconnecting in 1 second...\n", in ? (char *)in : "unknown error");
            // Stop service timer and start reconnect timer
            ev_timer_stop(ws_loop, &ws_service_timer);
            ws_connected = false; // Mark as disconnected
            //ev_timer_start(ws_loop, &ws_reconnect_timer);
            break;

        case LWS_CALLBACK_CLIENT_CLOSED:
            printf("⚠️ Connection closed. Reconnecting in 1 second...\n");
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

static void ws_reconnect_cb(EV_P_ ev_timer *w, int revents) {
    // Check if already connected
    if (ws_connected) {
        printf("🔄 Already connected, skipping reconnection attempt\n");
        return;
    }

    struct lws_client_connect_info connect_info = {0};

    // Get serial number for WebSocket path
    char buf[UCI_BUF_LEN];
    memset(buf, 0, sizeof(buf));
    if (cmd_buf("uci get aircnms.@aircnms[0].serial_num", buf, sizeof(buf)) != 0 || strlen(buf) == 0) {
        printf("❌ Failed to get serial number from UCI. Using default path\n");
        strcpy(buf, "AIR1231234"); // Fallback to default
    }
    // Remove trailing newline if present
    buf[strcspn(buf, "\n")] = 0;

    char websocket_path[128];
    snprintf(websocket_path, sizeof(websocket_path), "/ws/%s", buf);
    printf("🔄 Reconnection attempt - websocket path: %s\n", websocket_path);

    // Stop timers
    ev_timer_stop(ws_loop, &ws_service_timer);
    ev_timer_stop(ws_loop, w);

    // Destroy previous context if it exists
    if (ws_context) {
        lws_context_destroy(ws_context);
        ws_context = NULL;
        printf("🔄 Context destroyed\n");
    }

    // Create new context
    struct lws_context_creation_info context_info = {0};
    context_info.port = CONTEXT_PORT_NO_LISTEN;
    context_info.protocols = ws_protocols;
    context_info.options = 0; // No LIBEV or SSL options
    context_info.connect_timeout_secs = 10; // 10-second timeout

    ws_context = lws_create_context(&context_info);
    if (!ws_context) {
        printf("❌ Failed to create context. Reconnecting in 5 seconds...\n");
        ev_timer_again(ws_loop, w);
        return;
    }
    printf("🔄 Context created\n");

    // Set up connection info
    connect_info.context = ws_context;
    connect_info.address = WEBSOCKET_URL;
    connect_info.port = WEBSOCKET_PORT;
    connect_info.path = websocket_path;
    connect_info.host = WEBSOCKET_URL;
    connect_info.origin = WEBSOCKET_URL;
    connect_info.protocol = ws_protocols[0].name;
    connect_info.ietf_version_or_minus_one = -1;
    connect_info.userdata = websocket_path; // For logging in callback

    ws_wsi = lws_client_connect_via_info(&connect_info);
    if (!ws_wsi) {
        printf("❌ Failed to connect to %s. Reconnecting in 5 seconds...\n", websocket_path);
        lws_context_destroy(ws_context);
        ws_context = NULL;
        ev_timer_again(ws_loop, w);
        return;
    }
    printf("🔄 Connection initiated to %s\n", websocket_path);

    // Start service timer immediately to handle connection process
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
    printf("🛑 WebSocket listener stopped.\n");
}

