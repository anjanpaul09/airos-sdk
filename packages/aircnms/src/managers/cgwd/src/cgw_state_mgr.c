#include <stdio.h>
#include "cgw_state_mgr.h"
#include "cgw.h"     // your existing functions
#include "log.h"

static device_context_t g_device_ctx;

int handle_device_state_change(device_state_t state)
{
    switch (state) {
    case DEVICE_STATE_DISCOVERY:
        LOG(INFO, "[DISCOVERY] Checking device ID...");
        if (!cgw_check_valid_device_id()) {
            if (!cgw_device_discovery_request()) {
                LOG(INFO, "Cloud Registration Failed.");
                set_device_state(DEVICE_STATE_NOT_REGISTERED);
            } else {
                LOG(INFO, "Device registered successfully");
                cgw_set_online_status();
                set_device_state(DEVICE_STATE_REGISTERED);
            }
        } else {
            set_device_state(DEVICE_STATE_REGISTERED);
        }
        break;

    case DEVICE_STATE_NOT_REGISTERED:
        LOG(INFO, "[NOT REGISTERED] Starting WebSocket...");
        ws_init();
        ev_run(EV_DEFAULT, 0);
        // When registration completes successfully:
        // set_device_state(DEVICE_STATE_REGISTERED);
        break;

    case DEVICE_STATE_REGISTERED:
        LOG(INFO, "[REGISTERED] Initializing MQTT and services...");
        if (!cgw_mqtt_init()) {
            LOG(ERR, "Failed to initialize MQTT");
        }

        cgw_queue_init();
        if (!cgw_mqtt_start_worker()) {
            LOG(ERR, "Failed to start MQTT worker");
        }
        break;
    default:
        LOG(ERR, "Unknown device state");
        break;
    }

    return state;
}

void set_device_state(device_state_t new_state)
{
    pthread_mutex_lock(&g_device_ctx.lock);
    if (g_device_ctx.current_state != new_state) {
        LOG(INFO, "State change: %s -> %s",
            device_state_to_string(g_device_ctx.current_state),
            device_state_to_string(new_state));

        g_device_ctx.current_state = new_state;
        pthread_mutex_unlock(&g_device_ctx.lock);

        // Perform actions based on new state
        handle_device_state_change(new_state);
        return;
    }
    pthread_mutex_unlock(&g_device_ctx.lock);
}

// Thread-safe getter
device_state_t get_device_state(void)
{
    pthread_mutex_lock(&g_device_ctx.lock);
    device_state_t s = g_device_ctx.current_state;
    pthread_mutex_unlock(&g_device_ctx.lock);
    return s;
}

// Convert to string
const char *device_state_to_string(device_state_t s)
{
    switch (s) {
    case DEVICE_STATE_DISCOVERY: return "DEVICE_DISCOVERY";
    case DEVICE_STATE_NOT_REGISTERED: return "DEVICE_NOT_REGISTERED";
    case DEVICE_STATE_REGISTERED: return "DEVICE_REGISTERED";
    default: return "UNKNOWN";
    }
}

bool device_state_init(void)
{
    g_device_ctx.current_state = DEVICE_STATE_DISCOVERY;
    pthread_mutex_init(&g_device_ctx.lock, NULL);

    LOG(INFO, "Device state initialized to DISCOVERY");
    handle_device_state_change(g_device_ctx.current_state);

    return true;
}

void device_state_deinit(void)
{
    pthread_mutex_destroy(&g_device_ctx.lock);
}
