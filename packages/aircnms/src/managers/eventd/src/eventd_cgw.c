#include <limits.h>
#include <stdio.h>
#include <libubox/blobmsg_json.h>
#include "eventd.h"

#include "os_time.h"
#include "os_nif.h"
#include "dppline.h"
#include "log.h"
#include "device_config.h"
#include "unixcomm.h"
#include "ipc_dir.h"

// Retry configuration
#define MAX_RETRY_ATTEMPTS 3
#define RETRY_INITIAL_DELAY_MS 1000
#define RETRY_MAX_DELAY_MS 8000
#define RETRY_BACKOFF_MULTIPLIER 2

static uint8_t          eventd_mqtt_buf[STATS_MQTT_BUF_SZ];

/**
 * Publish message to MQTT via cmdexec service
 * @param mlen Length of message buffer
 * @param mbuf Message buffer
 * @param type Message type
 * @return true on success, false on failure
 */
bool eventd_mqtt_publish(size_t mlen, const void *mbuf) {
    struct blob_buf b = {};
    int ret;
    bool success = false;

    // Validate inputs
    if (!mbuf || mlen == 0) {
        LOG(ERR, "Invalid message buffer or length");
        return false;
    }

    // Sanity check on message length
    if (mlen > STATS_MQTT_BUF_SZ) {
        LOG(ERR, "Message length %zu exceeds maximum %d", mlen, STATS_MQTT_BUF_SZ);
        return false;
    }

    // Initialize blob buffer
    blob_buf_init(&b, 0);

    // Add message data
    if (blobmsg_add_field(&b, BLOBMSG_TYPE_UNSPEC, "data", mbuf, mlen) != 0) {
        LOG(ERR, "Failed to add data field to blob");
        goto cleanup;
    }

    if (blobmsg_add_u32(&b, "size", (uint32_t)mlen) != 0) {
        LOG(ERR, "Failed to add size field to blob");
        goto cleanup;
    }

    // Optional: Add message type
    if (blobmsg_add_u32(&b, "type", (uint32_t)1) != 0) {
        LOG(ERR, "Failed to add type field to blob");
        goto cleanup;
    }

    // Invoke method
    ret = call_eventd_method("cmdexec.event", &b);
    if (ret != 0) {
        LOG(ERR, "Failed to call cmdexec method: %d", ret);
        goto cleanup;
    }

    success = true;
    LOG(DEBUG, "Successfully published MQTT message (size: %zu, type: %d)", mlen, 1);

cleanup:
    blob_buf_free(&b);
    return success;
}

/**
 * Sleep for specified milliseconds
 * @param ms Milliseconds to sleep
 */
static void sleep_ms(uint32_t ms) {
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000;
    nanosleep(&ts, NULL);
}

/**
 * Calculate retry delay with exponential backoff
 * @param attempt Current attempt number (0-based)
 * @return Delay in milliseconds
 */
static uint32_t calculate_retry_delay(uint32_t attempt) {
    uint32_t delay = RETRY_INITIAL_DELAY_MS;

    // Calculate exponential backoff: initial_delay * (multiplier ^ attempt)
    for (uint32_t i = 0; i < attempt; i++) {
        delay *= RETRY_BACKOFF_MULTIPLIER;
        if (delay > RETRY_MAX_DELAY_MS) {
            delay = RETRY_MAX_DELAY_MS;
            break;
        }
    }

    return delay;
}

/**
 * Send event to cloud via cmdexec service
 * @param type Event type
 * @param status Event status
 * @param data Event data (optional, can be NULL)
 * @param id Cloud ID (optional, can be NULL)
 * @return 0 on success, negative error code on failure
 */
int eventd_send_event_to_cloud(event_msg_t *event) {
    
    //event_msg_t info;
    uint32_t buf_len;
    bool rc;
    int ret = -EIO;
    uint32_t attempt;

    int type = event->type;
    
    // Validate buffer size
    if (sizeof(event_msg_t) > sizeof(eventd_mqtt_buf)) {
        LOG(ERR, "Event message too large for MQTT buffer");
        return -ENOMEM;
    }

    // Serialize the event message
    memcpy(eventd_mqtt_buf, event, sizeof(event_msg_t));
    buf_len = sizeof(event_msg_t);

    // Retry loop with exponential backoff
    for (attempt = 0; attempt < MAX_RETRY_ATTEMPTS; attempt++) {
        if (attempt > 0) {
            uint32_t delay = calculate_retry_delay(attempt - 1);
            LOG(WARN, "Retry attempt %u/%u after %u ms delay (type=%d)",
                attempt + 1, MAX_RETRY_ATTEMPTS, delay, type);
            sleep_ms(delay);
        }

        // Send event via MQTT
        rc = eventd_mqtt_publish(buf_len, eventd_mqtt_buf);
        if (rc) {
            // Success
            ret = 0;
            LOG(INFO, "Successfully sent event to cloud on attempt %u (type=%d)",
                attempt + 1, type);
            break;
        }

        // Log failure
        LOG(WARN, "Failed to publish event on attempt %u/%u (type=%d)",
            attempt + 1, MAX_RETRY_ATTEMPTS, type);
    }

    // Check if all retries failed
    if (ret != 0) {
        LOG(ERR, "Failed to publish event after %u attempts (type=%d)",
            MAX_RETRY_ATTEMPTS, type);
    }

    return ret;
}

