#include <limits.h>
#include <stdio.h>
#include <libubox/blobmsg_json.h>
#include "cmdexec.h"

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

char fw_id[128];    
static uint8_t          cmdexec_mqtt_buf[STATS_MQTT_BUF_SZ];

/**
 * Publish message to MQTT via cmdexec service
 * @param mlen Length of message buffer
 * @param mbuf Message buffer
 * @param type Message type
 * @return true on success, false on failure
 */
bool cmdexec_mqtt_publish(size_t mlen, const void *mbuf, DmMsgType type) {
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
    if (blobmsg_add_u32(&b, "type", (uint32_t)type) != 0) {
        LOG(ERR, "Failed to add type field to blob");
        goto cleanup;
    }

    // Invoke method
    ret = call_cmdexec_method(CMDEXEC_EVENT_METHOD, &b);
    if (ret != 0) {
        LOG(ERR, "Failed to call cmdexec method: %d", ret);
        goto cleanup;
    }

    success = true;
    LOG(DEBUG, "Successfully published MQTT message (size: %zu, type: %d)", mlen, type);

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
int cmdexec_send_event_to_cloud(event_type_t type, event_status_t status,
                                 const char *data, const char *id) {
    event_msg_t info;
    uint32_t buf_len;
    bool rc;
    int ret = -EIO;
    uint32_t attempt;

    // Initialize event structure
    memset(&info, 0, sizeof(event_msg_t));
    info.type = type;
    info.status = status;

    // Populate event-specific data
    switch (type) {
        case EVENT_TYPE_CMD:
            // Validate required parameters for command events
            if (!id || !data) {
                LOG(ERR, "Command event requires both id and data");
                return -EINVAL;
            }

            safe_strncpy(info.cloud_id, id, sizeof(info.cloud_id));
            safe_strncpy(info.data, data, sizeof(info.data));

            LOG(INFO, "CMDEXECD->CGWD");
            LOG(INFO, "Sending CMD event: id=%s, status=%d", info.cloud_id, status);
            break;

        case EVENT_TYPE_UPGRADE:
            // Get firmware ID from aircnms
            if (get_fw_id_frm_aircnms(info.cloud_id) != 0) {
                LOG(ERR, "Failed to get firmware ID from aircnms");
                return -EIO;
            }

            LOG(INFO, "CMDEXECD->CGWD");
            LOG(INFO, "Sending UPGRADE event: fw_id=%s, status=%d", info.cloud_id, status);
            break;

        default:
            LOG(ERR, "Unknown event type: %d", type);
            return -EINVAL;
    }

    // Validate buffer size
    if (sizeof(event_msg_t) > sizeof(cmdexec_mqtt_buf)) {
        LOG(ERR, "Event message too large for MQTT buffer");
        return -ENOMEM;
    }

    // Serialize the event message
    memcpy(cmdexec_mqtt_buf, &info, sizeof(event_msg_t));
    buf_len = sizeof(event_msg_t);

    // Retry loop with exponential backoff
    for (attempt = 0; attempt < MAX_RETRY_ATTEMPTS; attempt++) {
        if (attempt > 0) {
            uint32_t delay = calculate_retry_delay(attempt - 1);
            LOG(WARN, "Retry attempt %u/%u after %u ms delay (type=%d, status=%d)",
                attempt + 1, MAX_RETRY_ATTEMPTS, delay, type, status);
            sleep_ms(delay);
        }

        // Send event via MQTT
        rc = cmdexec_mqtt_publish(buf_len, cmdexec_mqtt_buf, EVENT);
        if (rc) {
            // Success
            ret = 0;
            LOG(INFO, "Successfully sent event to cloud on attempt %u (type=%d, status=%d)",
                attempt + 1, type, status);
            break;
        }

        // Log failure
        LOG(WARN, "Failed to publish event on attempt %u/%u (type=%d, status=%d)",
            attempt + 1, MAX_RETRY_ATTEMPTS, type, status);
    }

    // Check if all retries failed
    if (ret != 0) {
        LOG(ERR, "Failed to publish event after %u attempts (type=%d, status=%d)",
            MAX_RETRY_ATTEMPTS, type, status);
    }

    return ret;
}

/**
 * Check and send firmware upgrade status if needed
 * Handles the complete flow with proper error checking and retries
 * @return 0 on success, negative error code on failure
 */
int check_and_send_fw_upgrade_status(void) 
{
    int ret;
    uint32_t attempt;
    bool cloud_notified = false;
    int online_status;

    // Check if there's an upgrade status to report
    if (!check_fw_upgrade_status()) {
        // No upgrade status to send
        return 0;
    }

    LOG(INFO, "%s: CMDEXEC fw upgrade status sending", __func__);

    // Check if we're online before attempting
    online_status = air_check_online_status();
    if (!online_status) {
        LOG(WARN, "System is offline, deferring upgrade status report");
        sleep_ms(RETRY_INITIAL_DELAY_MS*5);
        return -1;
    }

    sleep_ms(RETRY_INITIAL_DELAY_MS*15);
    // Retry loop for sending event to cloud
    for (attempt = 0; attempt < MAX_RETRY_ATTEMPTS; attempt++) {
        if (attempt > 0) {
            uint32_t delay = calculate_retry_delay(attempt - 1);
            LOG(WARN, "Retrying cloud notification: attempt %u/%u after %u ms delay",
                attempt + 1, MAX_RETRY_ATTEMPTS, delay);
            sleep_ms(delay);
        }

        online_status = air_check_online_status();
        if (!online_status) {
            LOG(WARN, "System went offline during retry, aborting");
            return -1;
        }

        // Send upgrade event to cloud (has its own internal retries)
        ret = cmdexec_send_event_to_cloud(EVENT_TYPE_UPGRADE, UPGRADED, NULL, NULL);
        if (ret == 0) {
            cloud_notified = true;
            LOG(INFO, "Cloud notification succeeded on attempt %u", attempt + 1);
            break;
        }

        LOG(WARN, "Cloud notification failed on attempt %u/%u: %d",
            attempt + 1, MAX_RETRY_ATTEMPTS, ret);
    }

    // Check if cloud notification ultimately failed
    if (!cloud_notified) {
        LOG(ERR, "Failed to send upgrade event to cloud after %u attempts", MAX_RETRY_ATTEMPTS);
        // Don't clear local status if cloud notification failed
        return -1;
    }

    // Retry loop for clearing local status
    for (attempt = 0; attempt < MAX_RETRY_ATTEMPTS; attempt++) {
        if (attempt > 0) {
            uint32_t delay = calculate_retry_delay(attempt - 1);
            LOG(WARN, "Retrying local status clear: attempt %u/%u after %u ms delay",
                attempt + 1, MAX_RETRY_ATTEMPTS, delay);
            sleep_ms(delay);
        }

        // Clear local status after successful cloud notification
        ret = set_fw_upgrade_status_to_aircnms(UPGRADED);
        if (ret == 0) {
            LOG(INFO, "Local status cleared successfully on attempt %u", attempt + 1);
            LOG(INFO, "Firmware upgrade status successfully reported");
            return 0;
        }

        LOG(WARN, "Failed to clear local status on attempt %u/%u: %d",
            attempt + 1, MAX_RETRY_ATTEMPTS, ret);
    }

    // Cloud was notified but local status not cleared after all retries
    LOG(ERR, "Failed to clear upgrade status in aircnms after %u attempts", MAX_RETRY_ATTEMPTS);
    LOG(WARN, "Cloud notified successfully but local status update failed - may cause duplicate reports");

    return -1;
}

