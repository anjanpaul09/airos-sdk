#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <jansson.h>

#include "log.h"
#include "info_events.h"
#include "stats_report.h"
#include "netev_ubus_tx.h"

#define INFO_EVENT_BUF_SZ (4*1024)    // 4 KB
//static uint8_t netev_info_buf[INFO_EVENT_BUF_SZ];

/* Helper function to send info event via unixcomm to cgwd */
static bool netev_send_info_event(info_event_t *event)
{
    if (!event) {
        LOG(ERR, "netev_send_info_event: NULL event");
        return false;
    }

    // Serialize the event
    size_t event_size = sizeof(info_event_type_t) + sizeof(uint64_t);
    uint8_t netev_info_buf[INFO_EVENT_BUF_SZ];
    
    switch (event->type) {
        case INFO_EVENT_CLIENT:
            event_size += sizeof(client_info_event_t);
            break;
        case INFO_EVENT_VIF:
            event_size += sizeof(vif_info_event_t);
            break;
        case INFO_EVENT_DEVICE:
            event_size += sizeof(device_info_event_t);
            break;
        default:
            LOG(ERR, "Unknown info event type: %d", event->type);
            return false;
    }

    if (event_size > INFO_EVENT_BUF_SZ) {
        LOG(ERR, "Event size %zu exceeds buffer size %d", event_size, INFO_EVENT_BUF_SZ);
        return false;
    }

    // Copy event to buffer
    memcpy(netev_info_buf, &event->type, sizeof(info_event_type_t));
    size_t offset = sizeof(info_event_type_t);
    
    memcpy(netev_info_buf + offset, &event->timestamp_ms, sizeof(uint64_t));
    offset += sizeof(uint64_t);

    switch (event->type) {
        case INFO_EVENT_CLIENT:
            memcpy(netev_info_buf + offset, &event->u.client, sizeof(client_info_event_t));
            break;
        case INFO_EVENT_VIF:
            memcpy(netev_info_buf + offset, &event->u.vif, sizeof(vif_info_event_t));
            break;
        case INFO_EVENT_DEVICE:
            memcpy(netev_info_buf + offset, &event->u.device, sizeof(device_info_event_t));
            break;
    }

    // Send via ubus to cgwd (similar to how netstatsd sends stats)
    LOG(DEBUG, "Sending info event type=%d size=%zu", event->type, event_size);
    netev_publish_info_event(netev_info_buf, event_size);
    
    return true;
}

/* Send client info event */
bool netev_send_client_info_event(client_info_event_t *client_info, uint64_t timestamp_ms)
{
    if (!client_info) {
        LOG(ERR, "netev_send_client_info_event: NULL client_info");
        return false;
    }

    info_event_t event = {0};
    event.type = INFO_EVENT_CLIENT;
    event.timestamp_ms = timestamp_ms;
    
    memcpy(&event.u.client, client_info, sizeof(client_info_event_t));

    return netev_send_info_event(&event);
}

/* Send VIF info event */
bool netev_send_vif_info_event(vif_info_event_t *vif_info, uint64_t timestamp_ms)
{
    if (!vif_info) {
        LOG(ERR, "netev_send_vif_info_event: NULL vif_info");
        return false;
    }

    info_event_t event = {0};
    event.type = INFO_EVENT_VIF;
    event.timestamp_ms = timestamp_ms;
    
    memcpy(&event.u.vif, vif_info, sizeof(vif_info_event_t));

    return netev_send_info_event(&event);
}

/* Send device info event */
bool netev_send_device_info_event(device_info_event_t *device_info, uint64_t timestamp_ms)
{
    if (!device_info) {
        LOG(ERR, "netev_send_device_info_event: NULL device_info");
        return false;
    }

    info_event_t event = {0};
    event.type = INFO_EVENT_DEVICE;
    event.timestamp_ms = timestamp_ms;
    
    memcpy(&event.u.device, device_info, sizeof(device_info_event_t));

    return netev_send_info_event(&event);
}

