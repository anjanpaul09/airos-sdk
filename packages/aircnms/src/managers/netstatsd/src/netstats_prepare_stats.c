#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

#include "netstats.h"
#include "log.h"

#define STATS_MQTT_BUF_SZ        (128*1024)    // 128 KB
static uint8_t          netstats_mqtt_buf[STATS_MQTT_BUF_SZ];

// Helper function to serialize client data with pointer handling
static size_t serialize_client_data(const client_report_data_t *client, uint8_t *buffer, size_t max_size)
{
    size_t offset = 0;
    
    // Check if we have enough space
    size_t required_size = sizeof(client->timestamp_ms) + 
                          sizeof(client->n_client) + 
                          client->n_client * sizeof(client_record_t);
    
    if (required_size > max_size) {
        LOG(ERR, "Not enough buffer space: required=%zu, available=%zu", required_size, max_size);
        return 0;
    }
    
    // Serialize timestamp
    memcpy(buffer + offset, &client->timestamp_ms, sizeof(client->timestamp_ms));
    offset += sizeof(client->timestamp_ms);
    
    // Serialize n_client
    memcpy(buffer + offset, &client->n_client, sizeof(client->n_client));
    offset += sizeof(client->n_client);
    
    // Serialize the actual records (not the pointer!)
    if (client->n_client > 0 && client->record) {
        size_t records_size = client->n_client * sizeof(client_record_t);
        memcpy(buffer + offset, client->record, records_size);
        offset += records_size;
    } else {
        LOG(DEBUG, "No client records to serialize");
    }
    
    return offset;
}

size_t serialize_compress_netstats_stats(const netstats_stats_t *stats, uint8_t *compressed_data, size_t compressed_max_size)
{
    if (!stats || !compressed_data) {
        LOG(ERR, "NULL pointer in serialize_compress_netstats_stats");
        return 0;
    }

    uint8_t serialized_data[STATS_MQTT_BUF_SZ];
    size_t serialized_size = 0;
    
    // Serialize type and size first
    memcpy(serialized_data, &stats->type, sizeof(stats->type));
    serialized_size += sizeof(stats->type);
    
    // We'll update size later, reserve space for it
    size_t size_offset = serialized_size;
    serialized_size += sizeof(stats->size);

    // Handle different types
    switch (stats->type) {
        case NETSTATS_T_CLIENT:
        {
            size_t client_size = serialize_client_data(&stats->u.client, 
                                                       serialized_data + serialized_size,
                                                       sizeof(serialized_data) - serialized_size);
            if (client_size == 0) {
                return 0;
            }
            serialized_size += client_size;
            break;
        }
        
        case NETSTATS_T_DEVICE:
        case NETSTATS_T_VIF:
        case NETSTATS_T_NEIGHBOR:
        {
            // These types don't have pointers, can use direct copy
            size_t data_size = stats->size;
            if (serialized_size + data_size > sizeof(serialized_data)) {
                return 0;
            }
            memcpy(serialized_data + serialized_size, &stats->u, data_size);
            serialized_size += data_size;
            break;
        }
        
        default:
            LOG(ERR, "Unknown stats type: %d", stats->type);
            return 0;
    }
    
    // Update the size field
    int actual_size = serialized_size - size_offset - sizeof(stats->size);
    memcpy(serialized_data + size_offset, &actual_size, sizeof(stats->size));
    
    /* Compress the serialized data */
    uLongf compressed_size = compressed_max_size;
    
    if (compress2(compressed_data, &compressed_size, serialized_data, serialized_size, Z_BEST_SPEED) != Z_OK) {
        LOG(ERR, "Compression failed");
        return 0;
    }

    LOG(DEBUG, "Compressed to %lu bytes", compressed_size);
    return compressed_size;  // Return actual compressed size
}

bool netstats_copy_stats(netstats_stats_t *dst, void *sts)
{
    if (!dst || !sts) {
        LOG(ERR, "NULL pointer detected in netstats_copy_stats");
        return false;
    }

    LOG(DEBUG, "netstats_copy_stats: type=%d", dst->type);

    switch (dst->type)
    {
        case NETSTATS_T_DEVICE:
        {
            device_report_data_t *report_data = (device_report_data_t *)sts;
            memcpy(&dst->u.device.record, &report_data->record, sizeof(device_record_t));
            dst->u.device.timestamp_ms = report_data->timestamp_ms;
            dst->size = sizeof(dst->u.device.timestamp_ms) + sizeof(dst->u.device);
            break;
        }

        case NETSTATS_T_VIF:
        {
            vif_report_data_t *report_data = (vif_report_data_t *)sts;
   
            // Copy timestamp
            dst->u.vif.timestamp_ms = report_data->timestamp_ms;
            memcpy(&dst->u.vif.record, &report_data->record, sizeof(vif_record_t));
            dst->size = sizeof(dst->u.vif.timestamp_ms) + sizeof(dst->u.vif);

            break;
        }
        
        case NETSTATS_T_CLIENT:
        {
            client_report_data_t *report_data = (client_report_data_t *)sts;

            if (!report_data) {
                LOG(ERR, "report_data is NULL");
                return false;
            }

            // Validate number of clients
            if (report_data->n_client <= 0) {
                LOG(WARN, "No clients to copy (n_client=%d)", report_data->n_client);
                dst->u.client.timestamp_ms = report_data->timestamp_ms;
                dst->u.client.n_client = 0;
                dst->u.client.record = NULL;
                dst->size = sizeof(dst->u.client.timestamp_ms) + sizeof(dst->u.client.n_client);
                return true;
            }

            // Ensure report_data->record is valid
            if (!report_data->record) {
                LOG(ERR, "report_data->record is NULL, cannot copy client records");
                return false;
            }

            // Copy timestamp
            dst->u.client.timestamp_ms = report_data->timestamp_ms;

            // Limit to MAX_CLIENTS
            dst->u.client.n_client = (report_data->n_client > MAX_CLIENTS)
                                 ? MAX_CLIENTS
                                 : report_data->n_client;
    
            // The serialization function will handle dereferencing it
            dst->u.client.record = report_data->record;
            dst->u.client.capacity = report_data->capacity;
            
            // Compute size (this is the size of serialized data, not the struct)
            dst->size = sizeof(dst->u.client.timestamp_ms)
                      + sizeof(dst->u.client.n_client)
                      + dst->u.client.n_client * sizeof(client_record_t);

            break;
        }

        case NETSTATS_T_NEIGHBOR:
        {
            neighbor_report_data_t *report_data = (neighbor_report_data_t *)sts;

            // Copy timestamp
            dst->u.neighbor.timestamp_ms = report_data->timestamp_ms;

            // Copy client neighbor, ensuring it does not exceed MAX_NEIGHBOR
            dst->u.neighbor.n_entry = (report_data->n_entry > MAX_NEIGHBOUR) ? MAX_NEIGHBOUR : report_data->n_entry;

            // Copy neighbor records safely
            memcpy(dst->u.neighbor.record, report_data->record, dst->u.neighbor.n_entry * sizeof(neighbor_record_t));
            dst->size = sizeof(dst->u.neighbor.timestamp_ms)
                      + sizeof(dst->u.neighbor.n_entry)
                      + dst->u.neighbor.n_entry * sizeof(neighbor_record_t);
            break;
        }

        default:
            LOG(ERR, "NETSTATS ""(Failed - Unknown stats type %d)", dst->type);
            return false;
    }

    return true;
}

bool netstats_prepare_stats(NETSTATS_STATS_TYPE type, void *rpt)
{
    netstats_stats_t *s = calloc(1, sizeof(netstats_stats_t));
    long buf_len;

    LOG(DEBUG, "netstats_prepare_stats: ENTER, type=%d", type);

    if (!s) {
        LOG(ERR, "NETSTATS (Failed to allocate netstats_stats_t)");
        return false;
    }

    s->type = type;

    if (!netstats_copy_stats(s, rpt)) {
        LOG(ERR, "netstats_copy_stats failed");
        free(s);
        return false;
    }

    if (sizeof(netstats_stats_t) > STATS_MQTT_BUF_SZ) {
        LOG(ERR, "NETSTATS (Failed - netstats_stats_t size exceeds netstats_mqtt_buf size!)");
        free(s);
        return false;
    }

    buf_len = serialize_compress_netstats_stats(s, netstats_mqtt_buf, STATS_MQTT_BUF_SZ);
    if (buf_len == 0) {
        LOG(ERR, "serialize_compress_netstats_stats failed");
        free(s);
        return false;
    }

    LOG(DEBUG, "Serialization successful, compressed size: %ld bytes", buf_len);

    netstats_item_t *qi = CALLOC(1, sizeof(netstats_item_t));
    if (!qi) {
        free(s);
        return false;
    }
        
    // Fill request metadata
    qi->req.data_type = DATA_STATS;
    if (buf_len > 0) {
        qi->buf = MALLOC(buf_len);
        if (!qi->buf) {
            netstats_queue_item_free(qi);
            free(s);
            LOG(ERR, "Failed to allocate buffer for queue item");
            return false;
        }
        memcpy(qi->buf, netstats_mqtt_buf, buf_len);
        qi->size = buf_len;
    }
    
    netstats_response_t res = {0};
    if (!netstats_queue_put(&qi, &res)) {
        if (qi) netstats_queue_item_free(qi);
        free(s);
        LOG(ERR, "Failed to put item in queue");
        return false;
    }

    free(s);
    return true;
}

/* Prepare device stats */
bool netstats_put_device(device_report_data_t *rpt)
{
    return netstats_prepare_stats(NETSTATS_T_DEVICE, rpt);
}

/* Prepare VIF stats */
bool netstats_put_vif(vif_report_data_t *rpt)
{
    return netstats_prepare_stats(NETSTATS_T_VIF, rpt);
}

bool netstats_put_client(client_report_data_t *rpt)
{
    return netstats_prepare_stats(NETSTATS_T_CLIENT, rpt);
}
        
bool netstats_put_neighbor(neighbor_report_data_t *rpt)
{
    return netstats_prepare_stats(NETSTATS_T_NEIGHBOR, rpt);
}
