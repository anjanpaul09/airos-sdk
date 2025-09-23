#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

#include "sm.h"

#define STATS_MQTT_BUF_SZ        (128*1024)    // 128 KB
static uint8_t          sm_mqtt_buf[STATS_MQTT_BUF_SZ];

size_t serialize_compress_sm_stats(const sm_stats_t *stats, uint8_t *compressed_data, size_t compressed_max_size)
{
    if (!stats || !compressed_data) return 0;

    uint8_t serialized_data[sizeof(sm_stats_t)];

    /* Serialize: Convert struct to a byte array */
    memcpy(serialized_data, stats, sizeof(sm_stats_t));

    /* Compress the serialized data */
    uLongf compressed_size = compressed_max_size;
    if (compress2(compressed_data, &compressed_size, serialized_data, sizeof(sm_stats_t), Z_BEST_SPEED) != Z_OK) {
        fprintf(stderr, "Compression failed\n");
        return 0;
    }

    return compressed_size;  // Return actual compressed size
}

bool sm_copy_stats(sm_stats_t *dst, void *sts)
{
    if (!dst || !sts) {
        printf("Error: NULL pointer detected in sm_copy_stats\n");
        return false;
    }

    switch (dst->type)
    {
        case SM_T_DEVICE:
        {
            device_report_data_t *report_data = (device_report_data_t *)sts;
            memcpy(&dst->u.device.record, &report_data->record, sizeof(device_record_t));
            dst->u.device.timestamp_ms = report_data->timestamp_ms;
            break;
        }

        case SM_T_VIF:
        {
            vif_report_data_t *report_data = (vif_report_data_t *)sts;
            memcpy(&dst->u.vif.record, &report_data->record, sizeof(vif_record_t));
            dst->u.vif.timestamp_ms = report_data->timestamp_ms;
            break;
        }

        case SM_T_CLIENT:
        {
            client_report_data_t *report_data = (client_report_data_t *)sts;

            // Copy timestamp
            dst->u.client.timestamp_ms = report_data->timestamp_ms;

            // Copy client count, ensuring it does not exceed MAX_CLIENTS
            dst->u.client.n_client = (report_data->n_client > MAX_CLIENTS) ? MAX_CLIENTS : report_data->n_client;

            // Copy client records safely
            memcpy(dst->u.client.record, report_data->record, dst->u.client.n_client * sizeof(client_record_t));

            break;
        }
        
        case SM_T_NEIGHBOR:
        {
            neighbor_report_data_t *report_data = (neighbor_report_data_t *)sts;

            // Copy timestamp
            dst->u.neighbor.timestamp_ms = report_data->timestamp_ms;

            // Copy client neighbor, ensuring it does not exceed MAX_NEIGHBOR
            dst->u.neighbor.n_entry = (report_data->n_entry > MAX_NEIGHBOUR) ? MAX_NEIGHBOUR : report_data->n_entry;

            // Copy neighbor records safely
            memcpy(dst->u.neighbor.record, report_data->record, dst->u.neighbor.n_entry * sizeof(neighbor_record_t));

            break;
        }

        default:
            LOG(ERR, "SM ""(Failed - Unknown stats type %d)", dst->type);
            return false;
    }

    return true;
}

bool sm_prepare_stats(SM_STATS_TYPE type, void * rpt)
{
    sm_stats_t s;
    long buf_len;
    
    /* set stats buffer type    */
    s.type = type;

    /* copy stats               */
    if (!sm_copy_stats(&s, rpt))
    {
        return false;
    }
    
    //printf("Ankit: stat type = %d\n", s.type);

    /* Ensure the struct fits in the buffer */
    if (sizeof(sm_stats_t) > STATS_MQTT_BUF_SZ)
    {
        LOG(ERR, "SM ""(Failed - sm_stats_t size exceeds sm_mqtt_buf size!)");
        printf("Error: sm_stats_t size exceeds sm_mqtt_buf size!\n");
        return false;
    }

    /* Serialize & Compress */
    buf_len = serialize_compress_sm_stats(&s, sm_mqtt_buf, STATS_MQTT_BUF_SZ);
    if (buf_len == 0) return false;

    /* mqtt publish */
    sm_mqtt_publish(buf_len, sm_mqtt_buf);

    return true;
}

/* Prepare device stats */
bool sm_put_device(device_report_data_t *rpt)
{
    return sm_prepare_stats(SM_T_DEVICE, rpt);
}

/* Prepare device stats */
bool sm_put_vif(vif_report_data_t *rpt)
{
    return sm_prepare_stats(SM_T_VIF, rpt);
}

bool sm_put_client(client_report_data_t *rpt)
{
    return sm_prepare_stats(SM_T_CLIENT, rpt);
}
        
bool sm_put_neighbor(neighbor_report_data_t *rpt)
{
    return sm_prepare_stats(SM_T_NEIGHBOR, rpt);
}
