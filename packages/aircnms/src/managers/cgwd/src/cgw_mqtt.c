#include <limits.h>
#include <stdio.h>
#include <zlib.h>
#include <jansson.h>

#include "os_time.h"
#include "os_nif.h"
#include "mosqev.h"
#include "log.h"
#include "ds_dlist.h"
#include "memutil.h"

#include "stats_report.h"
#include "cgw.h"
#include "device_config.h"
#include "info_events.h"
#include <pthread.h>

// --- Globals ---
static ev_timer g_reconnect_timer;
static ev_async g_queue_async;

static bool g_mqtt_worker_running = false;
static bool g_mqtt_connected = false;
static pthread_mutex_t mqtt_lock = PTHREAD_MUTEX_INITIALIZER;


// Forward declarations for info event JSON parsing functions
bool cgw_parse_client_info_json(client_info_event_t *client_info, char *data, uint64_t timestamp_ms);
bool cgw_parse_vif_info_json(vif_info_event_t *vif_info, char *data, uint64_t timestamp_ms);
bool cgw_parse_device_info_json(device_info_event_t *device_info, char *data, uint64_t timestamp_ms);
void cgw_restart_mqtt_worker(void);
void free_netstats_stats(netstats_stats_t *stats);  // Forward declaration

#define MODULE_ID LOG_MODULE_ID_MAIN
#define MQTT_BROKER_TOPIC       "test"

#define STATS_MQTT_PORT         1883
#define STATS_MQTT_QOS          0
#define STATS_MQTT_INTERVAL     1   /* Report interval in seconds */
#define STATS_MQTT_RECONNECT    5  /* Reconnect interval -- seconds */
#define MAX_MQTT_SEND_DATA_SIZE  90000
#define MAX_MQTT_DATA_TOPICS     4
#define STATS_MQTT_BUF_SZ        (128*1024)
/* Global MQTT instance */
static mosqev_t         cgw_mqtt;
static bool             cgw_mosquitto_init = false;
static bool             cgw_mosqev_init = false;
static int64_t          cgw_mqtt_reconnect_ts = 0;
static char             cgw_mqtt_broker[HOST_NAME_MAX];
static char             cgw_mqtt_topic[HOST_NAME_MAX] = MQTT_BROKER_TOPIC;
static int              cgw_mqtt_port;
static int              cgw_mqtt_qos = STATS_MQTT_QOS;
static uint8_t          cgw_mqtt_compress = 0;
static uint64_t         cgw_mqtt_last_manual_reconnect_ms;
static const int        s_reconnect_backoff_ladder[] = {60, 120, 300, 600};
static int              s_reconnect_ladder_idx = 0;
static int              cgw_agg_stats_interval;
air_device_t air_dev;

typedef enum json_report {
    JSON_REPORT_DEVICE = 0,
    JSON_REPORT_CLIENT = 1,
    JSON_REPORT_VIF = 2,
    JSON_REPORT_NEIGHBOR = 3
} json_report_type;

bool cgw_publish_json_qos(char *data, char *topic, int qos, bool retain);
void cgw_mqtt_subscriber_set(mosqev_t *self, void *data, const char *topic, void *msg, size_t msglen);

bool cgw_mqtt_is_connected()
{
    return mosqev_is_connected(&cgw_mqtt);
}

/**
 * Set MQTT settings
 */
bool cgw_mqtt_set(const char *broker, const char *port, const char *topic, const char *qos, int compress)
{
    const char *new_broker;
    int new_port;
    bool broker_changed = false;

    cgw_mqtt_compress = compress;

    // broker address
    new_broker = broker ? broker : "";
    if (strcmp(cgw_mqtt_broker, new_broker)) broker_changed = true;
    STRSCPY(cgw_mqtt_broker, new_broker);

    // broker port
    new_port = port ? atoi(port) : STATS_MQTT_PORT;
    if (cgw_mqtt_port != new_port) broker_changed = true;
    cgw_mqtt_port = new_port;

    // qos
    if (qos)
    {
        cgw_mqtt_qos = atoi(qos);
    }
    else
    {
        cgw_mqtt_qos = STATS_MQTT_QOS;
    }

    // topic
    if (topic != NULL)
    {
        STRSCPY(cgw_mqtt_topic, topic);
    }
    else
    {
        cgw_mqtt_topic[0] = '\0';
    }

    LOGN("MQTT broker: '%s' port: %d topic: '%s' qos: %d compress: %d",
            cgw_mqtt_broker, cgw_mqtt_port, cgw_mqtt_topic, cgw_mqtt_qos, cgw_mqtt_compress);

    // reconnect if broker changed
    if (broker_changed) {
        LOGN("MQTT broker changed - reconnecting...");
        if (cgw_mqtt_is_connected()) {
            // if already connected, disconnect first.
            mosqev_disconnect(&cgw_mqtt);
        }
        cgw_mqtt_reconnect();
    }

    return true;
}

bool cgw_mqtt_config_valid(void)
{
    if (strlen(air_dev.username) > 0) {
        strncpy(cgw_mqtt.username, air_dev.username, sizeof(cgw_mqtt.username) - 1);
        cgw_mqtt.username[sizeof(cgw_mqtt.username) - 1] = '\0';
    } else {
        cgw_mqtt.username[0] = '\0';
    }
    
    if (strlen(air_dev.password) > 0) {
        strncpy(cgw_mqtt.password, air_dev.password, sizeof(cgw_mqtt.password) - 1);
        cgw_mqtt.password[sizeof(cgw_mqtt.password) - 1] = '\0';
    } else {
        cgw_mqtt.password[0] = '\0';
    }
    
    return
        (strlen(cgw_mqtt_broker) > 0) &&
        (cgw_mqtt_port > 0 && cgw_mqtt_port <= 65535) &&
        (strlen(cgw_mqtt_topic) > 0) &&
        (strlen(air_dev.username) > 0) &&
        (strlen(air_dev.password) > 0);
}

void cgw_mqtt_stop(void)
{
    // Send offline status before graceful disconnect
    if (cgw_mqtt_is_connected()) {
        char offline_payload[512];
        build_status_payload_to_buf("Offline", offline_payload, sizeof(offline_payload));
        LOG(INFO, "[MQTT] Sending OFFLINE status before graceful disconnect: topic=%s retain=true qos=1", 
            stats_topic.status);
        cgw_publish_json_qos(offline_payload, stats_topic.status, 1, true);
        
        // Give time for message to be sent (100ms should be sufficient)
        usleep(100000);
    }
    
    if (cgw_mosqev_init) mosqev_del(&cgw_mqtt);
    if (cgw_mosquitto_init) mosquitto_lib_cleanup();

    cgw_mosqev_init = cgw_mosquitto_init = false;

    LOG(NOTICE, "Closing MQTT connection.");
}

// Global variable to store the previous timestamp
static uint64_t prev_timestamp = 0;

uint64_t get_current_timestamp_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);  // Get time since system boot
    return (uint64_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);  // Convert to milliseconds
}

#define CGW_MQTT_MANUAL_RECONNECT_INTERVAL_MS 30000ULL

cgw_mqtt_reconnect_result_t cgw_mqtt_request_reconnect(uint32_t *retry_after)
{
    uint64_t now = get_current_timestamp_ms();
    uint64_t elapsed;

    if (retry_after)
        *retry_after = 0;
    if (!g_mqtt_worker_running || !cgw_mosqev_init || !cgw_mqtt_config_valid())
        return CGW_MQTT_RECONNECT_NOT_READY;
    if (cgw_mqtt_last_manual_reconnect_ms) {
        elapsed = now - cgw_mqtt_last_manual_reconnect_ms;
        if (elapsed < CGW_MQTT_MANUAL_RECONNECT_INTERVAL_MS) {
            if (retry_after)
                *retry_after = (uint32_t)((CGW_MQTT_MANUAL_RECONNECT_INTERVAL_MS -
                                           elapsed + 999) / 1000);
            return CGW_MQTT_RECONNECT_THROTTLED;
        }
    }
    cgw_mqtt_last_manual_reconnect_ms = now;
    cgw_mqtt_reconnect_ts = 0;
    s_reconnect_ladder_idx = 0;
    if (cgw_mqtt_is_connected())
        mosqev_disconnect(&cgw_mqtt);
    cgw_restart_mqtt_worker();
    return CGW_MQTT_RECONNECT_ACCEPTED;
}

bool cgw_publish_json_qos(char *data, char *topic, int qos, bool retain)
{
    mosqev_t *mqtt = &cgw_mqtt;
    void *mbuf;
    size_t mlen;
    bool ret;

    mbuf = data;
    mlen = strlen(data);

    uint64_t current_timestamp = get_current_timestamp_ms();
    uint64_t time_diff = (prev_timestamp > 0) ? (current_timestamp - prev_timestamp) : 0;
    prev_timestamp = current_timestamp;  // Update previous timestamp

    LOG(DEBUG, "MQTT: Publishing %zu bytes to topic-%s qos=%d retain=%d | Time since last publish: %" PRIu64 " ms", 
        mlen, topic, qos, retain, time_diff);

    //ret = mosqev_publish(mqtt, NULL, topic, mlen, mbuf, qos, retain);

    pthread_mutex_lock(&mqtt_lock);

    ret = mosqev_publish(
            mqtt,
            NULL,
            topic,
            mlen,
            mbuf,
            qos,
            retain);

    pthread_mutex_unlock(&mqtt_lock);

    if(ret == false) {
        //cgw_mqtt_reconnect();
        g_mqtt_connected = false;
        cgw_restart_mqtt_worker();
    }
 
    return ret;
}

bool cgw_publish_json(char *data, char *topic)
{
    return cgw_publish_json_qos(data, topic, 1, false);
}


static size_t deserialize_client_data(client_report_data_t *client, const uint8_t *buffer, size_t buffer_size)
{
    size_t offset = 0;

    if (buffer_size < sizeof(client->timestamp_ms) + sizeof(client->n_client)) {
        LOG(ERR, "Buffer too small for header");
        return 0;
    }

    // Deserialize timestamp
    memcpy(&client->timestamp_ms, buffer + offset, sizeof(client->timestamp_ms));
    offset += sizeof(client->timestamp_ms);

    // Deserialize n_client
    memcpy(&client->n_client, buffer + offset, sizeof(client->n_client));
    offset += sizeof(client->n_client);

    // Validate n_client
    if (client->n_client < 0 || client->n_client > MAX_CLIENTS) {
        LOG(ERR, "Invalid n_client: %d", client->n_client);
        return 0;
    }

    // Deserialize records
    if (client->n_client > 0) {
        // SECURITY_FIX: Issue #10 - Check for integer overflow
        if (client->n_client > SIZE_MAX / sizeof(client_record_t)) {
            LOG(ERR, "SECURITY_FIX: Integer overflow in records_size calculation (n_client=%d)", client->n_client);
            return 0;
        }
        
        size_t records_size = client->n_client * sizeof(client_record_t);

        if (offset + records_size > buffer_size) {
            LOG(ERR, "Buffer too small for records");
            return 0;
        }

        // Allocate memory for records
        client->record = (client_record_t *)malloc(records_size);
        if (!client->record) {
            LOG(ERR, "Failed to allocate memory for records");
            return 0;
        }
        client->capacity = client->n_client;

        memcpy(client->record, buffer + offset, records_size);
        offset += records_size;
    } else {
        client->record = NULL;
        client->capacity = 0;
    }

    return offset;
}


// Decompress and deserialize netstats_stats_t
bool decompress_deserialize_netstats_stats(const uint8_t *compressed_data, size_t compressed_size,
                                           netstats_stats_t *stats)
{
    if (!compressed_data || !stats || compressed_size == 0) {
        LOG(ERR, "Invalid parameters for decompression");
        return false;
    }

    uint8_t decompressed_data[STATS_MQTT_BUF_SZ];
    uLongf decompressed_size = sizeof(decompressed_data);

    // Decompress
    if (uncompress(decompressed_data, &decompressed_size, compressed_data, compressed_size) != Z_OK) {
        LOG(ERR, "Decompression failed");
        return false;
    }

    size_t offset = 0;

    // Deserialize type
    if (offset + sizeof(stats->type) > decompressed_size) {
        LOG(ERR, "Buffer too small for type");
        return false;
    }
    memcpy(&stats->type, decompressed_data + offset, sizeof(stats->type));
    offset += sizeof(stats->type);

    // Deserialize size
    if (offset + sizeof(stats->size) > decompressed_size) {
        LOG(ERR, "Buffer too small for size");
        return false;
    }
    memcpy(&stats->size, decompressed_data + offset, sizeof(stats->size));
    offset += sizeof(stats->size);

    // Deserialize based on type
    switch (stats->type) {
        case NETSTATS_T_CLIENT:
        {
            size_t client_size = deserialize_client_data(&stats->u.client,
                                                         decompressed_data + offset,
                                                         decompressed_size - offset);
            if (client_size == 0) {
                LOG(ERR, "Failed to deserialize client data");
                free_netstats_stats(stats);  // FIX: Free nested allocations on error
                return false;
            }
            offset += client_size;
            break;
        }

        case NETSTATS_T_DEVICE:
        case NETSTATS_T_VIF:
        case NETSTATS_T_NEIGHBOR:
        {
            if (offset + stats->size > decompressed_size) {
                LOG(ERR, "Buffer too small for data");
                free_netstats_stats(stats);  // FIX: Free nested allocations on error
                return false;
            }
            memcpy(&stats->u, decompressed_data + offset, stats->size);
            offset += stats->size;
            break;
        }

        default:
            LOG(ERR, "Unknown stats type: %d", stats->type);
            free_netstats_stats(stats);  // FIX: Free nested allocations on error
            return false;
    }

    return true;
}

// Helper to free deserialized stats
void free_netstats_stats(netstats_stats_t *stats)
{
    if (!stats) return;

    if (stats->type == NETSTATS_T_CLIENT) {
        if (stats->u.client.record) {
            LOG(DEBUG, "Freeing client records at %p", stats->u.client.record);
            free(stats->u.client.record);
            stats->u.client.record = NULL;
        }
    }
    // Add other cleanup if needed for other types
}


bool cgw_send_stats_json(cgw_item_t *qi)
{
    bool ret;

    if (!qi || !qi->buf || qi->size == 0) {
        LOG(ERR, "Invalid cgw_item_t");
        return false;
    }

    // Allocate stats structure
    netstats_stats_t *stats = (netstats_stats_t *)calloc(1, sizeof(netstats_stats_t));
    if (!stats) {
        LOG(ERR, "Failed to allocate netstats_stats_t");
        return false;
    }

    // Decompress and deserialize
    if (!decompress_deserialize_netstats_stats(qi->buf, qi->size, stats)) {
        LOG(ERR, "Failed to decompress/deserialize stats");
        free(stats);
        return false;
    }

    char data[MAX_MQTT_SEND_DATA_SIZE] = {0};
    
    // Helper to get type string
    const char *msgtype_str = "unknown";
    switch (stats->type) {
        case NETSTATS_T_NEIGHBOR: msgtype_str = "neighbor"; break;
        case NETSTATS_T_CLIENT: msgtype_str = "client"; break;
        case NETSTATS_T_DEVICE: msgtype_str = "device"; break;
        case NETSTATS_T_VIF: msgtype_str = "vif"; break;
        default: break;
    }
    
    switch (stats->type) {
        case NETSTATS_T_DEVICE: 
            {
                ret = cgw_parse_device_newjson(&stats->u.device, data);
                size_t msglen = strlen(data);
                LOG(INFO, "CGWD->CLOUD: msgtype=%s msglen=%zu", msgtype_str, msglen);
                ret = cgw_publish_json(data, stats_topic.device);

            }break;
        case NETSTATS_T_VIF: 
            {
                ret = cgw_parse_vif_newjson(&stats->u.vif, data);
                size_t msglen = strlen(data);
                LOG(INFO, "CGWD->CLOUD: msgtype=%s msglen=%zu", msgtype_str, msglen);
                ret = cgw_publish_json(data, stats_topic.vif);

            }break;
        case NETSTATS_T_CLIENT:
        {
            client_report_data_t *client = &stats->u.client;
            ret = cgw_parse_client_newjson(client, data);
            size_t msglen = strlen(data);
            LOG(INFO, "CGWD->CLOUD: msgtype=%s msglen=%zu", msgtype_str, msglen);
            ret = cgw_publish_json(data, stats_topic.client);
            break;
        }
        case NETSTATS_T_NEIGHBOR: 
        {
            neighbor_report_data_t *neighbor = &stats->u.neighbor;
            ret = cgw_parse_neighbor_newjson(neighbor, data);
            size_t msglen = strlen(data);
            char topic[256];
            sprintf(topic, "dev/to/cloud/%s/%s/event", air_dev.device_id, air_dev.serial_num);
            LOG(INFO, "CGWD->CLOUD: msgtype=%s entries=%d msglen=%zu", msgtype_str, neighbor->n_entry, msglen);
            ret = cgw_publish_json(data, topic);

        }break;
    }

    free_netstats_stats(stats);
    free(stats);
    return ret;
}

bool cgw_send_event_cloud(cgw_item_t *qi)
{
    bool ret = false;
    char data[MAX_MQTT_SEND_DATA_SIZE] = {0};
    char topic[100] = {0};

    if (!qi || !qi->buf || qi->size == 0) {
        LOG(ERR, "cgw_send_event_cloud: Invalid parameters");
        return false;
    }
    
    if(!cgw_mqtt_is_connected()){
        return true;
    }

    // Check data type explicitly
    if (qi->req.data_type == CGW_DATA_INFO_EVENT) {
        // This is an info event from netevd
        
        // Basic validation
        if (qi->size < sizeof(info_event_type_t) + sizeof(uint64_t)) {
            LOG(ERR, "Info event too small: size=%zu", qi->size);
            return false;
        }

        uint8_t *ptr = (uint8_t *)qi->buf;

        // Extract type
        info_event_type_t type;
        memcpy(&type, ptr, sizeof(type));
        ptr += sizeof(type);

        // Extract timestamp
        uint64_t timestamp_ms;
        memcpy(&timestamp_ms, ptr, sizeof(timestamp_ms));
        ptr += sizeof(timestamp_ms);

        LOG(DEBUG, "cgw_send_event_cloud: Processing info event type=%d timestamp=%" PRIu64,
            type, timestamp_ms);

        // Parse based on type
        int qos = 1; // Default QoS for info events
        switch (type) {
            case INFO_EVENT_CLIENT:
            {
                client_info_event_t client;
                memcpy(&client, ptr, sizeof(client));

                ret = cgw_parse_client_info_json(&client, data, timestamp_ms);
                strncpy(topic, stats_topic.client, sizeof(topic) - 1);
                topic[sizeof(topic) - 1] = '\0';
                qos = 1; // Client info events use QoS 1
                break;
            }
            case INFO_EVENT_VIF:
            {
                vif_info_event_t vif;
                memcpy(&vif, ptr, sizeof(vif));

                ret = cgw_parse_vif_info_json(&vif, data, timestamp_ms);
                strncpy(topic, stats_topic.vif, sizeof(topic) - 1);
                topic[sizeof(topic) - 1] = '\0';
                qos = 1; // VIF info events use QoS 1
                break;
            }
            case INFO_EVENT_DEVICE:
            {
                device_info_event_t device;
                memcpy(&device, ptr, sizeof(device));

                ret = cgw_parse_device_info_json(&device, data, timestamp_ms);
                sprintf(topic, "dev/to/cloud/%s/%s/event", air_dev.device_id, air_dev.serial_num);

                break;
            }
            case INFO_EVENT_CLIENT_HISTORY:
            {
                client_history_event_t hdr;

                if ((size_t)(ptr - (uint8_t *)qi->buf) +
                    sizeof(hdr) > qi->size) {

                    LOG(ERR,
                        "History event header truncated");

                    return false;
                }

                memcpy(&hdr, ptr, sizeof(hdr));

                ptr += sizeof(hdr);

                if (hdr.len == 0) {

                    LOG(ERR,
                        "Invalid history json length");

                    return false;
                }

                if ((size_t)(ptr - (uint8_t *)qi->buf) +
                    hdr.len > qi->size) {

                    LOG(ERR,
                        "History JSON exceeds message size");

                    return false;
                }

                if (hdr.len >= sizeof(data)) {

                    LOG(ERR,
                        "History JSON too large: %u",
                        hdr.len);

                    return false;
                }

                memcpy(data, ptr, hdr.len);

                data[hdr.len] = '\0';

                snprintf(topic,
                        sizeof(topic),
                        "dev/to/cloud/%s/%s/website_usage",
                        air_dev.device_id,
                        air_dev.serial_num);

                topic[sizeof(topic) - 1] = '\0';

                qos = 1;

                ret = true;

                break;
            }
            default:
                LOG(ERR, "Unknown info event type: %d", type);
                return false;
        }

        if (ret) {
            size_t msglen = strlen(data);
            LOG(INFO, "NETINFO->CLOUD: msgtype=info_event type=%d msglen=%zu qos=%d topic=%s",
                type, msglen, qos, topic);
            ret = cgw_publish_json_qos(data, topic, qos, false);
        } else {
            LOG(ERR, "Failed to parse info event JSON for type=%d", type);
        }

        return ret;
    } 
    else if (qi->req.data_type == CGW_DATA_EVENT) {
        // Regular event (from cmdexecd/alrmd)
        if (qi->size < sizeof(event_msg_t)) {
            LOG(ERR, "Event message too small");
            return false;
        }

        event_msg_t event;
        memcpy(&event, qi->buf, qi->size);

        ret = cgw_parse_event_newjson(&event, data);

        sprintf(topic, "dev/to/cloud/%s/%s/event", air_dev.device_id, air_dev.serial_num);
        topic[sizeof(topic) - 1] = '\0';
    
        LOG(INFO, "CGWD->CLOUD: msgtype=%s topic=%s ","event" , topic);
        ret = cgw_publish_json(data, topic);
        return ret;
    } else {
        LOG(ERR, "cgw_send_event_cloud: Unknown data type %d", qi->req.data_type);
        return false;
    }
}

bool cgw_send_config_cloud(cgw_item_t *qi)
{
    device_conf_t conf; 
    char data[512];

    // Ensure the buffer size matches the expected structure size
    if (qi->size < sizeof(device_conf_t)) {
        return false; // Error: Insufficient data
    }

    // Copy the buffer data into the structure
    memcpy(&conf, qi->buf, qi->size);
    cgw_parse_config_newjson(&conf, data);
        
    cgw_publish_json(data, stats_topic.config);

    return true;
}

// cgw_mqtt_send_message removed (unused)

void cgw_mqtt_publish_queue()
{
    LOGD("total %d elements queued for transmission.\n", cgw_queue_length());

    cgw_item_t *qi = NULL;
    cgw_item_t *next = NULL;

    // publish the rest of messages
    for (qi = ds_dlist_head(&g_cgw_queue.queue); qi != NULL; qi = next)
    {
        next = ds_dlist_next(&g_cgw_queue.queue, qi);
        if( cgw_send_stats_json(qi)) {
            cgw_queue_remove(qi);
        } else {
            LOGE("Publish message failed.\n");
        }
    }
}

void cgw_mqtt_reconnect()
{
    mosqev_t *mqtt = &cgw_mqtt;
    bool result;

    /*
     * Reconnect handler
     */
    if (cgw_mqtt_config_valid())
    {
        if (!mosqev_is_connected(mqtt))
        {
            if (cgw_mqtt_reconnect_ts < ticks())
            {
                LOG(DEBUG, "Connecting to %s ...\n", cgw_mqtt_broker);
                result = mosqev_connect(&cgw_mqtt, cgw_mqtt_broker, cgw_mqtt_port);
                if (!result)
                {
                    int delay_sec = s_reconnect_backoff_ladder[s_reconnect_ladder_idx];
                    cgw_mqtt_reconnect_ts = ticks() + TICKS_S(delay_sec);
                    int num_ladder_steps = (int)(sizeof(s_reconnect_backoff_ladder)/sizeof(s_reconnect_backoff_ladder[0]));
                    s_reconnect_ladder_idx = (s_reconnect_ladder_idx + 1) % num_ladder_steps;
                    LOG(INFO, "[MQTT] Connection failed, retrying in %ds (next ladder level %d)", delay_sec, s_reconnect_ladder_idx);
                    LOGE("Connecting.\n");
                    return;
                }
                else
                {
                    s_reconnect_ladder_idx = 0;
                    cgw_mqtt_reconnect_ts = ticks() + TICKS_S(STATS_MQTT_RECONNECT);
                    int ret;
                    for (int i = 0; i < cgw_topic_lst.n_topic; i++) {
                        ret = mosquitto_subscribe(mqtt->me_mosq, NULL, cgw_topic_lst.topic[i], 1);
                        if (ret) {
                            LOG(ERR, "Error subscribing to topic %s: %d", cgw_topic_lst.topic[i], ret);
                            break;
                        } else {
                            LOG(INFO, "Subscribed to topic %s", cgw_topic_lst.topic[i]);
                        }
                    }                    

                }

            }
            else
            {
                LOG(DEBUG, "Not connected, will reconnect in %d secs", (int)TICKS_TO_S(cgw_mqtt_reconnect_ts - ticks()));
            }
        }
    }
    else
    {
        /*
         * Config is invalid, but we're connected. Disconnect at once!
         */
        cgw_mqtt_reconnect_ts = 0;

        if (mosqev_is_connected(mqtt))
        {
            mosqev_disconnect(mqtt);
            return;
        }
    }
}

int cgw_send_status_online(void)
{
    int ret;
    char online_payload[512];
    
    build_status_payload_to_buf("Online", online_payload, sizeof(online_payload));
    LOG(INFO, "[MQTT] Sending ONLINE status: topic=%s retain=false qos=1", stats_topic.status);
    ret = cgw_publish_json_qos(online_payload, stats_topic.status, 1, false);
    
    if (ret) {
        LOG(INFO, "[MQTT] Online status sent successfully");
    } else {
        LOG(ERR, "[MQTT] Failed to send online status");
    }
    
    return ret;
}


// --- Callbacks ---

// Disconnect callback: log disconnect events
// static void cgw_mqtt_on_disconnect(mosqev_t *self, void *data, int rc)
// {
//     (void)self;
//     (void)data;
    
//     if (rc == 0) {
//         LOG(INFO, "[MQTT] Disconnect callback: rc=%d (graceful - will message NOT sent by broker)", rc);
//     } else {
//         LOG(INFO, "[MQTT] Disconnect callback: rc=%d (unexpected - will message WILL be sent by broker)", rc);
//     }
// }


static void cgw_mqtt_on_connect(mosqev_t *self, void *data, int rc)
{
    (void)self;
    (void)data;

    if (rc == 0) {
        g_mqtt_connected = true;
        LOG(NOTICE, "[MQTT] Successfully connected to broker '%s:%d' (ClientID: %s)",
            cgw_mqtt_broker, cgw_mqtt_port, air_dev.device_id);
        cgw_ubus_emit_mqtt_event(true, rc, "CONNECTED");
    } else {
        g_mqtt_connected = false;
        LOG(ERR, "[MQTT] Connection failed to broker '%s:%d': rc=%d (%s)",
            cgw_mqtt_broker, cgw_mqtt_port, rc, mosquitto_strerror(rc));
        cgw_ubus_emit_mqtt_event(false, rc, "CONNECT_FAILED");
    }
}

static void cgw_mqtt_on_disconnect(mosqev_t *self, void *data, int rc)
{
    (void)self;
    (void)data;

    g_mqtt_connected = false;
    cgw_ubus_emit_mqtt_event(false, rc,
                             rc == 0 ? "GRACEFUL_DISCONNECT" :
                                       "UNEXPECTED_DISCONNECT");

    LOG(ERR,
        "[MQTT] disconnected rc=%d err=%s",
        rc,
        mosquitto_strerror(rc));

    if (rc == 0) {
        LOG(INFO,
            "[MQTT] Graceful disconnect");
    } else {
        LOG(INFO,
            "[MQTT] Unexpected disconnect - broker will send WILL");
    }

    cgw_restart_mqtt_worker();
}

void cgw_restart_mqtt_worker(void)
{
    ev_timer_start(EV_DEFAULT, &g_reconnect_timer);
}

// Timer: try reconnect every 2s until connected
static void reconnect_cb(EV_P_ ev_timer *w, int revents) {
    (void)w; (void)revents;

    if (!g_mqtt_worker_running) return;

    cgw_mqtt_reconnect();
    g_mqtt_connected = cgw_mqtt_is_connected();

    if (g_mqtt_connected) {
        LOG(INFO, "[MQTT] Connected");
        s_reconnect_ladder_idx = 0;
        cgw_ubus_emit_mqtt_event(true, 0, "CONNECTED");
        
        // Retry online status up to 3 times to ensure delivery
        int retry = 0;
        bool status_sent = false;
        while (retry < 3) {
            if (cgw_send_status_online()) {
                status_sent = true;
                break;
            }
            LOG(WARNING, "[MQTT] Failed to send online status, retry %d/3", retry + 1);
            usleep(100000); // 100ms delay between retries
            retry++;
        }
        
        if (!status_sent) {
            LOG(ERR, "[MQTT] Failed to send online status after 3 retries");
        }
        
        ev_timer_stop(EV_A_ w); // stop reconnect timer once connected
    } else {
        LOG(DEBUG, "[MQTT] Not connected, will retry...");
    }
}

// Async: wake when new items arrive in queue
static void queue_cb(EV_P_ ev_async *w, int revents) {
    (void)w; (void)revents;

    if (!g_mqtt_worker_running) return;

    if (!g_mqtt_connected) {
        LOG(DEBUG, "[MQTT] Skip publish, not connected");
        return;
    }

    // Drain queue
    cgw_mqtt_publish_queue();
}

// --- Public API ---
// Called by producers when they add to queue
void cgw_mqtt_signal_new_item(void) {
    if (EV_DEFAULT) {
        ev_async_send(EV_DEFAULT, &g_queue_async);
    }
}

bool cgw_mqtt_start_worker(void) 
{
    if (g_mqtt_worker_running) {
        return true; // already running
    }

    g_mqtt_worker_running = true;
    g_mqtt_connected = false;

    // Setup reconnect timer (start immediately, repeat every 2s)
    ev_timer_init(&g_reconnect_timer, reconnect_cb, 0., 2.);
    ev_timer_start(EV_DEFAULT, &g_reconnect_timer);

    // Setup async signal for new queue items
    ev_async_init(&g_queue_async, queue_cb);
    ev_async_start(EV_DEFAULT, &g_queue_async);

    LOG(INFO, "[MQTT] Worker started");

    return true;
}

void cgw_mqtt_stop_worker(void) {
    if (!g_mqtt_worker_running) return;

    g_mqtt_worker_running = false;

    LOG(INFO, "[MQTT] Worker stopped");
}


void uci_get_mqtt_params()
{
#define UCI_BUF_LEN 256
    char buf[UCI_BUF_LEN];
    size_t len;
    int ip1 = 0, ip2 = 0, ip3 = 0, ip4 = 0;

    memset(buf, 0, sizeof(buf));
    cmd_buf("uci get aircnms.@aircnms[0].ipaddr", buf, (size_t)UCI_BUF_LEN);
    len = strlen(buf);
    if (len == 0)
    {
        LOGI("%s: No uci ipaddr found", __func__);
        return;
    }
    // Strip any trailing whitespace or newline characters from cmd_buf output
    while (len > 0 && (buf[len - 1] == '\r' || buf[len - 1] == '\n' || buf[len - 1] == ' ' || buf[len - 1] == '\t')) {
        buf[--len] = '\0';
    }
    if (len == 0)
    {
        LOGI("%s: No valid uci ipaddr found", __func__);
        return;
    }

    int ret_ip = sscanf(buf, "%d.%d.%d.%d", &ip1, &ip2, &ip3, &ip4);
    if (ret_ip == 4 && (ip1 >= 0 && ip1 <= 255) && (ip2 >= 0 && ip2 <= 255) &&
        (ip3 >= 0 && ip3 <= 255) && (ip4 >= 0 && ip4 <= 255)) {
        snprintf(cgw_mqtt_broker, sizeof(cgw_mqtt_broker), "%d.%d.%d.%d", ip1, ip2, ip3, ip4);
    } else {
        // Domain name or hostname
        STRSCPY(cgw_mqtt_broker, buf);
    }

    memset(buf, 0, sizeof(buf));
    cmd_buf("uci get aircnms.@aircnms[0].port", buf, (size_t)UCI_BUF_LEN);
    len = strlen(buf);
    if (len == 0)
    {
        LOGI("%s: No uci port found", __func__);
        return;
    }
    sscanf(buf, "%d", &cgw_mqtt_port);

    memset(buf, 0, sizeof(buf));
    cmd_buf("uci get aircnms.@aircnms[0].interval", buf, (size_t)UCI_BUF_LEN);
    len = strlen(buf);
    if (len == 0)
    {
        LOGI("%s: No uci interval found", __func__);
    }
    sscanf(buf, "%d", &cgw_agg_stats_interval);

    
    memset(buf, 0, sizeof(buf));
    cmd_buf("uci get aircnms.@aircnms[0].device_id", buf, (size_t)UCI_BUF_LEN);
    len = strlen(buf);
    if (len == 0)
    {
        LOGI("%s: No uci device_id found", __func__);
        return;
    }
    sscanf(buf, "%31s", air_dev.device_id);

    memset(buf, 0, sizeof(buf));
    cmd_buf("uci get aircnms.@aircnms[0].serial_num", buf, (size_t)UCI_BUF_LEN);
    len = strlen(buf);
    if (len == 0)
    {
        LOGI("%s: No uci serial_num found", __func__);
        return;
    }
    sscanf(buf, "%31s", air_dev.serial_num);

    memset(buf, 0, sizeof(buf));
    cmd_buf("uci get aircnms.@aircnms[0].macaddr", buf, (size_t)UCI_BUF_LEN);
    len = strlen(buf);
    if (len == 0)
    {
        LOGI("%s: No uci macaddr found", __func__);
        return;
    }
    sscanf(buf, "%31s", air_dev.macaddr);
    
    memset(buf, 0, sizeof(buf));
    cmd_buf("uci get aircnms.@aircnms[0].org_id", buf, (size_t)UCI_BUF_LEN);
    len = strlen(buf);
    if (len == 0)
    {
        LOGI("%s: No uci org_id found", __func__);
        return;
    }
    sscanf(buf, "%127s", air_dev.org_id);
    
    memset(buf, 0, sizeof(buf));
    cmd_buf("uci get aircnms.@aircnms[0].network_id", buf, (size_t)UCI_BUF_LEN);
    len = strlen(buf);
    if (len == 0)
    {
        LOGI("%s: No uci netwrk_id found", __func__);
        return;
    }
    sscanf(buf, "%127s", air_dev.netwrk_id);

    memset(buf, 0, sizeof(buf));
    cmd_buf("uci get aircnms.@aircnms[0].username", buf, (size_t)UCI_BUF_LEN);
    len = strlen(buf);
    if (len == 0)
    {
        LOGI("%s: No uci username found", __func__);
        return;
    }
    sscanf(buf, "%127s", air_dev.username);

    memset(buf, 0, sizeof(buf));
    cmd_buf("uci get aircnms.@aircnms[0].password", buf, (size_t)UCI_BUF_LEN);
    len = strlen(buf);
    if (len == 0)
    {
        LOGI("%s: No uci password found", __func__);
        return;
    }
    sscanf(buf, "%127s", air_dev.password);

    return;
}

static void cgw_mqtt_log_cbk(
        mosqev_t *self,
        void *data,
        int level,
        const char *msg)
{
    (void)self;
    (void)data;

    /* Suppress routine internal packet traces (PINGREQ, PINGRESP, PUBLISH, PUBACK) */
    if (level == 16 /* MOSQ_LOG_DEBUG */ ||
        level == 1  /* MOSQ_LOG_INFO */ ||
        level == 2  /* MOSQ_LOG_NOTICE */) {
        return;
    }

    if (level & 8 /* MOSQ_LOG_ERR */) {
        LOG(ERR, "[MQTT_LIB] %s", msg);
    } else if (level & 4 /* MOSQ_LOG_WARNING */) {
        LOG(WARN, "[MQTT_LIB] %s", msg);
    }
}

bool cgw_mqtt_init(void)
{
    char cID[64];
    char offline_payload[512];
    mosquitto_lib_init();
    cgw_mosquitto_init = true;

    cgw_update_topic_lst(&cgw_topic_lst);
    cgw_get_stats_topic_aircnms(&stats_topic);
    if (true != osp_unit_id_get(cID, sizeof(cID))) {
        LOGE("acquiring device id number\n");
        goto error;
    }
    
    uci_get_mqtt_params();
    strncpy(cID, air_dev.device_id, sizeof(cID));
    if (!mosqev_init(&cgw_mqtt, cID, EV_DEFAULT, NULL))
    {
        LOGE("initializing MQTT library.\n");
        goto error;
    }
    mosqev_log_cbk_set(&cgw_mqtt, cgw_mqtt_log_cbk);

    build_status_payload_to_buf("Offline", offline_payload, sizeof(offline_payload));
    
    if (!mosqev_set_will(&cgw_mqtt, stats_topic.status, offline_payload, 1, false))
    {
        LOG(ERR, "Failed to set MQTT Will");
    }
    
    // Register callbacks
    mosqev_connect_cbk_set(&cgw_mqtt, cgw_mqtt_on_connect);
    mosqev_message_cbk_set(&cgw_mqtt, cgw_mqtt_subscriber_set);
    mosqev_disconnect_cbk_set(&cgw_mqtt, cgw_mqtt_on_disconnect);

    cgw_mosqev_init = true;

    LOGD("QM MQTT worker enabled; periodic timer disabled");

    return true;

error:
    cgw_mqtt_stop();

    return false;
}
