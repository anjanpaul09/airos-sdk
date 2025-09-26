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

#include "report.h"
#include "qm.h"
#include "config.h"
#include "device_config.h"

#define MODULE_ID LOG_MODULE_ID_MAIN

#define STATS_MQTT_PORT         1883
#define STATS_MQTT_QOS          0
#define STATS_MQTT_INTERVAL     1   /* Report interval in seconds */
#define STATS_MQTT_RECONNECT    5  /* Reconnect interval -- seconds */
#define QM_LOG_TOPIC_PREFIX     "log"
#define MAX_MQTT_SEND_DATA_SIZE  50000
#define MAX_MQTT_DATA_TOPICS     4
/* Global MQTT instance */
static mosqev_t         qm_mqtt;
static bool             qm_mosquitto_init = false;
static bool             qm_mosqev_init = false;
static struct ev_timer  qm_mqtt_timer;
#ifdef CONFIG_LOG_REMOTE
static struct ev_timer  qm_mqtt_timer_log;
#endif
static int64_t          qm_mqtt_reconnect_ts = 0;
static char             qm_mqtt_broker[HOST_NAME_MAX];
static char             qm_mqtt_topic[HOST_NAME_MAX] = MQTT_BROKER_TOPIC;
static int              qm_mqtt_port;
static int              qm_mqtt_qos = STATS_MQTT_QOS;
static uint8_t          qm_mqtt_compress = 0;
static char             qm_log_topic[128];
static int              qm_log_interval = 0; // 0 = disabled
static int              qm_agg_stats_interval;
bool                    qm_log_enabled = false;

air_device_t air_dev;

typedef enum json_report {
    JSON_REPORT_DEVICE = 0,
    JSON_REPORT_CLIENT = 1,
    JSON_REPORT_VIF = 2,
    JSON_REPORT_NEIGHBOR = 3
} json_report_type;

void qm_mqtt_subscriber_set(void *__self, void *me_data, char *topic, char *payload, long payloadlen);

bool qm_mqtt_is_connected()
{
    return mosqev_is_connected(&qm_mqtt);
}

/**
 * Set MQTT settings
 */
bool qm_mqtt_set(const char *broker, const char *port, const char *topic, const char *qos, int compress)
{
    const char *new_broker;
    int new_port;
    bool broker_changed = false;

    qm_mqtt_compress = compress;

    // broker address
    new_broker = broker ? broker : "";
    if (strcmp(qm_mqtt_broker, new_broker)) broker_changed = true;
    STRSCPY(qm_mqtt_broker, new_broker);

    // broker port
    new_port = port ? atoi(port) : STATS_MQTT_PORT;
    if (qm_mqtt_port != new_port) broker_changed = true;
    qm_mqtt_port = new_port;

    // qos
    if (qos)
    {
        qm_mqtt_qos = atoi(qos);
    }
    else
    {
        qm_mqtt_qos = STATS_MQTT_QOS;
    }

    // topic
    if (topic != NULL)
    {
        STRSCPY(qm_mqtt_topic, topic);
    }
    else
    {
        qm_mqtt_topic[0] = '\0';
    }

    //Anjan: TODO: Mqtt tls disabled
#if 0
    /* Initialize TLS stuff */
    if (!mosqev_tls_opts_set(&qm_mqtt, SSL_VERIFY_PEER, MOSQEV_TLS_VERSION, mosqev_ciphers))
    {
        LOGE("Failed setting TLS options.\n");
        goto error;
    }

    if (!mosqev_tls_set(&qm_mqtt,
                target_tls_cacert_filename(),
                NULL,
                target_tls_mycert_filename(),
                target_tls_privkey_filename(),
                NULL))
    {
        LOGE("Failed setting TLS certificates.\n");
        goto error;
    }
#endif
    LOGN("MQTT broker: '%s' port: %d topic: '%s' qos: %d compress: %d",
            qm_mqtt_broker, qm_mqtt_port, qm_mqtt_topic, qm_mqtt_qos, qm_mqtt_compress);

    // reconnect if broker changed
    if (broker_changed) {
        LOGN("MQTT broker changed - reconnecting...");
        if (qm_mqtt_is_connected()) {
            // if already connected, disconnect first.
            mosqev_disconnect(&qm_mqtt);
        }
        qm_mqtt_reconnect();
    }

    return true;

//error:
   // qm_mqtt_stop();
   // return false;
}

bool qm_mqtt_config_valid(void)
{
    strcpy(qm_mqtt.username, air_dev.username);
    strcpy(qm_mqtt.password, air_dev.password);
    return
        (strlen(qm_mqtt_broker) > 0) &&
        (strlen(qm_mqtt_topic) > 0);
}

void qm_mqtt_stop(void)
{
    //mqtt_telog_fini();

    ev_timer_stop(EV_DEFAULT, &qm_mqtt_timer);
    qm_agg_stats_interval = STATS_MQTT_INTERVAL;

    if (qm_mosqev_init) mosqev_del(&qm_mqtt);
    if (qm_mosquitto_init) mosquitto_lib_cleanup();

    qm_mosqev_init = qm_mosquitto_init = false;

    LOG(NOTICE, "Closing MQTT connection.");
}

// Global variable to store the previous timestamp
static uint64_t prev_timestamp = 0;

uint64_t get_current_timestamp_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);  // Get time since system boot
    return (uint64_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);  // Convert to milliseconds
}

bool qm_publish_json(char *data, char *topic)
{
    mosqev_t *mqtt = &qm_mqtt;
    void *mbuf;
    size_t mlen;
    int ret;

    mbuf = data;
    mlen = strlen(data);

    uint64_t current_timestamp = get_current_timestamp_ms();
    uint64_t time_diff = (prev_timestamp > 0) ? (current_timestamp - prev_timestamp) : 0;
    prev_timestamp = current_timestamp;  // Update previous timestamp
    
    LOG(INFO,"MQTT: Publishing %zu bytes topic-%s | Time since last publish: %" PRIu64 " ms", mlen, topic, time_diff);

    //LOGI("MQTT: Publishing %zu bytes topic-%s", mlen, topic);
    ret = mosqev_publish(mqtt, NULL, topic, mlen, mbuf, 1, false);

    return ret;
}

/* Decompress & Deserialize sm_stats_t */
bool decompress_deserialize_sm_stats(const uint8_t *compressed_data, size_t compressed_size, sm_stats_t *stats)
{
    if (!compressed_data || !stats) return false;

    uLongf decompressed_size = sizeof(sm_stats_t);
    uint8_t decompressed_data[sizeof(sm_stats_t)];

    /* Decompress the data */
    if (uncompress(decompressed_data, &decompressed_size, compressed_data, compressed_size) != Z_OK) {
        fprintf(stderr, "Decompression failed\n");
        return false;
    }

    /* Deserialize: Convert byte array back to struct */
    memcpy(stats, decompressed_data, sizeof(sm_stats_t));

    return true;
}

bool qm_send_stats_json(qm_item_t *qi)
{
    bool ret;
    sm_stats_t stats;

    /* Zero initialize stats to prevent garbage values */
    memset(&stats, 0, sizeof(sm_stats_t));

    ret = decompress_deserialize_sm_stats(qi->buf, qi->size, &stats);
        
    /* Process the received stats */
    //printf("Stat Type: %d\n", stats.type);

    switch(stats.type)
    {
        char data[MAX_MQTT_SEND_DATA_SIZE] = {0};
        case SM_T_DEVICE: 
            {
                ret = qm_parse_device_newjson(&stats.u.device, data);
                ret = qm_publish_json(data, stats_topic.device);

            }break;
        case SM_T_VIF: 
            {
                ret = qm_parse_vif_newjson(&stats.u.vif, data);
                ret = qm_publish_json(data, stats_topic.vif);

            }break;
        case SM_T_CLIENT: 
            {
                ret = qm_parse_client_newjson(&stats.u.client, data);
                ret = qm_publish_json(data, stats_topic.client);

            }break;
        case SM_T_NEIGHBOR: 
            {
                ret = qm_parse_neighbor_newjson(&stats.u.neighbor, data);
                ret = qm_publish_json(data, stats_topic.neighbor);

            }break;
    }

    return ret;
}

bool qm_send_event_cloud(qm_item_t *qi)
{
    event_msg_t event;
    bool ret;
    char data[MAX_MQTT_SEND_DATA_SIZE] = {0};
    char topic[100] = {0};

    if (qi->size < sizeof(event_msg_t)) {
        return false;
    }

    memcpy(&event, qi->buf, qi->size);
    
    ret = qm_parse_event_newjson(&event, data);

    if ( event.type == EVENT_TYPE_UPGRADE ) {
        sprintf(topic, "%s", stats_topic.config);
    } else if ( event.type == EVENT_TYPE_CMD ) {
        sprintf(topic, "%s", stats_topic.cmdr);
    }

    ret = qm_publish_json(data, topic);

    return ret;
}


bool qm_send_config_cloud(qm_item_t *qi)
{
    device_conf_t conf; 
    char data[512];

    // Ensure the buffer size matches the expected structure size
    if (qi->size < sizeof(device_conf_t)) {
        return false; // Error: Insufficient data
    }

    // Copy the buffer data into the structure
    memcpy(&conf, qi->buf, qi->size);
    qm_parse_config_newjson(&conf, data);
        
    qm_publish_json(data, stats_topic.config);

    return true;
}

bool qm_mqtt_send_message(qm_item_t *qi, qm_response_t *res)
{
    bool result;
    if (!qm_mqtt_is_connected()) {
        result = false;
    } else {
        result = qm_send_stats_json(qi);
    }
    if (!result) {
        res->response = QM_RESPONSE_ERROR;
        res->error = QM_ERROR_SEND;
    }
    return result;
}

void qm_mqtt_publish_queue()
{
    //mosqev_t *mqtt = &qm_mqtt;
    // publish messages to mqtt
    LOGD("total %d elements queued for transmission.\n", qm_queue_length());

    qm_item_t *qi = NULL;
    qm_item_t *next = NULL;

    // publish the rest of messages
    for (qi = ds_dlist_head(&g_qm_queue.queue); qi != NULL; qi = next)
    {
        next = ds_dlist_next(&g_qm_queue.queue, qi);
        if( qm_send_stats_json(qi)) {
            qm_queue_remove(qi);
        } else {
            LOGE("Publish message failed.\n");
        }
    }
}

void qm_mqtt_reconnect()
{
    mosqev_t *mqtt = &qm_mqtt;
    bool result;

    /*
     * Reconnect handler
     */
    if (qm_mqtt_config_valid())
    {
        if (!mosqev_is_connected(mqtt))
        {
            if (qm_mqtt_reconnect_ts < ticks())
            {
                LOG(DEBUG, "Connecting to %s ...\n", qm_mqtt_broker);
                result = mosqev_connect(&qm_mqtt, qm_mqtt_broker, qm_mqtt_port);
                qm_mqtt_reconnect_ts = ticks() + TICKS_S(STATS_MQTT_RECONNECT);
                if (!result)
                {
                    LOGE("Connecting.\n");
                    return;
                }
                else
                {
                    int ret;
                    //ret = mosquitto_subscribe(mqtt->me_mosq,NULL,"config",1);
                    for (int i = 0; i < qm_topic_lst.n_topic; i++) {
                        ret = mosquitto_subscribe(mqtt->me_mosq, NULL, qm_topic_lst.topic[i], 0);
                        if (ret) {
                            fprintf(stderr, "Error subscribing to topic %s: %d\n", qm_topic_lst.topic[i], ret);
                            break;
                        } else {
                            printf("Subscribed to topic %s\n", qm_topic_lst.topic[i]);
                        }
                    }                    

                }

            }
            else
            {
                LOG(DEBUG, "Not connected, will reconnect in %d secs", (int)TICKS_TO_S(qm_mqtt_reconnect_ts - ticks()));
            }
        }
    }
    else
    {
        /*
         * Config is invalid, but we're connected. Disconnect at once!
         */
        qm_mqtt_reconnect_ts = 0;

        if (mosqev_is_connected(mqtt))
        {
            mosqev_disconnect(mqtt);
            return;
        }
    }
}

void qm_mqtt_send_queue()
{
    // reconnect or disconnect if invalid config
    qm_mqtt_reconnect();
    // Do not report any stats if we're not connected
    if (!qm_mqtt_is_connected())
    {    //Anjan: change
        return;
    }
    qm_mqtt_publish_queue();
}


void qm_mqtt_timer_handler(struct ev_loop *loop, ev_timer *timer, int revents)
{
    (void)loop;
    (void)timer;
    (void)revents;
    qm_mqtt_send_queue();
}

void qm_mqtt_timer_handler_log(struct ev_loop *loop, ev_timer *timer, int revents)
{
    (void)loop;
    (void)timer;
    (void)revents;
    mosqev_t *mqtt = &qm_mqtt;
    bool result;

    if (!g_qm_log_buf_size) return;
    // reconnect or disconnect if invalid config
    qm_mqtt_reconnect();
    // Do not report any stats if we're not connected
    if (!qm_mqtt_is_connected()) return;
    // publish log
    LOGT("MQTT: Publishing log %d bytes", g_qm_log_buf_size);
    result = mosqev_publish(mqtt, NULL, qm_log_topic, g_qm_log_buf_size, g_qm_log_buf, 0, false);
    FREE(g_qm_log_buf);
    g_qm_log_buf = NULL;
    g_qm_log_buf_size = 0;
    if (!result) {
        // drop msg if failed
        g_qm_log_drop_count++;
    } else {
        // reset drop count
        g_qm_log_drop_count = 0;
    }
}

void qm_mqtt_set_log_interval(int log_interval)
{
#ifdef CONFIG_LOG_REMOTE
    if (log_interval == qm_log_interval) return;
    LOGD("QM log publish interval: %d", qm_log_interval);
    if (qm_log_enabled) {
        // disable: stop timer
        ev_timer_stop(EV_DEFAULT, &qm_mqtt_timer_log);
        qm_log_enabled = false;
    }
    if (log_interval > 0) {
        // enable: start timer
        qm_log_interval = log_interval;
        ev_timer_init(&qm_mqtt_timer_log, qm_mqtt_timer_handler_log,
                qm_log_interval, qm_log_interval);
        qm_mqtt_timer.data = &qm_mqtt;
        ev_timer_start(EV_DEFAULT, &qm_mqtt_timer_log);
        qm_log_enabled = true;
    }
#else
    (void) log_interval;
#endif
}

void qm_mqtt_set_agg_stats_interval(int agg_stats_interval)
{
    if (agg_stats_interval < 0) {
        LOGW("Invalid [%d] agg_stats_interval is configured", agg_stats_interval);
        agg_stats_interval = STATS_MQTT_INTERVAL;
    } else if (agg_stats_interval == 0) {
        agg_stats_interval = STATS_MQTT_INTERVAL;
    }

    if (agg_stats_interval == qm_agg_stats_interval)
        return;

    LOGI("QM agg_stats_interval interval: %d", agg_stats_interval);
    qm_agg_stats_interval = agg_stats_interval;
    qm_mqtt_timer.repeat = agg_stats_interval;
    ev_timer_again(EV_DEFAULT, &qm_mqtt_timer);
}


void qm_mqtt_log(mosqev_t *mqtt, void *data, int lvl, const char *str)
{
    (void)mqtt;
    (void)data;
    (void)lvl;
    LOGD("MQTT LOG: %s\n", str);
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
    sscanf(buf, "%d.%d.%d.%d", &ip1, &ip2, &ip3, &ip4);
    sprintf(qm_mqtt_broker, "%d.%d.%d.%d", ip1, ip2, ip3, ip4);

    memset(buf, 0, sizeof(buf));
    cmd_buf("uci get aircnms.@aircnms[0].port", buf, (size_t)UCI_BUF_LEN);
    len = strlen(buf);
    if (len == 0)
    {
        LOGI("%s: No uci port found", __func__);
        return;
    }
    sscanf(buf, "%d", &qm_mqtt_port);

    memset(buf, 0, sizeof(buf));
    cmd_buf("uci get aircnms.@aircnms[0].interval", buf, (size_t)UCI_BUF_LEN);
    len = strlen(buf);
    if (len == 0)
    {
        LOGI("%s: No uci interval found", __func__);
    }
    sscanf(buf, "%d", &qm_agg_stats_interval);

    
    memset(buf, 0, sizeof(buf));
    cmd_buf("uci get aircnms.@aircnms[0].device_id", buf, (size_t)UCI_BUF_LEN);
    len = strlen(buf);
    if (len == 0)
    {
        LOGI("%s: No uci device_id found", __func__);
        return;
    }
    sscanf(buf, "%s", air_dev.device_id);

    memset(buf, 0, sizeof(buf));
    cmd_buf("uci get aircnms.@aircnms[0].serial_num", buf, (size_t)UCI_BUF_LEN);
    len = strlen(buf);
    if (len == 0)
    {
        LOGI("%s: No uci serial_num found", __func__);
        return;
    }
    sscanf(buf, "%s", air_dev.serial_num);

    memset(buf, 0, sizeof(buf));
    cmd_buf("uci get aircnms.@aircnms[0].macaddr", buf, (size_t)UCI_BUF_LEN);
    len = strlen(buf);
    if (len == 0)
    {
        LOGI("%s: No uci macaddr found", __func__);
        return;
    }
    sscanf(buf, "%s", air_dev.macaddr);

    memset(buf, 0, sizeof(buf));
    cmd_buf("uci get aircnms.@aircnms[0].username", buf, (size_t)UCI_BUF_LEN);
    len = strlen(buf);
    if (len == 0)
    {
        LOGI("%s: No uci username found", __func__);
        return;
    }
    sscanf(buf, "%s", air_dev.username);

    memset(buf, 0, sizeof(buf));
    cmd_buf("uci get aircnms.@aircnms[0].password", buf, (size_t)UCI_BUF_LEN);
    len = strlen(buf);
    if (len == 0)
    {
        LOGI("%s: No uci password found", __func__);
        return;
    }
    sscanf(buf, "%s", air_dev.password);

    return;
}

bool qm_mqtt_init(void)
{
    char cID[64];
    mosquitto_lib_init();
    qm_mosquitto_init = true;

    qm_update_topic_lst(&qm_topic_lst);
    qm_get_stats_topic_aircnms(&stats_topic);
    if (true != osp_unit_id_get(cID, sizeof(cID))) {
        LOGE("acquiring device id number\n");
        goto error;
    }
    snprintf(qm_log_topic, sizeof(qm_log_topic), "%s/%s", QM_LOG_TOPIC_PREFIX, cID);
    LOG(DEBUG, "log topic: %s\n", qm_log_topic);
    uci_get_mqtt_params();
    if (!mosqev_init(&qm_mqtt, cID, EV_DEFAULT, NULL))
    {
        LOGE("initializing MQTT library.\n");
        goto error;
    }
    mosqev_message_cbk_set(&qm_mqtt, qm_mqtt_subscriber_set);
    /* Initialize logging */
    //Anjan: TODO: compilation
    //mosqev_log_cbk_set(&qm_mqtt, qm_mqtt_log);

    qm_mosqev_init = true;

    qm_agg_stats_interval = 1;
    // publish timer
    LOGD("QM publish interval: %d", qm_agg_stats_interval);
    ev_timer_init(&qm_mqtt_timer, qm_mqtt_timer_handler,
            qm_agg_stats_interval, qm_agg_stats_interval);
    qm_mqtt_timer.data = &qm_mqtt;
    ev_timer_start(EV_DEFAULT, &qm_mqtt_timer);

    // log publish timer
    qm_mqtt_set_log_interval(qm_log_interval);

    //Anjan: TODO: compialtion
    //mqtt_telog_init(EV_DEFAULT);
    return true;

error:
    qm_mqtt_stop();

    return false;
}
