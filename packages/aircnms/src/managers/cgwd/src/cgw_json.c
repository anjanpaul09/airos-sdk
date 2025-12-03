#include <stdio.h>
#include <jansson.h>
#include "memutil.h"

#include "cgw.h"
#include "stats_report.h"
#include "device_config.h"
#include "info_events.h"
#include "log.h"

// Forward declarations for info event JSON parsing
bool cgw_parse_client_info_json(client_info_event_t *client_info, char *data, uint64_t timestamp_ms);
bool cgw_parse_vif_info_json(vif_info_event_t *vif_info, char *data, uint64_t timestamp_ms);
bool cgw_parse_device_info_json(device_info_event_t *device_info, char *data, uint64_t timestamp_ms);

#include <jansson.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Get epoch time in milliseconds
static long long current_time_ms()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

// Callback used by jansson to write JSON into buffer
static int json_buf_writer(const char *buffer, size_t size, void *data)
{
    char *out = (char *)data;
    strncat(out, buffer, size);  // append safely
    return 0;
}

// Build JSON → fill buffer
int build_status_payload_to_buf(const char *status,
                                char *outbuf,
                                size_t outlen)
{
    outbuf[0] = '\0';   // clear buffer

    json_t *root = json_object();
    json_t *data_obj = json_object();

    if (!root || !data_obj)
        return -1;

    json_object_set_new(root, "networkId", json_string(air_dev.netwrk_id));
    json_object_set_new(root, "deviceId", json_string(air_dev.device_id));
    json_object_set_new(root, "OrgId", json_string(air_dev.org_id));
    json_object_set_new(root, "tms", json_integer(current_time_ms()));

    json_object_set_new(data_obj, "status", json_string(status));
    json_object_set_new(data_obj, "serialNum", json_string(air_dev.serial_num));
    json_object_set_new(root, "data", data_obj);

    json_dump_callback(root, json_buf_writer, outbuf, JSON_COMPACT);

    json_decref(root);

    // Ensure null termination
    outbuf[outlen - 1] = '\0';

    return 0;
}

bool cgw_parse_device_newjson(device_report_data_t *device, char *data)
{
    if (!device || !data)
        return false;

    json_t *root = json_object();
    if (!root)
        return false;

    json_t *device_root = json_object();
    if (!device_root)
    {
        json_decref(root);
        return false;
    }

    // Adding main metadata
    json_object_set_new(root, "networkId", json_string(air_dev.netwrk_id));
    json_object_set_new(root, "deviceId", json_string(air_dev.device_id));
    json_object_set_new(root, "OrgId", json_string(air_dev.org_id));
    json_object_set_new(root, "tms", json_integer(device->timestamp_ms));
    json_object_set_new(root, "type", json_string("ap_stats"));

    // System info
    json_t *system_obj = json_object();
    json_object_set_new(system_obj, "uptime", json_integer(device->record.uptime));
    json_object_set_new(system_obj, "downtime", json_integer(0));
    json_object_set_new(system_obj, "totalClient", json_integer(device->record.w_util.num_sta));
    json_object_set_new(system_obj, "uplinkMb", json_integer(device->record.w_util.uplink_mb));
    json_object_set_new(system_obj, "downlinkMb", json_integer(device->record.w_util.downlink_mb));
    json_object_set_new(system_obj, "totalTrafficMb", json_integer(device->record.w_util.total_traffic_mb));
    json_object_set_new(device_root, "system", system_obj);

    // Memory utilization
    json_t *memUtil_obj = json_object();
    //json_object_set_new(memUtil_obj, "memTotal", json_integer(device->record.mem_util.mem_total));
    //json_object_set_new(memUtil_obj, "memUsed", json_integer(device->record.mem_util.mem_used));
    //json_object_set_new(memUtil_obj, "swapTotal", json_integer(device->record.mem_util.swap_total));
    //json_object_set_new(memUtil_obj, "swapUsed", json_integer(device->record.mem_util.swap_used));
    json_object_set_new(memUtil_obj, "ramUsed", json_integer(device->record.mem_util.mem_util_percent)); 

    // Filesystem utilization
    //json_t *fsUtil_arr = json_array();
    for (int i = 0; i < DEVICE_FS_TYPE_QTY; i++)
    {
        //json_t *fsUtil_obj = json_object();
        //const char *fs_type_str = "UNKNOWN";

        switch (device->record.fs_util[i].fs_type)
        {
        case DEVICE_FS_TYPE_ROOTFS:
            //fs_type_str = "FS_TYPE_ROOTFS";
            json_object_set_new(memUtil_obj, "diskUsed", json_integer(device->record.fs_util[i].fs_util_percent));
            break;
        case DEVICE_FS_TYPE_TMPFS:
            //fs_type_str = "FS_TYPE_TMPFS";
            break;
        default:
            break;
        }

        //json_object_set_new(fsUtil_obj, "fsType", json_string(fs_type_str));
        //json_object_set_new(fsUtil_obj, "fsTotal", json_integer(device->record.fs_util[i].fs_total));
        //json_object_set_new(fsUtil_obj, "fsUsed", json_integer(device->record.fs_util[i].fs_used));
        //json_object_set_new(fsUtil_obj, "fsUsedPercent", json_integer(device->record.fs_util[i].fs_util_percent));
        //json_array_append_new(fsUtil_arr, fsUtil_obj);
    }
    //json_object_set_new(device_root, "fsUtil", fsUtil_arr);
    json_object_set_new(device_root, "memUtil", memUtil_obj);

    // CPU utilization
    json_t *cpuutil_obj = json_object();
    json_object_set_new(cpuutil_obj, "cpuUtil", json_integer(device->record.cpu_util.cpu_util));
    json_object_set_new(device_root, "cpuUtil", cpuutil_obj);

    // Final structure
    json_object_set_new(root, "data", device_root);

    // Serialize JSON
    char *json_str = json_dumps(root, JSON_COMPACT);
    if (!json_str)
    {
        LOG(ERR, "Failed to serialize JSON");
        json_decref(root);
        return false;
    }

    // Copy JSON to the provided buffer safely
    // Note: data buffer should be at least MAX_MQTT_SEND_DATA_SIZE (90000 bytes)
    size_t json_len = strlen(json_str);
    size_t max_size = 90000;  // Based on MAX_MQTT_SEND_DATA_SIZE
    size_t copy_len = json_len < max_size - 1 ? json_len : max_size - 1;
    memcpy(data, json_str, copy_len);
    data[copy_len] = '\0';
    
    if (copy_len < json_len) {
        LOG(ERR, "JSON data truncated: %zu bytes copied of %zu", copy_len, json_len);
    }

    // Cleanup
    free(json_str);
    json_decref(root); // Cleans up all allocated JSON objects

    return true;
}

bool cgw_parse_vif_newjson(vif_report_data_t *vif, char *data)
{
    json_t *vif_root = json_object();
    json_t *data_obj = json_object();
    json_t *stats_obj = json_object();

    if (!vif || !data) {
        LOG(ERR, "Invalid parameters for cgw_parse_vif_newjson");
        return false;
    }

    if (!vif_root || !data_obj || !stats_obj)
    {
        LOG(ERR, "Failed to allocate JSON objects");
        goto cleanup;
    }

    // Add root level fields
    json_object_set_new(vif_root, "networkId", json_string(air_dev.netwrk_id));
    json_object_set_new(vif_root, "deviceId", json_string(air_dev.device_id));
    json_object_set_new(vif_root, "OrgId", json_string(air_dev.org_id));
    json_object_set_new(vif_root, "tms", json_integer(vif->timestamp_ms));

    // Info moved to netevd - only stats here
    // Fill stats object
    // Radio stats array
    json_t *radio_stats_array = json_array();
    for (int i = 0; i < vif->record.stats.n_radio; i++) {
        json_t *radio_stats = json_object();
        json_object_set_new(radio_stats, "band", json_string(vif->record.stats.radio[i].band));
        json_object_set_new(radio_stats, "channel_utilization", json_integer(vif->record.stats.radio[i].channel_utilization));
        json_array_append_new(radio_stats_array, radio_stats);
    }
    json_object_set_new(stats_obj, "radio", radio_stats_array);
    
    // VIF stats array
    json_t *vif_stats_array = json_array();
    for (int i = 0; i < vif->record.stats.n_vif; i++) {
        json_t *vif_stats = json_object();
        json_object_set_new(vif_stats, "radio", json_string(vif->record.stats.vif[i].radio));
        json_object_set_new(vif_stats, "ssid", json_string(vif->record.stats.vif[i].ssid));
        json_object_set_new(vif_stats, "statNumSta", json_integer(vif->record.stats.vif[i].statNumSta));
        json_object_set_new(vif_stats, "statUplinkMb", json_integer(vif->record.stats.vif[i].statUplinkMb));
        json_object_set_new(vif_stats, "statDownlinkMb", json_integer(vif->record.stats.vif[i].statDownlinkMb));
        json_array_append_new(vif_stats_array, vif_stats);
    }
    json_object_set_new(stats_obj, "vif", vif_stats_array);
    
    // Ethernet stats array
    json_t *ethernet_stats_array = json_array();
    for (int i = 0; i < vif->record.stats.n_ethernet; i++) {
        json_t *eth_stats = json_object();
        json_object_set_new(eth_stats, "interface", json_string(vif->record.stats.ethernet[i].interface));
        json_object_set_new(eth_stats, "rxBytes", json_integer(vif->record.stats.ethernet[i].rxBytes));
        json_object_set_new(eth_stats, "txBytes", json_integer(vif->record.stats.ethernet[i].txBytes));
        json_object_set_new(eth_stats, "rxPackets", json_integer(vif->record.stats.ethernet[i].rxPackets));
        json_object_set_new(eth_stats, "txPackets", json_integer(vif->record.stats.ethernet[i].txPackets));
        json_object_set_new(eth_stats, "rxErrors", json_integer(vif->record.stats.ethernet[i].rxErrors));
        json_object_set_new(eth_stats, "txErrors", json_integer(vif->record.stats.ethernet[i].txErrors));
        json_object_set_new(eth_stats, "rxDropped", json_integer(vif->record.stats.ethernet[i].rxDropped));
        json_object_set_new(eth_stats, "txDropped", json_integer(vif->record.stats.ethernet[i].txDropped));
        json_object_set_new(eth_stats, "speed", json_integer(vif->record.stats.ethernet[i].speed));
        json_object_set_new(eth_stats, "duplex", json_string(vif->record.stats.ethernet[i].duplex));
        json_object_set_new(eth_stats, "link", json_integer(vif->record.stats.ethernet[i].link));
        json_array_append_new(ethernet_stats_array, eth_stats);
    }
    json_object_set_new(stats_obj, "ethernet", ethernet_stats_array);

    /* Store stats only inside `data` (info moved to netevd) */
    json_object_set_new(data_obj, "stats", stats_obj);

    /* Attach `data` to `vif_root` */
    json_object_set_new(vif_root, "data", data_obj);

    /* Convert JSON object to string */
    char *json_str = json_dumps(vif_root, 0);
    if (!json_str)
    {
        LOG(ERR, "Failed to serialize message to JSON");
        goto cleanup;
    }

    /* Copy JSON string safely */
    size_t json_len = strlen(json_str);
    size_t max_size = 90000;  // Based on MAX_MQTT_SEND_DATA_SIZE
    size_t copy_len = json_len < max_size - 1 ? json_len : max_size - 1;
    memcpy(data, json_str, copy_len);
    data[copy_len] = '\0';
    
    if (copy_len < json_len) {
        LOG(ERR, "JSON data truncated: %zu bytes copied of %zu", copy_len, json_len);
    }

    /* Cleanup */
    free(json_str);
    json_decref(vif_root);

    return true;

cleanup:
    if (vif_root) json_decref(vif_root);
    if (data_obj) json_decref(data_obj);
    if (stats_obj) json_decref(stats_obj);
    return false;
}

void mac_addr_to_str(const uint8_t mac[6], char *str, size_t size) {
    if (!mac || !str) {
        return;
    }
    if (size < 18) {  // Ensure buffer size is at least 18 (17 chars + null terminator)
        LOG(ERR, "Buffer size too small for MAC address: %zu", size);
        return;
    }
    snprintf(str, size, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

bool cgw_parse_client_newjson(client_report_data_t *client, char *data)
{
    if (!client || !data) {
        LOG(ERR, "cgw_parse_client_newjson: NULL parameter");
        return false;
    }

    // Validate the client record pointer
    if (client->n_client > 0 && !client->record) {
        LOG(ERR, "client->record is NULL but n_client=%d", client->n_client);
        return false;
    }

    json_t *root = json_object();
    if (!root) {
        LOG(ERR, "Failed to create JSON root object");
        return false;
    }

    json_t *client_arr = json_array();
    if (!client_arr) {
        LOG(ERR, "Failed to create JSON array");
        json_decref(root);
        return false;
    }

    int n_client = client->n_client;
    char mac_str[18];

    // Add device information - new format
    json_object_set_new(root, "networkId", json_string(air_dev.netwrk_id));
    json_object_set_new(root, "deviceId", json_string(air_dev.device_id));
    json_object_set_new(root, "OrgId", json_string(air_dev.org_id));
    json_object_set_new(root, "tms", json_integer(client->timestamp_ms));
    json_object_set_new(root, "type", json_string("client_stats"));

    LOG(DEBUG, "Processing %d clients for JSON", n_client);

    // Process each client using pointer to record - STATS ONLY
    for (int i = 0; i < n_client; i++) {
        client_record_t *rec = &client->record[i];

        //json_t *client_node = json_object();

        // Convert MAC address to string
        mac_addr_to_str(rec->macaddr, mac_str, sizeof(mac_str));

        // Add stats object only (info moved to netevd)
        json_t *stats_obj = json_object();
        json_object_set_new(stats_obj, "macAddress", json_string(mac_str));
        json_object_set_new(stats_obj, "durationMs", json_integer(rec->stats.duration_ms));
        json_object_set_new(stats_obj, "rssi", json_integer(rec->stats.rssi));
        json_object_set_new(stats_obj, "snr", json_integer(rec->stats.snr));
        json_object_set_new(stats_obj, "txRateMbps", json_integer(rec->stats.tx_rate_mbps));
        json_object_set_new(stats_obj, "rxRateMbps", json_integer(rec->stats.rx_rate_mbps));
        json_object_set_new(stats_obj, "txBytes", json_integer(rec->stats.tx_bytes));
        json_object_set_new(stats_obj, "rxBytes", json_integer(rec->stats.rx_bytes));
        json_object_set_new(stats_obj, "txPackets", json_integer(rec->stats.tx_packets));
        json_object_set_new(stats_obj, "rxPackets", json_integer(rec->stats.rx_packets));
        json_object_set_new(stats_obj, "txRetries", json_integer(rec->stats.tx_retries));
        json_object_set_new(stats_obj, "txFailures", json_integer(rec->stats.tx_failures));
        json_object_set_new(stats_obj, "txPhyRate", json_integer(rec->stats.tx_phy_rate));
        json_object_set_new(stats_obj, "rxPhyRate", json_integer(rec->stats.rx_phy_rate));
        json_object_set_new(stats_obj, "signalAvg", json_integer(rec->stats.signal_avg));
        //json_object_set_new(client_node, "stats", stats_obj);

        // Append client to array
        json_array_append_new(client_arr, stats_obj);
        //json_array_append_new(client_arr, client_node);

    }

    json_object_set_new(root, "data", client_arr);

    // Convert JSON object to string
    char *json_str = json_dumps(root, 0);
    if (!json_str) {
        LOG(ERR, "Error converting JSON object to string");
        json_decref(root);
        return false;
    }

    // Copy to output buffer safely
    size_t json_len = strlen(json_str);
    size_t max_size = 90000;  // Based on MAX_MQTT_SEND_DATA_SIZE
    size_t copy_len = json_len < max_size - 1 ? json_len : max_size - 1;
    memcpy(data, json_str, copy_len);
    data[copy_len] = '\0';
    
    if (copy_len < json_len) {
        LOG(ERR, "JSON data truncated: %zu bytes copied of %zu", copy_len, json_len);
    }

    // Cleanup
    free(json_str);
    json_decref(root);

    return true;
}

int cgw_parse_config_newjson(device_conf_t *conf, char *data)
{
    if (!conf || !data) {
        LOG(ERR, "Invalid parameters for cgw_parse_config_newjson");
        return 1;
    }

    json_t *root = json_object();
    if (!root) {
        LOG(ERR, "Failed to create JSON root object");
        return 1;
    }

    json_t *conf_root = json_object();
    if (!conf_root) {
        LOG(ERR, "Failed to create JSON conf_root object");
        json_decref(root);
        return 1;
    }
    
    json_object_set_new(root, "type", json_string("device_static_data"));
    
    json_object_set_new(conf_root, "serial_number", json_string(air_dev.serial_num));
    json_object_set_new(conf_root, "fw_info", json_string(conf->fw_info));
    json_object_set_new(conf_root, "hw_version", json_string(conf->hw_version));
    json_object_set_new(conf_root, "mgmt_ip", json_string(conf->mgmt_ip));
    json_object_set_new(conf_root, "egress_ip", json_string(conf->egress_ip));

    json_object_set_new(root, "data", conf_root);

    char *json_str = json_dumps(root, 0);
    if (!json_str) {
        LOG(ERR, "Error converting JSON object to string");
        json_decref(root);
        return 1;
    }
    
    // Copy to output buffer safely (data is char[512] in cgw_mqtt.c)
    size_t json_len = strlen(json_str);
    size_t max_size = 512;  // Based on function signature in cgw_mqtt.c
    size_t copy_len = json_len < max_size - 1 ? json_len : max_size - 1;
    memcpy(data, json_str, copy_len);
    data[copy_len] = '\0';
    
    if (copy_len < json_len) {
        LOG(ERR, "JSON data truncated: %zu bytes copied of %zu", copy_len, json_len);
    }

    // Cleanup
    free(json_str);
    json_decref(root);
    
    return 0;
}

bool cgw_parse_alarm_newjson(alarm_msg_t *alarm, char *data)
{
    json_t *root = json_object();
    json_t *alarm_root = json_object();
    
    json_object_set_new(alarm_root, "type", json_string(alarm->type));
    json_object_set_new(alarm_root, "reason", json_string(alarm->reason));
    
    json_object_set_new(root, "data", alarm_root);


    char *json_str = json_dumps(root, 0);
    if (!json_str) {
        LOG(ERR, "Error converting JSON object to string");
        json_decref(root);
        return false;
    }
    
    // Copy to output buffer safely
    size_t json_len = strlen(json_str);
    size_t max_size = 90000;  // Based on MAX_MQTT_SEND_DATA_SIZE
    size_t copy_len = json_len < max_size - 1 ? json_len : max_size - 1;
    memcpy(data, json_str, copy_len);
    data[copy_len] = '\0';
    
    if (copy_len < json_len) {
        LOG(ERR, "JSON data truncated: %zu bytes copied of %zu", copy_len, json_len);
    }
    
    // Print serialized JSON string
    LOG(INFO, "ALARM JSON: %s", json_str);

    // Cleanup
    free(json_str);
    json_decref(root);
    
    return true;
}

bool cgw_parse_event_newjson(event_msg_t *event, char *data)
{
    json_t *root = json_object();
    json_t *event_root = json_object();
    
    if ( event->type == EVENT_TYPE_UPGRADE ) {
        json_object_set_new(root, "type", json_string("device_upgrading_data"));
    } else if ( event->type == EVENT_TYPE_ALARM ) {
        json_object_set_new(root, "type", json_string("device_alarm"));
    } else if ( event->type == EVENT_TYPE_CMD ) {
        json_object_set_new(root, "type", json_string("device_cmd_data"));
    }
    
    if ( event->type == EVENT_TYPE_UPGRADE ) {
        if ( event->status == EVENT_STATUS_DOWNLOADED ) {
            json_object_set_new(event_root, "status", json_string("Downloaded"));
        } else if ( event->status == EVENT_STATUS_UPGRADING ) {
            json_object_set_new(event_root, "status", json_string("Upgrading"));
        }  else if ( event->status == EVENT_STATUS_FAILED ) {
            json_object_set_new(event_root, "status", json_string("Failed"));
        }  else if ( event->status == EVENT_STATUS_UPGRADED ) {
            json_object_set_new(event_root, "status", json_string("Success"));
        }
        json_object_set_new(event_root, "device_firmware_id", json_string(event->cloud_id));
    } else if ( event->type == EVENT_TYPE_CMD ) {
        json_object_set_new(event_root, "cmd_reply", json_string(event->data));
        json_object_set_new(event_root, "device_command_id", json_string(event->cloud_id));
    } 
    json_object_set_new(root, "data", event_root);


    char *json_str = json_dumps(root, 0);
    if (!json_str) {
        LOG(ERR, "Error converting JSON object to string");
        json_decref(root);
        return false;
    }
    
    // Copy to output buffer safely
    size_t json_len = strlen(json_str);
    size_t max_size = 90000;  // Based on MAX_MQTT_SEND_DATA_SIZE
    size_t copy_len = json_len < max_size - 1 ? json_len : max_size - 1;
    memcpy(data, json_str, copy_len);
    data[copy_len] = '\0';
    
    if (copy_len < json_len) {
        LOG(ERR, "JSON data truncated: %zu bytes copied of %zu", copy_len, json_len);
    }
    
    // Print serialized JSON string
    LOG(INFO, "EVENT JSON: %s", json_str);

    // Cleanup
    free(json_str);
    json_decref(root);
    
    return true;

}

bool cgw_parse_neighbor_newjson(neighbor_report_data_t *rpt, char *data) 
{
    if (!rpt || !data) {
        return false;
    }

    json_t *root = json_object();
    if (!root) {
        LOG(ERR, "Failed to create JSON root object");
        return false;
    }

    json_t *neighbor_array = json_array();
    if (!neighbor_array) {
        LOG(ERR, "Failed to create JSON array");
        json_decref(root);
        return false;
    }

    json_object_set_new(root, "serialNum", json_string(air_dev.serial_num));
    json_object_set_new(root, "deviceId", json_string(air_dev.device_id));
    json_object_set_new(root, "macAddr", json_string(air_dev.macaddr));
    json_object_set_new(root, "tms", json_integer(rpt->timestamp_ms));

    for (int itr = 0; itr < rpt->n_entry; itr++) {
        json_t *neighbor = json_object();
        if (!neighbor) {
            LOG(ERR, "Failed to create JSON object for neighbor");
            continue;
        }

        char band[8];  // Declare band string buffer
        if (rpt->record[itr].radio_type == RADIO_TYPE_2G) {
            strncpy(band, "2.4GHz", sizeof(band) - 1);
            band[sizeof(band) - 1] = '\0';
        } else if (rpt->record[itr].radio_type == RADIO_TYPE_5G) {
            strncpy(band, "5GHz", sizeof(band) - 1);
            band[sizeof(band) - 1] = '\0';
        } else {
            strncpy(band, "Unknown", sizeof(band) - 1);
            band[sizeof(band) - 1] = '\0';
        }

        json_object_set_new(neighbor, "bssid", json_string(rpt->record[itr].bssid));
        json_object_set_new(neighbor, "ssid", json_string(rpt->record[itr].ssid));
        json_object_set_new(neighbor, "rssi", json_integer(rpt->record[itr].rssi));
        json_object_set_new(neighbor, "tsf", json_integer(rpt->record[itr].tsf));
        json_object_set_new(neighbor, "channel", json_integer(rpt->record[itr].channel));
        json_object_set_new(neighbor, "channelWidth", json_integer(rpt->record[itr].chan_width));
        json_object_set_new(neighbor, "band", json_string(band));

        json_array_append_new(neighbor_array, neighbor);
    }

    json_object_set_new(root, "data", neighbor_array);

    char *json_str = json_dumps(root, 0);
    if (!json_str) {
        LOG(ERR, "Failed to serialize message to JSON");
        json_decref(root);
        return false;
    }

    // Copy the JSON string safely
    size_t json_len = strlen(json_str);
    size_t max_size = 90000;  // Based on MAX_MQTT_SEND_DATA_SIZE
    size_t copy_len = json_len < max_size - 1 ? json_len : max_size - 1;
    memcpy(data, json_str, copy_len);
    data[copy_len] = '\0';
    
    if (copy_len < json_len) {
        LOG(ERR, "JSON data truncated: %zu bytes copied of %zu", copy_len, json_len);
    }

    // Cleanup
    free(json_str);
    json_decref(root);

    return true;
}
