#include <stdio.h>
#include <jansson.h>
#include "memutil.h"

#include "qm.h"
#include "report.h"
#include "device_config.h"

#include <jansson.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool qm_parse_device_newjson(device_report_data_t *device, char *data)
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
    json_object_set_new(root, "serialNum", json_string(air_dev.serial_num));
    json_object_set_new(root, "deviceId", json_string(air_dev.device_id));
    json_object_set_new(root, "macAddr", json_string(air_dev.macaddr));
    json_object_set_new(root, "tms", json_integer(device->timestamp_ms));

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
    json_object_set_new(memUtil_obj, "memTotal", json_integer(device->record.mem_util.mem_total));
    json_object_set_new(memUtil_obj, "memUsed", json_integer(device->record.mem_util.mem_used));
    json_object_set_new(memUtil_obj, "swapTotal", json_integer(device->record.mem_util.swap_total));
    json_object_set_new(memUtil_obj, "swapUsed", json_integer(device->record.mem_util.swap_used));
    json_object_set_new(device_root, "memUtil", memUtil_obj);

    // Filesystem utilization
    json_t *fsUtil_arr = json_array();
    for (int i = 0; i < DEVICE_FS_TYPE_QTY; i++)
    {
        json_t *fsUtil_obj = json_object();
        const char *fs_type_str = "UNKNOWN";

        switch (device->record.fs_util[i].fs_type)
        {
        case DEVICE_FS_TYPE_ROOTFS:
            fs_type_str = "FS_TYPE_ROOTFS";
            break;
        case DEVICE_FS_TYPE_TMPFS:
            fs_type_str = "FS_TYPE_TMPFS";
            break;
        default:
            break;
        }

        json_object_set_new(fsUtil_obj, "fsType", json_string(fs_type_str));
        json_object_set_new(fsUtil_obj, "fsTotal", json_integer(device->record.fs_util[i].fs_total));
        json_object_set_new(fsUtil_obj, "fsUsed", json_integer(device->record.fs_util[i].fs_used));
        json_array_append_new(fsUtil_arr, fsUtil_obj);
    }
    json_object_set_new(device_root, "fsUtil", fsUtil_arr);

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
        fprintf(stderr, "Failed to serialize JSON\n");
        json_decref(root);
        return false;
    }

    // Copy JSON to the provided buffer
    strcpy(data, json_str);
    LOG(INFO, "DEVICE JSON:\n %s\n", json_str);

    // Cleanup
    free(json_str);
    json_decref(root); // Cleans up all allocated JSON objects

    return true;
}

bool qm_parse_vif_newjson(vif_report_data_t *vif, char *data)
{
    json_t *vif_root = json_object();
    json_t *data_obj = json_object();
    json_t *radio_array = json_array();
    json_t *vif_array = json_array();

    if (!vif_root || !data_obj || !radio_array || !vif_array)
    {
        fprintf(stderr, "Error: Failed to allocate JSON objects\n");
        goto cleanup;
    }

    json_object_set_new(vif_root, "serialNum", json_string(air_dev.serial_num));
    json_object_set_new(vif_root, "deviceId", json_string(air_dev.device_id));
    json_object_set_new(vif_root, "macAddr", json_string(air_dev.macaddr));
    json_object_set_new(vif_root, "tms", json_integer(vif->timestamp_ms));

    /* Parse radio data */
    for (int i = 0; i < vif->record.n_radio; i++)
    {
        json_t *radio = json_object();
        if (!radio)
        {
            fprintf(stderr, "Error: Failed to allocate JSON radio object\n");
            goto cleanup;
        }

        json_object_set_new(radio, "band", json_string(vif->record.radio[i].band));
        json_object_set_new(radio, "channel", json_integer(vif->record.radio[i].channel));
        json_object_set_new(radio, "txpower", json_integer(vif->record.radio[i].txpower));
        json_object_set_new(radio, "channel_utilization", json_integer(vif->record.radio[i].channel_utilization));

        json_array_append_new(radio_array, radio); // Takes ownership of `radio`
    }

    /* Parse VIF data */
    for (int i = 0; i < vif->record.n_vif; i++)
    {
        json_t *vif_obj = json_object();
        if (!vif_obj)
        {
            fprintf(stderr, "Error: Failed to allocate JSON vif object\n");
            goto cleanup;
        }

        json_object_set_new(vif_obj, "radio", json_string(vif->record.vif[i].radio));  // Fixed
        json_object_set_new(vif_obj, "ssid", json_string(vif->record.vif[i].ssid));
        json_object_set_new(vif_obj, "statNumSta", json_integer(vif->record.vif[i].num_sta));
        json_object_set_new(vif_obj, "statUplinkMb", json_integer(vif->record.vif[i].uplink_mb));
        json_object_set_new(vif_obj, "statDownlinkMb", json_integer(vif->record.vif[i].downlink_mb));

        json_array_append_new(vif_array, vif_obj); // Takes ownership of `vif_obj`
    }

    /* Store radio and vif data inside `data` */
    json_object_set_new(data_obj, "radio", radio_array);
    json_object_set_new(data_obj, "vif", vif_array);

    /* Attach `data` to `vif_root` */
    json_object_set_new(vif_root, "data", data_obj);

    /* Convert JSON object to string */
    char *json_str = json_dumps(vif_root, 0);
    if (!json_str)
    {
        fprintf(stderr, "Error: Failed to serialize message to JSON\n");
        goto cleanup;
    }

    /* Copy JSON string safely */
    strncpy(data, json_str, strlen(json_str) + 1);  // Ensure `data` is large enough!
    LOG(INFO, "VIF JSON:\n %s\n", json_str);

    /* Cleanup */
    free(json_str);
    json_decref(vif_root);

    return true;

cleanup:
    if (vif_root) json_decref(vif_root);
    if (data_obj) json_decref(data_obj);
    if (radio_array) json_decref(radio_array);
    if (vif_array) json_decref(vif_array);
    return false;
}

void mac_addr_to_str(const uint8_t mac[6], char *str, size_t size) {
    if (size < 18) {  // Ensure buffer size is at least 18 (17 chars + null terminator)
        fprintf(stderr, "Error: Buffer size too small for MAC address\n");
        return;
    }
    snprintf(str, size, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

bool qm_parse_client_newjson(client_report_data_t *client, char *data)
{
    json_t *root = json_object();
    //json_t *client_root = json_object();
    json_t *client_arr = json_array();
    int n_client = client->n_client;
    char mac_str[18];


    json_object_set_new(root, "serialNum", json_string(air_dev.serial_num));
    json_object_set_new(root, "deviceId", json_string(air_dev.device_id));
    json_object_set_new(root, "macAddr", json_string(air_dev.macaddr));
        
    json_object_set_new(root, "tms", json_integer(client->timestamp_ms));
    for (int i = 0; i < n_client; i++){
    
        char band[8];
        if(client->record[i].radio_type == RADIO_TYPE_2G) {
            strcpy(band, "BAND2G");
        } else if(client->record[i].radio_type == RADIO_TYPE_5G) {
            strcpy(band, "BAND5G");
        } 

        int channel = client->record[i].channel;
        
        json_t *client_node = json_object();
        
        mac_addr_to_str(client->record[i].macaddr, mac_str, sizeof(mac_str));
        json_object_set_new(client_node, "macAddress", json_string(mac_str));
        json_object_set_new(client_node, "hostname", json_string(client->record[i].hostname));
        json_object_set_new(client_node, "ipAddress", json_string(client->record[i].ipaddr));
        json_object_set_new(client_node, "ssid", json_string(client->record[i].ssid));
        
        json_object_set_new(client_node, "isConnected", json_integer(client->record[i].is_connected));
        json_object_set_new(client_node, "durationMs", json_integer(client->record[i].duration_ms));
        json_object_set_new(client_node, "channel", json_integer(channel));
        json_object_set_new(client_node, "band", json_string(band));

        /* stats */
        json_t *stats_obj = json_object();
        
        json_object_set_new(stats_obj, "rxBytes", json_integer(client->record[i].rx_bytes));
        json_object_set_new(stats_obj, "txBytes", json_integer(client->record[i].tx_bytes));
        json_object_set_new(stats_obj, "rssi", json_integer(client->record[i].rssi));
        json_object_set_new(client_node, "stats", stats_obj);
        
        json_array_append_new(client_arr, client_node);
        
    }
    json_object_set_new(root, "data", client_arr);

    // Convert JSON object to JSON string
    char *json_str = NULL;
    json_str = json_dumps(root, 0);
    if (!json_str) {
        fprintf(stderr, "Error converting JSON object to string\n");
        json_decref(root);
        return 1;
    }
    strcpy(data, json_str);
    
    // Print serialized JSON string
    LOG(INFO, "CLIENT JSON:\n %s\n", json_str);

    // Cleanup
    free(json_str);
    json_decref(root);
    
    return true;

}

int qm_parse_config_newjson(device_conf_t *conf, char *data)
{
    json_t *root = json_object();
    json_t *conf_root = json_object();
    
    json_object_set_new(root, "type", json_string("device_static_data"));
    
    json_object_set_new(conf_root, "serial_number", json_string(air_dev.serial_num));
    json_object_set_new(conf_root, "fw_info", json_string(conf->fw_info));
    json_object_set_new(conf_root, "hw_version", json_string(conf->hw_version));
    json_object_set_new(conf_root, "mgmt_ip", json_string(conf->mgmt_ip));
    json_object_set_new(conf_root, "egress_ip", json_string(conf->egress_ip));

    json_object_set_new(root, "data", conf_root);


    char *json_str = NULL;
    json_str = json_dumps(root, 0);
    if (!json_str) {
        fprintf(stderr, "Error converting JSON object to string\n");
        json_decref(root);
        return 1;
    }
    strcpy(data, json_str);
    
    // Print serialized JSON string
    LOG(INFO, "DEVICE_CONF JSON:\n %s\n", json_str);

    // Cleanup
    free(json_str);
    json_decref(root);
    
    return true;
}

bool qm_parse_alarm_newjson(alarm_msg_t *alarm, char *data)
{
    json_t *root = json_object();
    json_t *alarm_root = json_object();
    
    json_object_set_new(alarm_root, "type", json_string(alarm->type));
    json_object_set_new(alarm_root, "reason", json_string(alarm->reason));
    
    json_object_set_new(root, "data", alarm_root);


    char *json_str = NULL;
    json_str = json_dumps(root, 0);
    if (!json_str) {
        fprintf(stderr, "Error converting JSON object to string\n");
        json_decref(root);
        return 1;
    }
    strcpy(data, json_str);
    
    // Print serialized JSON string
    LOG(INFO, "ALARM JSON:\n %s\n", json_str);

    // Cleanup
    free(json_str);
    json_decref(root);
    
    return true;
}

bool qm_parse_event_newjson(event_msg_t *event, char *data)
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


    char *json_str = NULL;
    json_str = json_dumps(root, 0);
    if (!json_str) {
        fprintf(stderr, "Error converting JSON object to string\n");
        json_decref(root);
        return 1;
    }
    strcpy(data, json_str);
    
    // Print serialized JSON string
    LOG(INFO, "EVENT JSON:\n %s\n", json_str);

    // Cleanup
    free(json_str);
    json_decref(root);
    
    return true;

}

bool qm_parse_neighbor_newjson(neighbor_report_data_t *rpt, char *data) 
{
    if (!rpt || !data) {
        return false;
    }

    json_t *root = json_object();
    if (!root) {
        fprintf(stderr, "Failed to create JSON root object\n");
        return false;
    }

    json_t *neighbor_array = json_array();
    if (!neighbor_array) {
        fprintf(stderr, "Failed to create JSON array\n");
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
            fprintf(stderr, "Failed to create JSON object for neighbor\n");
            continue;
        }

        char band[8];  // Declare band string buffer
        if (rpt->record[itr].radio_type == RADIO_TYPE_2G) {
            strcpy(band, "2.4GHz");
        } else if (rpt->record[itr].radio_type == RADIO_TYPE_5G) {
            strcpy(band, "5GHz");
        } else {
            strcpy(band, "Unknown");
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
        fprintf(stderr, "Failed to serialize message to JSON\n");
        json_decref(root);
        return false;
    }

    // Copy the JSON string into `data` without checking size
    strcpy(data, json_str);

    // Print serialized JSON
    LOG(INFO, "NEIGHBOUR JSON:\n%s\n", json_str);

    // Cleanup
    free(json_str);
    json_decref(root);

    return true;
}
