#include <stdio.h>
#include <jansson.h>
#include "memutil.h"

#include "cgw.h"
#include "stats_report.h"
#include "device_config.h"
#include "info_events.h"
#include "log.h"

#include <jansson.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern air_device_t air_dev;

// mac_addr_to_str is defined in cgw_json.c
extern void mac_addr_to_str(const uint8_t mac[6], char *str, size_t size);

/* Parse client info event to JSON */
bool cgw_parse_client_info_json(client_info_event_t *client_info, char *data, uint64_t timestamp_ms)
{
    if (!client_info || !data) {
        LOG(ERR, "cgw_parse_client_info_json: NULL parameter");
        return false;
    }

    json_t *root = json_object();
    if (!root) {
        LOG(ERR, "Failed to create JSON root object");
        return false;
    }

    char mac_str[18];
    mac_addr_to_str(client_info->macaddr, mac_str, sizeof(mac_str));

    // Add root level fields
    json_object_set_new(root, "networkId", json_string(air_dev.netwrk_id)); // TODO: Get from air_dev
    json_object_set_new(root, "deviceId", json_string(air_dev.device_id));
    json_object_set_new(root, "orgId", json_string(air_dev.org_id));
    json_object_set_new(root, "tms", json_integer(timestamp_ms));
    json_object_set_new(root, "type", json_string("client_event"));

    // Add data object
    json_t *data_obj = json_object();
    json_object_set_new(data_obj, "macAddress", json_string(mac_str));
    
    if (client_info->is_connected) {
        json_object_set_new(data_obj, "hostname", json_string(client_info->hostname));
        json_object_set_new(data_obj, "ipAddress", json_string(client_info->ipaddr));
        json_object_set_new(data_obj, "ssid", json_string(client_info->ssid));
        json_object_set_new(data_obj, "band", json_string(client_info->band));
        json_object_set_new(data_obj, "channel", json_integer(client_info->channel));
        json_object_set_new(data_obj, "clientType", json_string(client_info->client_type));
        json_object_set_new(data_obj, "osInfo", json_string(client_info->osinfo));
        json_object_set_new(data_obj, "startTime", json_integer(client_info->start_time));
        json_object_set_new(data_obj, "isConnected", json_integer(client_info->is_connected));
    
        // Add capability object
        json_t *capability_obj = json_object();
        json_object_set_new(capability_obj, "phy", json_string(client_info->capability.phy));
        json_object_set_new(capability_obj, "roaming", json_string(client_info->capability.roaming));
        json_object_set_new(capability_obj, "mcs", json_string(client_info->capability.mcs));
        json_object_set_new(capability_obj, "nss", json_string(client_info->capability.nss));
        json_object_set_new(capability_obj, "ps", json_string(client_info->capability.ps));
        json_object_set_new(capability_obj, "wmm", json_string(client_info->capability.wmm));
        json_object_set_new(capability_obj, "mu-mimo", json_string(client_info->capability.mu_mimo));
        json_object_set_new(capability_obj, "ofdma", json_string(client_info->capability.ofdma));
        json_object_set_new(capability_obj, "bw", json_string(client_info->capability.bw));
        json_object_set_new(data_obj, "capability", capability_obj);
    } else {
        json_object_set_new(data_obj, "endTime", json_integer(client_info->end_time));
        json_object_set_new(data_obj, "isConnected", json_integer(client_info->is_connected));
    }
    json_object_set_new(root, "data", data_obj);

    // Convert JSON object to string
    char *json_str = json_dumps(root, 0);
    if (!json_str) {
        LOG(ERR, "Error converting JSON object to string");
        json_decref(root);
        return false;
    }

    // Copy to output buffer safely
    size_t json_len = strlen(json_str);
    size_t max_size = 90000;
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

/* Parse VIF info event to JSON */
bool cgw_parse_vif_info_json(vif_info_event_t *vif_info, char *data, uint64_t timestamp_ms)
{
    if (!vif_info || !data) {
        LOG(ERR, "cgw_parse_vif_info_json: NULL parameter");
        return false;
    }

    json_t *root = json_object();
    if (!root) {
        LOG(ERR, "Failed to create JSON root object");
        return false;
    }

    // Add root level fields
    json_object_set_new(root, "networkId", json_string(air_dev.netwrk_id)); // TODO: Get from air_dev
    json_object_set_new(root, "deviceId", json_string(air_dev.device_id));
    json_object_set_new(root, "orgId", json_string(air_dev.org_id));
    json_object_set_new(root, "tms", json_integer(timestamp_ms));
    json_object_set_new(root, "type", json_string("vif_info"));

    // Add data object
    json_t *data_obj = json_object();
    
    // Radio info array
    json_t *radio_info_array = json_array();
    for (int i = 0; i < vif_info->n_radio; i++) {
        json_t *radio_info = json_object();
        json_object_set_new(radio_info, "band", json_string(vif_info->radio[i].band));
        json_object_set_new(radio_info, "channel", json_integer(vif_info->radio[i].channel));
        json_object_set_new(radio_info, "txpower", json_integer(vif_info->radio[i].txpower));
        json_array_append_new(radio_info_array, radio_info);
    }
    json_object_set_new(data_obj, "radio", radio_info_array);
    
    // VIF info array
    json_t *vif_info_array = json_array();
    for (int i = 0; i < vif_info->n_vif; i++) {
        json_t *vif_item = json_object();
        json_object_set_new(vif_item, "radio", json_string(vif_info->vif[i].radio));
        json_object_set_new(vif_item, "ssid", json_string(vif_info->vif[i].ssid));
        json_array_append_new(vif_info_array, vif_item);
    }
    json_object_set_new(data_obj, "vif", vif_info_array);
    
    // Ethernet info array
    json_t *ethernet_info_array = json_array();
    for (int i = 0; i < vif_info->n_ethernet; i++) {
        json_t *eth_info = json_object();
        json_object_set_new(eth_info, "interface", json_string(vif_info->ethernet[i].interface));
        json_object_set_new(eth_info, "name", json_string(vif_info->ethernet[i].name));
        json_object_set_new(eth_info, "type", json_string(vif_info->ethernet[i].type));
        json_array_append_new(ethernet_info_array, eth_info);
    }
    json_object_set_new(data_obj, "ethernet", ethernet_info_array);
    
    json_object_set_new(root, "data", data_obj);

    // Convert JSON object to string
    char *json_str = json_dumps(root, 0);
    if (!json_str) {
        LOG(ERR, "Error converting JSON object to string");
        json_decref(root);
        return false;
    }

    // Copy to output buffer safely
    size_t json_len = strlen(json_str);
    size_t max_size = 90000;
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

/* Parse device info event to JSON */
bool cgw_parse_device_info_json(device_info_event_t *device_info, char *data, uint64_t timestamp_ms)
{
    if (!device_info || !data) {
        LOG(ERR, "cgw_parse_device_info_json: NULL parameter");
        return false;
    }

    json_t *root = json_object();
    if (!root) {
        LOG(ERR, "Failed to create JSON root object");
        return false;
    }

    char mac_out[18];
    // Add root level fields
    json_object_set_new(root, "networkId", json_string(air_dev.netwrk_id)); // TODO: Get from air_dev
    json_object_set_new(root, "deviceId", json_string(air_dev.device_id));
    json_object_set_new(root, "orgId", json_string(air_dev.org_id));
    json_object_set_new(root, "tms", json_integer(timestamp_ms));
    json_object_set_new(root, "type", json_string("ap_info"));

    // Add data object
    json_t *data_obj = json_object();
    json_object_set_new(data_obj, "serialNum", json_string(air_dev.serial_num));
    if (mac_to_colon_format(air_dev.macaddr, mac_out, sizeof(mac_out)) == 0) {    
        json_object_set_new(data_obj, "macAddr", json_string(mac_out));
    } else {
        json_object_set_new(data_obj, "macAddr", json_string(air_dev.macaddr));
    }
    json_object_set_new(data_obj, "deviceType", json_string("Access Point"));
    json_object_set_new(data_obj, "model", json_string("MT7621"));
    json_object_set_new(data_obj, "firmwareVersion", json_string(device_info->firmwareVersion));
    json_object_set_new(data_obj, "manufacturer", json_string("Airpro"));
    json_object_set_new(data_obj, "egressIp", json_string(device_info->egressIp));
    json_object_set_new(data_obj, "mgmtIp", json_string(device_info->mgmtIp));
    json_object_set_new(data_obj, "latitude", json_string(device_info->latitude));
    json_object_set_new(data_obj, "longitude", json_string(device_info->longitude));
    
    json_object_set_new(root, "data", data_obj);

    // Convert JSON object to string
    char *json_str = json_dumps(root, 0);
    if (!json_str) {
        LOG(ERR, "Error converting JSON object to string");
        json_decref(root);
        return false;
    }

    // Copy to output buffer safely
    size_t json_len = strlen(json_str);
    size_t max_size = 90000;
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

