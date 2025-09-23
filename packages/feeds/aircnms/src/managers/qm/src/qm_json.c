#include <stdio.h>
#include <jansson.h>
#include <linux/nl80211.h>
#include "../../../pbuf/aircnms_stats.pb-c.h"
#include "../../../pbuf/aircnms_alarm.pb-c.h"
#include "../../../pbuf/aircnms_config.pb-c.h"
#include "memutil.h"

#include "qm.h"

int get_ht_mode(enum nl80211_chan_width chanwidth, char *ht_mode)
{
    switch (chanwidth) {
        case NL80211_CHAN_WIDTH_20_NOHT:
            strcpy(ht_mode, "NOHT20");
            break;
        case NL80211_CHAN_WIDTH_20:
            strcpy(ht_mode, "HT20");
            break;
        case NL80211_CHAN_WIDTH_40:
            strcpy(ht_mode, "HT40");
            break;
        case NL80211_CHAN_WIDTH_80:
            strcpy(ht_mode, "HT80");
            break;
        case NL80211_CHAN_WIDTH_80P80:
            strcpy(ht_mode, "HT80P80");
            break;
        case NL80211_CHAN_WIDTH_160:
            strcpy(ht_mode, "HT160");
            break;
        default:
            strscpy(ht_mode, "Undefined");
            break;
    }

    return 0;
}

bool qm_parse_neighbor_json(Sts__Report *rpt, char *data)
{
    json_t *root = json_object();
    json_t *neighbor_root = json_object();
    json_t *neighbor_array = json_array();
    int n_neighbor = rpt->n_neighbors;

    json_object_set_new(root, "serialNum", json_string(air_dev.serial_num));
    json_object_set_new(root, "deviceId", json_string(air_dev.device_id));
    json_object_set_new(root, "macAddr", json_string(air_dev.macaddr));
    for (int itr = 0; itr < n_neighbor; itr++) {
       Sts__Neighbor *sr = NULL;
       sr = rpt->neighbors[itr];

       char band[8];
       if (sr->band == STS__RADIO_BAND_TYPE__BAND2G) {
           strcpy(band, "2.4GHz");
        } else if ( sr->band == STS__RADIO_BAND_TYPE__BAND5G) {
            strcpy(band, "5GHz");
        } else if ( sr->band == STS__RADIO_BAND_TYPE__BAND5GL) {
            strcpy(band, "5GL");
        } else if ( sr->band == STS__RADIO_BAND_TYPE__BAND5GU) {
            strcpy(band, "5GU");
        } else if ( sr->band == STS__RADIO_BAND_TYPE__BAND6G) {
            strcpy(band, "6GHz");
        }

        if (sr->has_timestamp_ms) {
            json_object_set_new(root, "tms", json_integer(sr->timestamp_ms));
        }    

        for (int i = 0; i < sr->n_bss_list; i++)
        {
            Sts__Neighbor__NeighborBss *dr = NULL; // dest rec
            dr = sr->bss_list[i];
        
            json_t *neighbor = json_object();

            json_object_set_new(neighbor, "bssid", json_string(dr->bssid));
            json_object_set_new(neighbor, "ssid", json_string(dr->ssid));
            if (dr->has_rssi) {
                int rssi = dr->rssi - 95;

                json_object_set_new(neighbor, "rssi", json_integer(rssi));
            }
            if (dr->has_tsf) {
                json_object_set_new(neighbor, "tsf", json_integer(dr->tsf));
            }
            json_object_set_new(neighbor, "channel", json_integer(dr->channel));
            if (dr->has_chan_width) {
                char chwidth[16] = {0};
                get_ht_mode(dr->chan_width, chwidth);
                json_object_set_new(neighbor, "channelWidth", json_string(chwidth));
            }
        
            json_object_set_new(neighbor, "band", json_string(band));
            json_array_append_new(neighbor_array, neighbor);
        }
    
    }
    json_object_set_new(root, "data", neighbor_array);

    char *json_str = NULL;
    json_str = json_dumps(root, 0);
    if (!json_str) {
        fprintf(stderr, "Failed to serialize message to JSON\n");
        json_decref(root);
        return 1;
    }
    strcpy(data, json_str);

    // Print serialized JSON string
    printf("Serialized JSON:\n%s\n", json_str);

    // Cleanup
    free(json_str);
    json_decref(root);

    return true;
}


bool qm_parse_device_json(Sts__Device *device, Sts__VifStatReport *vr, char *data)
{
    json_t *root = json_object();
    json_t *j_obj = json_object();
    json_t *device_root = json_object();
    long tx_mb = 0, rx_mb = 0;
    int total_sta = 0;

    json_object_set_new(root, "serialNum", json_string(air_dev.serial_num));
    json_object_set_new(root, "deviceId", json_string(air_dev.device_id));
    json_object_set_new(root, "macAddr", json_string(air_dev.macaddr));
    if(device->has_timestamp_ms){
        json_object_set_new(root, "tms", json_integer(device->timestamp_ms));
    }

    //system 
    json_t *system_obj = json_object();
    if(device->has_uptime){
        json_object_set_new(system_obj, "uptime", json_integer(device->uptime));
    }
    json_object_set_new(system_obj, "downtime", json_integer(0));
  
    if (vr) {
        int n_vif_list = vr->n_vif_list;
        for (int itr = 0; itr < n_vif_list; itr++){
            Sts__Vif *vl = NULL;
            vl = vr->vif_list[itr];
        
            total_sta += vl->stat_num_sta;
            tx_mb += vl->stat_uplink_mb;
            rx_mb += vl->stat_downlink_mb;
        }
    }
    json_object_set_new(system_obj, "totalClient", json_integer(total_sta));
    json_object_set_new(system_obj, "uplinkMb", json_integer(tx_mb));
    json_object_set_new(system_obj, "downlinkMb", json_integer(rx_mb));
    json_object_set_new(system_obj, "totalTrafficMb", json_integer(tx_mb + rx_mb));
    json_object_set_new(device_root, "system", system_obj);

    //memutil
    json_t *memUtil_obj = json_object();
    Sts__Device__MemUtil *mem_util = NULL;
    mem_util = device->mem_util;
    json_object_set_new(memUtil_obj, "memTotal", json_integer(mem_util->mem_total));
    json_object_set_new(memUtil_obj, "memUsed", json_integer(mem_util->mem_used));
    json_object_set_new(memUtil_obj, "swapTotal", json_integer(mem_util->swap_total));
    json_object_set_new(memUtil_obj, "swapUsed", json_integer(mem_util->swap_used));
    json_object_set_new(device_root, "memUtil", memUtil_obj);

    //fsutil
    int n_fs_util = device->n_fs_util;
    json_t *fsUtil_arr = json_array();
    for (int i = 0; i < n_fs_util; i++) {
        json_t *fsUtil_obj = json_object();
        Sts__Device__FsUtil *fs_util = NULL;
        fs_util = device->fs_util[i];

        if (fs_util->fs_type == STS__FS_TYPE__FS_TYPE_ROOTFS) {
            json_object_set_new(fsUtil_obj, "fsType", json_string("FS_TYPE_ROOTFS"));
        } else if (fs_util->fs_type == STS__FS_TYPE__FS_TYPE_TMPFS) {
            json_object_set_new(fsUtil_obj, "fsType", json_string("FS_TYPE_TMPFS"));
        } 
        json_object_set_new(fsUtil_obj, "fsTotal", json_integer(fs_util->fs_total));
        json_object_set_new(fsUtil_obj, "fsUsed", json_integer(fs_util->fs_used));
        json_array_append_new(fsUtil_arr, fsUtil_obj);
    }
    json_object_set_new(device_root, "fsUtil", fsUtil_arr);
    //json_object_set_new(root, "data", device_root);
    
    //cpuutil
    json_t *cpuutil_obj = json_object();
    Sts__Device__CpuUtil *cpuutil = NULL;
    cpuutil = device->cpuutil;
    if(cpuutil->has_cpu_util){
        json_object_set_new(cpuutil_obj, "cpuUtil", json_integer(cpuutil->cpu_util));
    }
    json_object_set_new(device_root, "cpuUtil", cpuutil_obj);

    //pscpuutil
    json_t *pscpuutil_arr = json_array();
    int n_ps_cpu_util = device->n_ps_cpu_util;
    for(int i = 0; i < n_ps_cpu_util; i++){
        json_t *PsCpuUtil_obj = json_object();
        Sts__Device__PerProcessUtil *ps_cpu_util = NULL;
        ps_cpu_util = device->ps_cpu_util[i];

        json_object_set_new(PsCpuUtil_obj, "pid", json_integer(ps_cpu_util->pid));
        json_object_set_new(PsCpuUtil_obj, "cmd", json_string(ps_cpu_util->cmd));
        json_object_set_new(PsCpuUtil_obj, "util", json_integer(ps_cpu_util->util));
        
        json_array_append_new(pscpuutil_arr, PsCpuUtil_obj);
    }
    json_object_set_new(device_root, "psCpuUtil", pscpuutil_arr);

    json_object_set_new(root, "data", device_root);

    char *json_str = NULL;
    json_str = json_dumps(root, 0);
    if (!json_str) {
        fprintf(stderr, "Failed to serialize message to JSON\n");
        json_decref(j_obj);
        return 1;
    }
    strcpy(data, json_str);

    // Print serialized JSON string
    printf("Serialized JSON:\n%s\n", json_str);

    // Cleanup
    free(json_str);
    json_decref(device_root);
    
    return true;
}

bool qm_parse_vif_json(Sts__VifStatReport *vr, char *data)
{
    json_t *vif_root = json_object();
    json_t *vif = json_object();
    json_t *vif_array = json_array();
    json_t *radio_array = json_array();

    json_object_set_new(vif_root, "serialNum", json_string(air_dev.serial_num));
    json_object_set_new(vif_root, "deviceId", json_string(air_dev.device_id));
    json_object_set_new(vif_root, "macAddr", json_string(air_dev.macaddr));
    if(vr->has_timestamp_ms){
        json_object_set_new(vif_root, "tms", json_integer(vr->timestamp_ms));
    }

    int n_radio_list = vr->n_radio_list;
    for (int itr = 0; itr < n_radio_list; itr++){
        Sts__Radio *rl = NULL;
        rl = vr->radio_list[itr];
        
        json_t *radio = json_object();
        
        json_object_set_new(radio, "band", json_string(rl->band));
        json_object_set_new(radio, "channel", json_integer(rl->channel));
        json_object_set_new(radio, "txpower", json_integer(rl->txpower));
        json_object_set_new(radio, "channel_utilization", json_integer(rl->channel_utilization));

        json_array_append_new(radio_array, radio);
    }
    json_object_set_new(vif, "radio", radio_array);

    int n_vif_list = vr->n_vif_list;
    for (int itr = 0; itr < n_vif_list; itr++){
        Sts__Vif *vl = NULL;
        vl = vr->vif_list[itr];
        
        json_t *vif = json_object();
        
        json_object_set_new(vif, "band", json_string(vl->radio));
        json_object_set_new(vif, "ssid", json_string(vl->stat_ssid));
        json_object_set_new(vif, "statNumSta", json_integer(vl->stat_num_sta));
        json_object_set_new(vif, "statUplinkMb", json_integer(vl->stat_uplink_mb));
        json_object_set_new(vif, "statDownlinkMb", json_integer(vl->stat_downlink_mb));

        json_array_append_new(vif_array, vif);
    }
    json_object_set_new(vif, "vif", vif_array);
    json_object_set_new(vif_root, "data", vif);

    char *json_str = NULL;
    json_str = json_dumps(vif_root, 0);
    if (!json_str) {
        fprintf(stderr, "Failed to serialize message to JSON\n");
        json_decref(vif_root);
        return 1;
    }
    strcpy(data, json_str);

    // Print serialized JSON string
    printf("Serialized JSON:\n%s\n", json_str);

    // Cleanup
    free(json_str);
    json_decref(vif_root);
    
    return true;
}

bool qm_parse_client_json(Sts__Report *rpt, char * data)
{
    json_t *root = json_object();
    json_t *client_root = json_object();
    json_t *client_arr = json_array();
    int n_client = rpt->n_clients;
    
    json_object_set_new(root, "serialNum", json_string(air_dev.serial_num));
    json_object_set_new(root, "deviceId", json_string(air_dev.device_id));
    json_object_set_new(root, "macAddr", json_string(air_dev.macaddr));
    for (int i = 0; i < rpt->n_clients; i++){
        Sts__ClientReport *cr = NULL;
        cr = rpt->clients[i];

        if(cr->has_timestamp_ms){
            json_object_set_new(root, "tms", json_integer(cr->timestamp_ms));
        }
    
        char band[8];
        if(cr->band == STS__RADIO_BAND_TYPE__BAND2G) {
            strcpy(band, "BAND2G");
        } else if(cr->band == STS__RADIO_BAND_TYPE__BAND5G) {
            strcpy(band, "BAND5G");
        } else if(cr->band == STS__RADIO_BAND_TYPE__BAND5GL) {
            strcpy(band, "BAND5GL");
        } else if(cr->band == STS__RADIO_BAND_TYPE__BAND5GU) {
            strcpy(band, "BAND5GU");
        } else if(cr->band == STS__RADIO_BAND_TYPE__BAND6G) {
            strcpy(band, "BAND6G");
        } 

        int channel = cr->channel;
        int n_client_list = cr->n_client_list;
        for (int itr = 0; itr < n_client_list; itr++){
            json_t *client = json_object();
            Sts__Client *cl = NULL;
            cl = cr->client_list[itr];
        
            json_object_set_new(client, "macAddress", json_string(cl->mac_address));
            json_object_set_new(client, "hostname", json_string(cl->hostname));
            json_object_set_new(client, "ipAddress", json_string(cl->ip_address));
            json_object_set_new(client, "ssid", json_string(cl->ssid));
        
            if (cl->has_connected){
                json_object_set_new(client, "isConnected", json_integer(cl->connected));
            }
            if (cl->has_connect_count){
                json_object_set_new(client, "connectCount", json_integer(cl->connect_count));
            }
            if (cl->has_disconnect_count){
                json_object_set_new(client, "disconnectCount", json_integer(cl->disconnect_count));
            }
            if (cl->has_duration_ms){
                json_object_set_new(client, "durationMs", json_integer(cl->duration_ms));
            }
            json_object_set_new(client, "channel", json_integer(channel));
            json_object_set_new(client, "band", json_string(band));

            json_t *stats_obj = json_object();
            Sts__Client__Stats *stats = NULL;
            stats = cl->stats;
            if (stats->has_rx_bytes){
                json_object_set_new(stats_obj, "rxBytes", json_integer(stats->rx_bytes));
            }
            if (stats->has_tx_bytes){
                json_object_set_new(stats_obj, "txBytes", json_integer(stats->tx_bytes));
            }
            if (stats->has_rx_frames){
                json_object_set_new(stats_obj, "rxFrames", json_integer(stats->rx_frames));
            }
            if (stats->has_tx_frames){
                json_object_set_new(stats_obj, "txFrames", json_integer(stats->tx_frames));
            }
            if (stats->has_rx_rate){
                json_object_set_new(stats_obj, "rxRate", json_integer(stats->rx_rate));
            }
            if (stats->has_tx_rate){
                json_object_set_new(stats_obj, "txRate", json_integer(stats->tx_rate));
            }
            if (stats->has_rssi){
                json_object_set_new(stats_obj, "rssi", json_integer(stats->rssi));
            }
            json_object_set_new(client, "stats", stats_obj);
        
            json_array_append_new(client_arr, client);
        
        }
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
    printf("Serialized JSON:\n%s\n", json_str);

    // Cleanup
    free(json_str);
    json_decref(root);
    
    return true;
}

bool qm_parse_alarm_json(Sts__AlarmMessage *alarm, char *data)
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
    printf("Serialized JSON:\n%s\n", json_str);

    // Cleanup
    free(json_str);
    json_decref(root);
    
    return true;
}

bool qm_parse_event_json(Sts__EventMessage *event, char *data)
{
    json_t *root = json_object();
    json_t *event_root = json_object();
    
    if ( event->type == STS__EVENT_TYPE__UPGRADE ) {
        json_object_set_new(root, "type", json_string("device_upgrading_data"));
    } else if ( event->type == STS__EVENT_TYPE__ALARM ) {
        json_object_set_new(root, "type", json_string("device_alarm"));
    } else if ( event->type == STS__EVENT_TYPE__CMD ) {
        json_object_set_new(root, "type", json_string("device_cmd_data"));
    }
    
    if ( event->type == STS__EVENT_TYPE__UPGRADE ) {
        if ( event->status == STS__EVENT_STATUS__DOWNLOADED ) {
            json_object_set_new(event_root, "status", json_string("Downloaded"));
        } else if ( event->status == STS__EVENT_STATUS__UPGRADING ) {
            json_object_set_new(event_root, "status", json_string("Upgrading"));
        }  else if ( event->status == STS__EVENT_STATUS__FAILED ) {
            json_object_set_new(event_root, "status", json_string("Failed"));
        }  else if ( event->status == STS__EVENT_STATUS__UPGRADED ) {
            json_object_set_new(event_root, "status", json_string("Success"));
        }
        json_object_set_new(event_root, "device_firmware_id", json_string(event->cloud_id));
    } else if ( event->type == STS__EVENT_TYPE__CMD ) {
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
    printf("Serialized JSON:\n%s\n", json_str);

    // Cleanup
    free(json_str);
    json_decref(root);
    
    return true;

}

int qm_parse_config_json(Sts__DeviceConf *conf, char *data)
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
    printf("Serialized JSON:\n%s\n", json_str);

    // Cleanup
    free(json_str);
    json_decref(root);
    
    return true;
}
