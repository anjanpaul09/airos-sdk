#include <stdarg.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <netev.h>
#include "dppline.h"

//#include "../../../pbuf/aircnms_config.pb-c.h"
#include "device_config.h"
#include "os_nif.h"
#define UCI_BUF_LEN 256
#define MAX_LAN_IP_RETRIES 3
uint8_t          netev_mqtt_buf[STATS_MQTT_BUF_SZ];

bool netev_get_current_change(device_conf_t *conf) 
{
    char cur_fw_version[UCI_BUF_LEN] = {0};
    __attribute__((unused)) char cur_mgmt_ip[32] = {0};
    char cur_egress_ip[32] = {0};
    os_ipaddr_t ip;
    __attribute__((unused)) int retry_count = 0;

    // Get current firmware version
    get_fw_version(cur_fw_version, sizeof(cur_fw_version));
    strncpy(conf->fw_info, cur_fw_version, sizeof(conf->fw_info) - 1);
    conf->fw_info[sizeof(conf->fw_info) - 1] = '\0';

    if (os_nif_ipaddr_get("br-lan", &ip)) {
        snprintf(conf->mgmt_ip, sizeof(conf->mgmt_ip), "%d.%d.%d.%d",
                 ip.addr[0], ip.addr[1], ip.addr[2], ip.addr[3]);
    }
    
    // Get public IP address
    if (get_public_ip(cur_egress_ip)) {
        strncpy(conf->egress_ip, cur_egress_ip, sizeof(conf->egress_ip) - 1);
        conf->egress_ip[sizeof(conf->egress_ip) - 1] = '\0';
    }
    strcpy(conf->hw_version, "1.0");

    return true;
}

int netev_get_config_proto_msg(uint8_t * buff, size_t sz, uint32_t * packed_sz, device_conf_t *conf)
{
    if (!buff || !sz || !conf) {
        return -1; // Error: Invalid arguments
    }

    // Ensure buffer has enough space
    uint32_t required_size = sizeof(device_conf_t);
    if (sz < required_size) {
        return -1; // Error: Buffer too small
    }

    // Copy the structure data into the buffer
    memcpy(buff, conf, required_size);

    // Update the packed size
    *packed_sz = required_size;
   
    return 0;
}

int netev_update_aircnms_param(device_conf_t *conf)
{
    int rc;
    char cmd[256];

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set aircnms.@device[0].mgmt_ip=%s", conf->mgmt_ip);
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set aircnms.@device[0].egress_ip=%s", conf->egress_ip);
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set aircnms.@device[0].fw_version=%s", conf->fw_info);
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set aircnms.@device[0].hw_version=%s", conf->hw_version);
    rc = system(cmd);
    rc = system("uci commit aircnms");

    return rc;
}

int netev_update_cloud_config(device_conf_t *conf)
{
    uint32_t buf_len;

    if (netev_get_config_proto_msg(netev_mqtt_buf, sizeof(netev_mqtt_buf), &buf_len, conf)) {
        LOGE("Get report failed.\n");
        return -1;
    }
     
    netev_update_aircnms_param(conf);

    if (!netev_mqtt_publish(buf_len, netev_mqtt_buf, CONF)) {
        printf("Publish report failed.\n");
    }

    return 0;
}

bool netev_check_device_config(device_conf_t *curr_conf)
{
#define UCI_BUF_LEN 256
    device_conf_t pre_conf;
    char buf[UCI_BUF_LEN];
    size_t len;
    int rc;
    
    memset(buf, 0, sizeof(buf));
    rc = cmd_buf("uci get aircnms.@device[0].mgmt_ip", buf, (size_t)UCI_BUF_LEN);
    len = strlen(buf);
    if (len == 0)
    {
        LOGI("%s: No uci found for mgmt-ip", __func__);
    }
    sscanf(buf, "%s", pre_conf.mgmt_ip);

    memset(buf, 0, sizeof(buf));
    rc = cmd_buf("uci get aircnms.@device[0].egress_ip", buf, (size_t)UCI_BUF_LEN);
    (void)rc;  // Result may be checked in future
    len = strlen(buf);
    if (len == 0)
    {
        LOGI("%s: No uci found egress-ip", __func__);
    }
    sscanf(buf, "%s", pre_conf.egress_ip);

    memset(buf, 0, sizeof(buf));
    rc = cmd_buf("uci get aircnms.@device[0].fw_version", buf, (size_t)UCI_BUF_LEN);
    len = strlen(buf);
    if (len == 0)
    {
        LOGI("%s: No uci found fw version", __func__);
    }
    sscanf(buf, "%s", pre_conf.fw_info);

    bool changed = false;

    // Compare and update each field
    if (strcmp(pre_conf.fw_info, curr_conf->fw_info) != 0) {
        changed = true;
    }

    if (strcmp(pre_conf.mgmt_ip, curr_conf->mgmt_ip) != 0) {
        changed = true;
    }

    if (strcmp(pre_conf.egress_ip, curr_conf->egress_ip) != 0) {
        changed = true;
    }

    return changed;
}


int netev_monitor_config_change()
{
    device_conf_t current_config;
    netev_get_current_change(&current_config);

    //printf("Ankit: Config Monitor!!! \n");
    if (netev_check_device_config(&current_config)) {
        printf("Configuration changed. Updated global config.\n");
        netev_update_cloud_config(&current_config);
    }

    return 0;
}

int netev_event_config_change()
{
    device_conf_t current_config;

    if (!netev_get_current_change(&current_config)) {
        LOG(ERR, "Failed to fetch current device configuration.");
        return -1;
    }
    
    netev_update_cloud_config(&current_config);

    return 0;
}

