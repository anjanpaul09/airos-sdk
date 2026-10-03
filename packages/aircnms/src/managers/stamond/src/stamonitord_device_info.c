#include <stdarg.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <stamonitord.h>

#include "stamonitord_device_info.h"
#include "stamonitord_info_events.h"
#include "info_events.h"
#include "os_nif.h"
#define UCI_BUF_LEN 256
#define MAX_LAN_IP_RETRIES 3

static struct ev_timer  stamonitord_mqtt_timer;
static double           stamonitord_mqtt_timer_interval = 10;
static bool             stamonitord_device_info_initial_sync_done = false;

bool stamonitord_is_cloud_enrolled(void)
{
    char mode[32] = {0};
    char dev_id[64] = {0};

    if (cmd_buf("uci get aircnms.@aircnms[0].mode", mode, sizeof(mode)) != 0) {
        return false;
    }
    mode[strcspn(mode, "\r\n \t")] = '\0';
    if (strcmp(mode, "cloud") != 0) {
        return false;
    }

    if (cmd_buf("uci get aircnms.@aircnms[0].device_id", dev_id, sizeof(dev_id)) != 0) {
        return false;
    }
    dev_id[strcspn(dev_id, "\r\n \t")] = '\0';
    if (dev_id[0] == '\0' || strcmp(dev_id, "XXXXXXXXXX") == 0) {
        return false;
    }

    return true;
}

bool stamonitord_get_current_change(device_info_event_t *conf) 
{
    char cur_fw_version[UCI_BUF_LEN] = {0};
    __attribute__((unused)) char cur_mgmt_ip[32] = {0};
    char cur_egress_ip[32] = {0};
    os_ipaddr_t ip;
    __attribute__((unused)) int retry_count = 0;

    // Get current firmware version
    get_fw_version(cur_fw_version, sizeof(cur_fw_version));
    strncpy(conf->firmwareVersion, cur_fw_version, sizeof(conf->firmwareVersion) - 1);
    conf->firmwareVersion[sizeof(conf->firmwareVersion) - 1] = '\0';

    if (os_nif_ipaddr_get("br-lan", &ip)) {
        snprintf(conf->mgmtIp, sizeof(conf->mgmtIp), "%d.%d.%d.%d",
                 ip.addr[0], ip.addr[1], ip.addr[2], ip.addr[3]);
    }
    
    // Get public IP address
    if (get_public_ip(cur_egress_ip)) {
        strncpy(conf->egressIp, cur_egress_ip, sizeof(conf->egressIp) - 1);
        conf->egressIp[sizeof(conf->egressIp) - 1] = '\0';
    }

    if (get_location_from_ipinfo(conf->latitude, sizeof(conf->latitude), conf->longitude, sizeof(conf->longitude))) {
        LOG(DEBUG, "Location retrieved successfully:\n");
    }

    return true;
}

int stamonitord_update_aircnms_param(device_info_event_t *conf)
{
    int rc;
    char cmd[256];

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set aircnms.@device[0].mgmt_ip=%s", conf->mgmtIp);
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set aircnms.@device[0].egress_ip=%s", conf->egressIp);
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set aircnms.@device[0].fw_version=%s", conf->firmwareVersion);
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set aircnms.@device[0].latitude=%s", conf->latitude);
    rc = system(cmd);
    
    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set aircnms.@device[0].longitude=%s", conf->longitude);
    rc = system(cmd);
    rc = system("uci commit aircnms");

    return rc;
}

int stamonitord_update_cloud_config(device_info_event_t *conf)
{
    uint64_t timestamp_ms = get_timestamp_ms();
     
    stamonitord_update_aircnms_param(conf);

    if (!stamonitord_send_device_info_event(conf, timestamp_ms)) {
        LOG(ERR, "Failed to send client connect info event");
    }

    return 0;
}

bool stamonitord_check_device_config(device_info_event_t *curr_conf)
{
#define UCI_BUF_LEN 256
    device_info_event_t pre_conf;
    memset(&pre_conf, 0, sizeof(pre_conf));
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
    sscanf(buf, "%s", pre_conf.mgmtIp);

    memset(buf, 0, sizeof(buf));
    rc = cmd_buf("uci get aircnms.@device[0].egress_ip", buf, (size_t)UCI_BUF_LEN);
    (void)rc;  // Result may be checked in future
    len = strlen(buf);
    if (len == 0)
    {
        LOGI("%s: No uci found egress-ip", __func__);
    }
    sscanf(buf, "%s", pre_conf.egressIp);

    memset(buf, 0, sizeof(buf));
    rc = cmd_buf("uci get aircnms.@device[0].fw_version", buf, (size_t)UCI_BUF_LEN);
    len = strlen(buf);
    if (len == 0)
    {
        LOGI("%s: No uci found fw version", __func__);
    }
    sscanf(buf, "%s", pre_conf.firmwareVersion);
    
    memset(buf, 0, sizeof(buf));
    rc = cmd_buf("uci get aircnms.@device[0].latitude", buf, (size_t)UCI_BUF_LEN);
    len = strlen(buf);
    if (len == 0)
    {
        LOGI("%s: No uci found fw version", __func__);
    }
    sscanf(buf, "%s", pre_conf.latitude);

    memset(buf, 0, sizeof(buf));
    rc = cmd_buf("uci get aircnms.@device[0].longitude", buf, (size_t)UCI_BUF_LEN);
    len = strlen(buf);
    if (len == 0)
    {
        LOGI("%s: No uci found fw version", __func__);
    }
    sscanf(buf, "%s", pre_conf.longitude);

    bool changed = false;

    // Compare and update each field
    if (strcmp(pre_conf.firmwareVersion, curr_conf->firmwareVersion) != 0) {
        changed = true;
    }

    if (strcmp(pre_conf.mgmtIp, curr_conf->mgmtIp) != 0) {
        changed = true;
    }

    if (strcmp(pre_conf.egressIp, curr_conf->egressIp) != 0) {
        changed = true;
    }

    if (strcmp(pre_conf.latitude, curr_conf->latitude) != 0) {
        changed = true;
    }
    
    if (strcmp(pre_conf.longitude, curr_conf->longitude) != 0) {
        changed = true;
    }

    return changed;
}


int stamonitord_monitor_device_info_change()
{
    if (!stamonitord_is_cloud_enrolled()) {
        return 0;
    }

    device_info_event_t current_config;
    stamonitord_get_current_change(&current_config);

    if (!stamonitord_device_info_initial_sync_done) {
        stamonitord_device_info_initial_sync_done = true;
        LOG(INFO, "Sending initial device info sync to cloud");
        stamonitord_update_cloud_config(&current_config);
    } else if (stamonitord_check_device_config(&current_config)) {
        printf("Configuration changed. Updated global config.\n");
        stamonitord_update_cloud_config(&current_config);
    }

    return 0;
}

void stamonitord_mqtt_timer_handler(struct ev_loop *loop, ev_timer *timer, int revents)
{
    (void)loop;
    (void)timer;
    (void)revents;

    stamonitord_monitor_device_info_change();
        
}

bool stamonitord_monitor_device_info(void)
{
    ev_timer_init(&stamonitord_mqtt_timer, stamonitord_mqtt_timer_handler, stamonitord_mqtt_timer_interval, stamonitord_mqtt_timer_interval);

    stamonitord_mqtt_timer.data = NULL;

    ev_timer_start(EV_DEFAULT, &stamonitord_mqtt_timer);

    return true;
}
