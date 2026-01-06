#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#include "log.h"
#include "os_nif.h"
//#include "osp_unit.h"
#include "memutil.h"
#include "cgw.h"
//#include "cgw_types.h"

#define MAX_MACADDR_SIZE 18
#define MAX_TOPIC_LEN 264
#define MAX_TOPICS 16

#define UCI_BUF_LEN 256
#define MAX_LAN_IP_RETRIES 5

static char *get_wan_macaddr(void)
{
    int sockfd;
    struct ifreq ifr;
    char *mac_str = NULL;
    unsigned char *mac_bytes = NULL;
    char temp[MAX_MACADDR_SIZE];
    
    mac_str = MALLOC(MAX_MACADDR_SIZE);
    if (!mac_str) {
        LOG(ERR, "Memory allocation failed for MAC address string");
        return NULL;
    }
    
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        LOG(ERR, "Failed to create socket: %s", strerror(errno));
        FREE(mac_str);
        return NULL;
    }
    
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        LOG(ERR, "Failed to get MAC address for eth0: %s", strerror(errno));
        close(sockfd);
        FREE(mac_str);
        return NULL;
    }
    
    close(sockfd);
    
    mac_bytes = (unsigned char *)ifr.ifr_hwaddr.sa_data;
    
    //snprintf(mac_str, MAX_MACADDR_SIZE, "%02x:%02x:%02x:%02x:%02x:%02x",
      //       mac_bytes[0], mac_bytes[1], mac_bytes[2],
        //     mac_bytes[3], mac_bytes[4], mac_bytes[5]);
 
        // 1️⃣ Create standard lowercase colon-separated MAC string
    snprintf(temp, sizeof(temp), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac_bytes[0], mac_bytes[1], mac_bytes[2],
             mac_bytes[3], mac_bytes[4], mac_bytes[5]);

    char *p = temp;
    char *q = mac_str;
    while (*p) {
        if (*p != ':')
            *q++ = toupper((unsigned char)*p);
        p++;
    }
    *q = '\0';

    LOG(INFO, "Retrieved WAN MAC address: %s", mac_str);
    return mac_str;
}


int get_uptime_seconds() 
{
    FILE *fp;
    double uptime = 0.0;

    fp = fopen("/proc/uptime", "r");
    if (fp == NULL) {
        return -1;
    }

    if (fscanf(fp, "%lf", &uptime) != 1) {
        fclose(fp);
        return -1;
    }

    fclose(fp);

    return (int)uptime;
}

bool cgw_params_init()
{
    int rc = 0;
    char cmd[256];
    char *mac = get_wan_macaddr();

    if (!mac) {
        LOG(ERR, "Failed to get MAC address");
        return false;
    }

    memset(cmd, 0, sizeof(cmd));
    int ret = snprintf(cmd, sizeof(cmd), "uci set aircnms.@aircnms[0].macaddr=%s", mac);
    if (ret < 0 || ret >= (int)sizeof(cmd)) {
        LOG(ERR, "Command buffer overflow for macaddr (ret=%d)", ret);
        FREE(mac);
        return false;
    }
    rc = system(cmd);
    if (rc != 0) {
        LOG(ERR, "Failed to set MAC address: command returned %d", rc);
        FREE(mac);
        return false;
    }

    memset(cmd, 0, sizeof(cmd));
    ret = snprintf(cmd, sizeof(cmd), "uci set aircnms.@aircnms[0].serial_num=AIR%s", mac);
    if (ret < 0 || ret >= (int)sizeof(cmd)) {
        LOG(ERR, "Command buffer overflow for serial_num (ret=%d)", ret);
        FREE(mac);
        return false;
    }
    rc = system(cmd);
    if (rc != 0) {
        LOG(ERR, "Failed to set serial number: command returned %d", rc);
        FREE(mac);
        return false;
    }

    rc = system("uci commit aircnms");
    if (rc != 0) {
        LOG(ERR, "Failed to commit UCI changes: command returned %d", rc);
        FREE(mac);
        return false;
    }

    FREE(mac);
    return true;
}

int cgw_check_online_status()
{
    char buf[UCI_BUF_LEN];
    size_t len;
    int status = 0;

    memset(buf, 0, sizeof(buf));
    cmd_buf("uci get aircnms.@aircnms[0].online", buf, (size_t)UCI_BUF_LEN);

    len = strlen(buf);
    if (len == 0) {
        LOGI("%s: No uci found", __func__);
        return 0; 
    }

    status = atoi(buf);

    return status;
}

bool cgw_check_valid_device_id() 
{
    char buf[UCI_BUF_LEN];
    size_t len;
    int rc;
    // Removed hardcoded default value - should be validated via configuration

    memset(buf, 0, sizeof(buf));

    rc = cmd_buf("uci get aircnms.@aircnms[0].device_id", buf, (size_t)UCI_BUF_LEN);
    if (rc != 0) {
        LOG(ERR, "%s: Failed to execute uci command", __func__);
        return false;
    }

    buf[strcspn(buf, "\n")] = '\0';
    len = strlen(buf);
    
    // Validate device_id format: should be exactly 10 digits and not all X's
    if (len != 10) {
        LOG(ERR, "%s: Invalid device_id length: expected 10, got %zu", __func__, len);
        return false;
    }

    // Check for placeholder values (all same character)
    bool all_same = true;
    for (size_t i = 1; i < len && all_same; i++) {
        if (buf[i] != buf[0]) {
            all_same = false;
        }
    }
    if (all_same && (buf[0] == 'X' || buf[0] == '0' || buf[0] == '-' || buf[0] == '_')) {
        LOG(ERR, "%s: device_id appears to be placeholder value", __func__);
        return false;
    }

    // Validate all characters are digits
    for (size_t i = 0; i < len; i++) {
        if (!isdigit((unsigned char)buf[i])) {
            LOG(ERR, "%s: device_id contains non-digit characters", __func__);
            return false;
        }
    }

    return true;
}

void cgw_add_topic_aircnms(cgw_mqtt_topic_list *topic_list)
{
    char command[512];
    int i;
    int rc;

    if (!topic_list) {
        LOG(ERR, "Invalid topic_list parameter");
        return;
    }

    for (i = 0; i < topic_list->n_topic && i < 16; i++) {  // Validate against MAX_TOPICS
        memset(command, 0, sizeof(command));
        int ret = snprintf(command, sizeof(command), "uci add_list aircnms.@aircnms[0].topics='%s'", 
                          topic_list->topic[i]);
        if (ret < 0 || ret >= (int)sizeof(command)) {
            LOG(ERR, "Command buffer overflow for topic %d (ret=%d)", i, ret);
            continue;
        }

        rc = system(command);
        if (rc != 0) {
            LOG(ERR, "Failed to execute command for topic %d: %s (exit code: %d)", 
                i, command, rc);
        }
    }

    rc = system("uci commit aircnms");
    if (rc != 0) {
        LOG(ERR, "Failed to commit changes to /etc/config/aircnms (exit code: %d)", rc);
    }
}
    
void cgw_add_stats_topic_aircnms(stats_topic_t *stats_topic)
{
    char command[512];
    int rc;
    int ret;
        
    if (!stats_topic) {
        LOG(ERR, "Invalid stats_topic parameter");
        return;
    }

    memset(command, 0, sizeof(command));
    ret = snprintf(command, sizeof(command), "uci set aircnms.@stats-topic[0].device='%s'", stats_topic->device);
    if (ret < 0 || ret >= (int)sizeof(command)) {
        LOG(ERR, "Command buffer overflow for device topic (ret=%d)", ret);
    } else {
        rc = system(command);
        if (rc != 0) {
            LOG(ERR, "Failed to set device topic (exit code: %d)", rc);
        }
    }

    memset(command, 0, sizeof(command));
    ret = snprintf(command, sizeof(command), "uci set aircnms.@stats-topic[0].vif='%s'", stats_topic->vif);
    if (ret < 0 || ret >= (int)sizeof(command)) {
        LOG(ERR, "Command buffer overflow for vif topic (ret=%d)", ret);
    } else {
        rc = system(command);
        if (rc != 0) {
            LOG(ERR, "Failed to set vif topic (exit code: %d)", rc);
        }
    }
    
    memset(command, 0, sizeof(command));
    ret = snprintf(command, sizeof(command), "uci set aircnms.@stats-topic[0].client='%s'", stats_topic->client);
    if (ret < 0 || ret >= (int)sizeof(command)) {
        LOG(ERR, "Command buffer overflow for client topic (ret=%d)", ret);
    } else {
        rc = system(command);
        if (rc != 0) {
            LOG(ERR, "Failed to set client topic (exit code: %d)", rc);
        }
    }
    
    memset(command, 0, sizeof(command));
    ret = snprintf(command, sizeof(command), "uci set aircnms.@stats-topic[0].neighbor='%s'", stats_topic->neighbor);
    if (ret < 0 || ret >= (int)sizeof(command)) {
        LOG(ERR, "Command buffer overflow for neighbor topic (ret=%d)", ret);
    } else {
        rc = system(command);
        if (rc != 0) {
            LOG(ERR, "Failed to set neighbor topic (exit code: %d)", rc);
        }
    }

    memset(command, 0, sizeof(command));
    ret = snprintf(command, sizeof(command), "uci set aircnms.@stats-topic[0].config='%s'", stats_topic->config);
    if (ret < 0 || ret >= (int)sizeof(command)) {
        LOG(ERR, "Command buffer overflow for config topic (ret=%d)", ret);
    } else {
        rc = system(command);
        if (rc != 0) {
            LOG(ERR, "Failed to set config topic (exit code: %d)", rc);
        }
    }

    memset(command, 0, sizeof(command));
    ret = snprintf(command, sizeof(command), "uci set aircnms.@stats-topic[0].cmdr='%s'", stats_topic->cmdr);
    if (ret < 0 || ret >= (int)sizeof(command)) {
        LOG(ERR, "Command buffer overflow for cmdr topic (ret=%d)", ret);
    } else {
        rc = system(command);
        if (rc != 0) {
            LOG(ERR, "Failed to set cmdr topic (exit code: %d)", rc);
        }
    }

    memset(command, 0, sizeof(command));
    ret = snprintf(command, sizeof(command), "uci set aircnms.@stats-topic[0].status='%s'", stats_topic->status);
    if (ret < 0 || ret >= (int)sizeof(command)) {
        LOG(ERR, "Command buffer overflow for status topic (ret=%d)", ret);
    } else {
        rc = system(command);
        if (rc != 0) {
            LOG(ERR, "Failed to set status topic (exit code: %d)", rc);
        }
    }

    memset(command, 0, sizeof(command));
    ret = snprintf(command, sizeof(command), "uci set aircnms.@stats-topic[0].website_usage='%s'", stats_topic->website_usage);
    if (ret < 0 || ret >= (int)sizeof(command)) {
        LOG(ERR, "Command buffer overflow for website_usage topic (ret=%d)", ret);
    } else {
        rc = system(command);
        if (rc != 0) {
            LOG(ERR, "Failed to set website_usage topic (exit code: %d)", rc);
        }
    }

    rc = system("uci commit aircnms");
    if (rc != 0) {
        LOG(ERR, "Failed to commit changes to /etc/config/aircnms (exit code: %d)", rc);
    }
}

#if 0
void remove_newline(char *str)
{
    int i;
    int len = strlen(str);

    for (i=0; i<len; i++) {
        if (str[i] == '\n') {
            str[i] = '\0';
        }
    }
}

int cgw_update_topic_lst(cgw_mqtt_topic_list *topic_list)
{
    FILE *fp;
    char line[MAX_TOPIC_LEN * MAX_TOPICS];  
    char command[] = "uci get aircnms.@aircnms[0].topics";
    char *token;
    const char *delimiter = " ";

    topic_list->n_topic = 0;
    memset(topic_list, 0, sizeof(cgw_mqtt_topic_list));

    fp = popen(command, "r");
    if (fp == NULL) {
        LOG(ERR, "Failed to run command: %s", command);
        return -1;
    }

    if (fgets(line, sizeof(line), fp) == NULL) {
        LOG(ERR, "Failed to read command output: %s", command);
        pclose(fp);
        return -1;
    }

    pclose(fp);

    token = strtok(line, delimiter);
    while (token != NULL) {
        if (topic_list->n_topic < MAX_TOPICS) {
            remove_newline(token);
            strncpy(topic_list->topic[topic_list->n_topic], token, MAX_TOPIC_LEN - 1);
            topic_list->topic[topic_list->n_topic][MAX_TOPIC_LEN - 1] = '\0';  
            topic_list->n_topic++;
        } else {
            LOG(ERR, "Maximum number of topics reached");
            break;
        }

        token = strtok(NULL, delimiter);
    }
    
    return 0;
}
#endif

static void remove_newline(char *str)
{
    char *p = strchr(str, '\n');
    if (p) *p = '\0';
}

int cgw_update_topic_lst(cgw_mqtt_topic_list *topic_list)
{
    FILE *fp;
    char line[MAX_TOPIC_LEN * MAX_TOPICS];
    const char *cmd = "uci get aircnms.@aircnms[0].topics";
    char *token;
    const char *delimiter = " \t\r\n";

    if (!topic_list)
        return -1;

    memset(topic_list, 0, sizeof(*topic_list));

    fp = popen(cmd, "r");
    if (!fp) {
        LOG(ERR, "Failed to run command: %s", cmd);
        return -1;
    }

    if (!fgets(line, sizeof(line), fp)) {
        LOG(ERR, "Failed to read command output: %s", cmd);
        pclose(fp);
        return -1;
    }
    pclose(fp);

    token = strtok(line, delimiter);
    while (token) {
        if (topic_list->n_topic >= MAX_TOPICS) {
            LOG(ERR, "Maximum topic limit (%d) reached", MAX_TOPICS);
            return -2; // Optional: indicate truncation
        }

        remove_newline(token);
        strncpy(topic_list->topic[topic_list->n_topic], token, MAX_TOPIC_LEN - 1);
        topic_list->topic[topic_list->n_topic][MAX_TOPIC_LEN - 1] = '\0';
        topic_list->n_topic++;

        token = strtok(NULL, delimiter);
    }

    return topic_list->n_topic;
}

void cgw_get_stats_topic_aircnms(stats_topic_t *stats_topic)
{
    const char *fields[] = {"device", "vif", "client", "neighbor", "config", "cmdr", "status", "website_usage"};
    char *targets[] = {stats_topic->device, stats_topic->vif, stats_topic->client, 
                       stats_topic->neighbor, stats_topic->config, stats_topic->cmdr,
                       stats_topic->status, stats_topic->website_usage};
    size_t sizes[] = {sizeof(stats_topic->device), sizeof(stats_topic->vif), 
                     sizeof(stats_topic->client), sizeof(stats_topic->neighbor),
                     sizeof(stats_topic->config), sizeof(stats_topic->cmdr),
                     sizeof(stats_topic->status), sizeof(stats_topic->website_usage)};

    char command[128];
    char buffer[256];
    FILE *fp;

    memset(stats_topic, 0, sizeof(stats_topic_t));

    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        snprintf(command, sizeof(command), "uci get aircnms.@stats-topic[0].%s 2>/dev/null", fields[i]);

        fp = popen(command, "r");
        if (fp) {
            if (fgets(buffer, sizeof(buffer), fp)) {
                buffer[strcspn(buffer, "\n")] = '\0';  // Remove newline
                strncpy(targets[i], buffer, sizes[i] - 1);
            }
            pclose(fp);
        }
    }
}

int cmd_buf(const char *command, char *buffer, size_t buffer_size)
{
    FILE *fp;
    int result = -1;

    if (!command || !buffer || buffer_size == 0) {
        LOG(ERR, "Invalid parameters for cmd_buf");
        return -1;
    }

    fp = popen(command, "r");
    if (fp == NULL) {
        LOG(ERR, "Failed to execute command: %s", command);
        return -1;
    }

    if (fgets(buffer, buffer_size, fp) != NULL) {
        // Remove trailing newline
        buffer[strcspn(buffer, "\n")] = '\0';
        result = 0;
    } else {
        LOG(ERR, "Failed to read command output: %s", command);
    }

    pclose(fp);
    return result;
}


