#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "qm.h"
#include "log.h"
#include "os_nif.h"
//#include "osp_unit.h"
#include "memutil.h"
#define TARGET_ID_SZ 16
#define MAX_TOPIC_LEN 264
#define MAX_TOPICS 16

#define UCI_BUF_LEN 256
#define MAX_LAN_IP_RETRIES 5

static char * getMac()
{   
    char * buff = NULL;
    
    buff = MALLOC(TARGET_ID_SZ);

    if (!osp_unit_id_get(buff, TARGET_ID_SZ))
    {
        LOG(ERR, "Error acquiring node id.");
        FREE(buff);
        return NULL;
    }

    return buff;
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

bool qm_set_aircnms_param()
{
    int rc;
    char cmd[256];
    char *mac = getMac();

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set aircnms.@aircnms[0].macaddr=%s", mac);
    rc = system(cmd);

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set aircnms.@aircnms[0].serial_num=AIR%s", mac);
    rc = system(cmd);

    rc = system("uci commit aircnms");

    return rc;
}

bool qm_set_online_status()
{
    int rc;
    char cmd[256];

    memset(cmd, 0, sizeof(cmd));
    sprintf(cmd, "uci set aircnms.@aircnms[0].online=1");
    rc = system(cmd);

    return rc;
}


int qm_check_online_status()
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

bool qm_check_valid_device_id() 
{
    char buf[UCI_BUF_LEN];
    size_t len;
    int rc;
    const char default_device_id[] = "XXXXXXXXXX";

    memset(buf, 0, sizeof(buf));

    rc = cmd_buf("uci get aircnms.@aircnms[0].device_id", buf, (size_t)UCI_BUF_LEN);
    if (rc != 0) {
        LOGI("%s: Failed to execute uci command", __func__);
        return false;
    }

    buf[strcspn(buf, "\n")] = '\0';
    len = strlen(buf);
    if (len != 10) {
        LOGI("%s: Invalid device_id length", __func__);
        return false;
    }

    if (strcmp(buf, default_device_id) == 0) {
        LOGI("%s: device_id is default value", __func__);
        return false;
    }

    for (size_t i = 0; i < len; i++) {
        if (!isdigit(buf[i])) {
            LOGI("%s: device_id contains non-digit characters", __func__);
            return false;
        }
    }

    return true;
}

void qm_add_topic_aircnms(qm_mqtt_topic_list *topic_list)
{
    char command[512];
    int i;

    for (i = 0; i < topic_list->n_topic; i++) {
        memset(command, 0, sizeof(command));
        snprintf(command, sizeof(command), "uci add_list aircnms.@aircnms[0].topics='%s'", topic_list->topic[i]);

        if (system(command) != 0) {
            fprintf(stderr, "Failed to execute command: %s\n", command);
        }
    }

    if (system("uci commit aircnms") != 0) {
        fprintf(stderr, "Failed to commit changes to /etc/config/aircnms\n");
    }
}
    
void qm_add_stats_topic_aircnms(stats_topic_t *stats_topic)
{
    char command[512];
        
    memset(command, 0, sizeof(command));
    snprintf(command, sizeof(command), "uci set aircnms.@stats-topic[0].device='%s'", stats_topic->device);
    system(command);

    memset(command, 0, sizeof(command));
    snprintf(command, sizeof(command), "uci set aircnms.@stats-topic[0].vif='%s'", stats_topic->vif);
    system(command);
    
    memset(command, 0, sizeof(command));
    snprintf(command, sizeof(command), "uci set aircnms.@stats-topic[0].client='%s'", stats_topic->client);
    system(command);
    
    memset(command, 0, sizeof(command));
    snprintf(command, sizeof(command), "uci set aircnms.@stats-topic[0].neighbor='%s'", stats_topic->neighbor);
    system(command);

    memset(command, 0, sizeof(command));
    snprintf(command, sizeof(command), "uci set aircnms.@stats-topic[0].config='%s'", stats_topic->config);
    system(command);

    memset(command, 0, sizeof(command));
    snprintf(command, sizeof(command), "uci set aircnms.@stats-topic[0].cmdr='%s'", stats_topic->cmdr);
    system(command);

    if (system("uci commit aircnms") != 0) {
        fprintf(stderr, "Failed to commit changes to /etc/config/aircnms\n");
    }
}

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

int qm_update_topic_lst(qm_mqtt_topic_list *topic_list)
{
    FILE *fp;
    char line[MAX_TOPIC_LEN * MAX_TOPICS];  
    char command[] = "uci get aircnms.@aircnms[0].topics";
    char *token;
    const char *delimiter = " ";

    topic_list->n_topic = 0;
    memset(topic_list, 0, sizeof(qm_mqtt_topic_list));

    fp = popen(command, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to run command\n"); 
        return -1;
    }

    if (fgets(line, sizeof(line), fp) == NULL) {
        fprintf(stderr, "Failed to read command output\n");
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
            fprintf(stderr, "Maximum number of topics reached\n");
            break;
        }

        token = strtok(NULL, delimiter);
    }
    
    return 0;
}

void qm_get_stats_topic_aircnms(stats_topic_t *stats_topic)
{
    const char *fields[] = {"device", "vif", "client", "neighbor", "config", "cmdr"};
    char *targets[] = {stats_topic->device, stats_topic->vif, stats_topic->client, 
                       stats_topic->neighbor, stats_topic->config, stats_topic->cmdr};
    size_t sizes[] = {sizeof(stats_topic->device), sizeof(stats_topic->vif), 
                     sizeof(stats_topic->client), sizeof(stats_topic->neighbor),
                     sizeof(stats_topic->config), sizeof(stats_topic->cmdr)};

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

