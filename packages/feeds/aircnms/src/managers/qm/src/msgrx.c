#include "common.h"
#include <netinet/in.h>
#include "zlib.h"
#include "cm_conn.h"
#include "sm_conn.h"
#include "dm_conn.h"
#include "qm.h"

void qm_restart_dm_process()
{
    FILE *fp;
    char pid_str[16];
    char kill_cmd[32];

    // Get the PID of the process
    fp = popen("pidof dm", "r");
    if (fp == NULL) {
        perror("Failed to run pidof command");
        return;
    }

    // Read the PID
    if (fgets(pid_str, sizeof(pid_str), fp) != NULL) {
        // Prepare the kill command
        snprintf(kill_cmd, sizeof(kill_cmd), "kill -9 %s", pid_str);
        LOG(INFO, "Executing: %s", kill_cmd);

        // Execute the kill command
        system(kill_cmd);
    } else {
        LOG(INFO, "No process found for /usr/sbin/dm\n");
    }

    pclose(fp);
    return;
}

int qm_send_msg_to_dm(char *payload, long payloadlen, char *topic)
{
    dm_response_t dm_res;
    bool ret;
    int retry_count = 0;
    const int max_retries = 3;

    while (retry_count < max_retries) {
        ret = dm_conn_send_topic_stats(payload, payloadlen, &dm_res, topic);

        if (ret) {
            return true; // Success, exit early
        }

        qm_restart_dm_process(); // needs optimization
        usleep(2000000);
        LOG(INFO, "QM: dm FAILED on attempt %d!!!!\n", retry_count + 1);
        retry_count++;
    }

    // If all retries failed
    LOG(INFO, "QM: dm FAILED after %d attempts!!!!\n", max_retries);

    return false;
}

int qm_handle_msgrx(char *payload, long payloadlen, char *topic)
{
    cm_response_t cm_res;
    sm_response_t sm_res;
    dm_response_t dm_res;
    bool ret;
     
    if (strstr(payload, "cmd") != NULL) {
        if (strstr(payload, "trigger_neighbour_scan") != NULL) {
            ret = sm_conn_send_topic_stats(payload, payloadlen, &sm_res, topic);
        } else {
            //ret = dm_conn_send_topic_stats(payload, payloadlen, &dm_res, topic);
            ret = qm_send_msg_to_dm(payload, payloadlen, topic);
        }
    } else {
        ret = cm_conn_send_topic_stats(payload, payloadlen, &cm_res, topic);
    }
    return ret;
}

void qm_mqtt_subscriber_set(void *__self, void *me_data, char *topic, char *payload, long payloadlen)
{
    LOG(INFO, "QM: FROM-CLOUD TOPIC: %s\n MSG: %s\n", topic, payload); 
    qm_handle_msgrx(payload, payloadlen, topic);
    
    return;
}
