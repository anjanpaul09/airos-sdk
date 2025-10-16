#include "common.h"
#include <netinet/in.h>
#include "zlib.h"
#include "qm.h"
#include "unixcomm.h"

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
    unixcomm_message_t *message = unixcomm_message_create((void *) payload, payloadlen);
    if (!message) return false;
    message->request.data_size = payloadlen;
    message->topic = strdup("cmd");
    if (strstr(topic, "cmd") != NULL) {
        message->request.data_type = DATA_CMD;
    }
    message->request.topic_len = strlen(message->topic);
    unixcomm_message_set_type(message, UNIXCOMM_MSG_NOTIFICATION);
    printf("Ankit: mlen = %zu msg->data_size = %zu \n", payloadlen, message->data_size);
    bool ok = unixcomm_send_to_process(UNIXCOMM_PROCESS_DM, message, NULL);
    unixcomm_message_destroy(message);
    return ok;
}

int qm_send_msg_to_cm(char *payload, long payloadlen, char *topic)
{
    unixcomm_message_t *message = unixcomm_message_create((void *) payload, payloadlen);
    if (!message) return false;
    message->request.data_size = payloadlen;
    message->topic = strdup("config");
    if (strstr(topic, "config") != NULL) {
        message->request.data_type = DATA_CONF;
    } else if (strstr(topic, "cmd") != NULL) {
        message->request.data_type = DATA_CMD;
    } else if (strstr(topic, "bw_list") != NULL) {
        message->request.data_type = DATA_ACL;
    } else if (strstr(topic, "rate_limit") != NULL) {
        message->request.data_type = DATA_RL;
        } else {
        message->request.data_type = DATA_STATS;
    }
    message->request.topic_len = strlen(message->topic);
    unixcomm_message_set_type(message, UNIXCOMM_MSG_NOTIFICATION);
    printf("Ankit: mlen = %zu msg->data_size = %zu \n", payloadlen, message->data_size);
    bool ok = unixcomm_send_to_process(UNIXCOMM_PROCESS_CM, message, NULL);
    unixcomm_message_destroy(message);
    return ok;
}

int qm_send_msg_to_sm(char *payload, long payloadlen, char *topic)
{
    unixcomm_message_t *message = unixcomm_message_create((void *) payload, payloadlen);
    if (!message) return false;
    message->request.data_size = payloadlen;
    message->topic = strdup("cmd");
    message->request.topic_len = strlen(message->topic);
    unixcomm_message_set_type(message, UNIXCOMM_MSG_NOTIFICATION);
    printf("Ankit: mlen = %zu msg->data_size = %zu \n", payloadlen, message->data_size);
    bool ok = unixcomm_send_to_process(UNIXCOMM_PROCESS_SM, message, NULL);
    unixcomm_message_destroy(message);
    return ok;
}

int qm_handle_msgrx(char *payload, long payloadlen, char *topic)
{
    bool ret;
     
    if (strstr(payload, "cmd") != NULL) {
        if (strstr(payload, "trigger_neighbour_scan") != NULL) {
            ret = qm_send_msg_to_sm(payload, payloadlen, topic);
        } else {
            ret = qm_send_msg_to_dm(payload, payloadlen, topic);
        }
    } else {
        ret = qm_send_msg_to_cm(payload, payloadlen, topic);
    }
    return ret;
}

void qm_mqtt_subscriber_set(void *__self, void *me_data, char *topic, char *payload, long payloadlen)
{
    LOG(INFO, "QM: FROM-CLOUD TOPIC: %s\n MSG: %s\n", topic, payload); 
    qm_handle_msgrx(payload, payloadlen, topic);
    
    return;
}
