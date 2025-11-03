#include "common.h"
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <netinet/in.h>
#include <ev.h>
#include "zlib.h"
#include "cgw.h"
#include "unixcomm.h"
#include "log.h"
#include "mosqev.h"

void cgw_restart_process()
{
    FILE *fp;
    char pid_str[16];
    char kill_cmd[32];

    // Get the PID of the process
    fp = popen("pidof cgw", "r");
    if (fp == NULL) {
        perror("Failed to run pidof command");
        return;
    }

    // Read the PID
    if (fgets(pid_str, sizeof(pid_str), fp) != NULL) {
        // Remove newline if present
        pid_str[strcspn(pid_str, "\n")] = '\0';
        
        // Prepare the kill command
        int ret = snprintf(kill_cmd, sizeof(kill_cmd), "kill -9 %s", pid_str);
        if (ret >= 0 && ret < (int)sizeof(kill_cmd)) {
            LOG(INFO, "Executing: %s", kill_cmd);
            int rc = system(kill_cmd);
            if (rc != 0) {
                LOG(ERR, "Kill command failed with exit code: %d", rc);
            }
        } else {
            LOG(ERR, "Kill command buffer overflow (ret=%d)", ret);
        }
    } else {
        LOG(INFO, "No process found for cgw");
    }

    pclose(fp);
    return;
}

int cgw_send_msg_to_dm(char *payload, long payloadlen, char *topic)
{
    struct blob_buf b = {};
    blob_buf_init(&b, 0);
    
    blobmsg_add_field(&b, BLOBMSG_TYPE_UNSPEC, "data", payload, payloadlen);
    blobmsg_add_u32(&b, "size", payloadlen);
    call_cmdexec_method("cmd", &b);
    blob_buf_free(&b);
    return 0;
}

bool cgw_send_msg_to_cm(char *payload, long payloadlen, char *topic)
{
    struct blob_buf b = {};
    blob_buf_init(&b, 0);
    
    blobmsg_add_field(&b, BLOBMSG_TYPE_UNSPEC, "data", payload, payloadlen);
    blobmsg_add_u32(&b, "size", payloadlen);

    if (strstr(topic, "config") != NULL) {
        call_netconfd_method("set.cgwd.conf", &b);
    } else if (strstr(topic, "bw_list") != NULL) {
        call_netconfd_method("set.cgwd.acl", &b);
    } else if (strstr(topic, "rate_limit") != NULL) {
        call_netconfd_method("set.cgwd.rl", &b);
    } else {
    }
    blob_buf_free(&b);
    return true;
}

int cgw_send_msg_to_sm(char *payload, long payloadlen, char *topic)
{
    struct blob_buf b = {};
    blob_buf_init(&b, 0);
    
    blobmsg_add_field(&b, BLOBMSG_TYPE_UNSPEC, "data", payload, payloadlen);
    blobmsg_add_u32(&b, "size", payloadlen);
    call_netstats_method("neighbor.trigger", &b);
    blob_buf_free(&b);
    return 0;
}

int cgw_handle_msgrx(char *payload, long payloadlen, char *topic)
{
    bool ret;
     
    if (strstr(payload, "cmd") != NULL) {
        if (strstr(payload, "trigger_neighbour_scan") != NULL) {
            ret = cgw_send_msg_to_sm(payload, payloadlen, topic);
        } else {
            ret = cgw_send_msg_to_dm(payload, payloadlen, topic);
        }
    } else {
        ret = cgw_send_msg_to_cm(payload, payloadlen, topic);
    }
    return ret;
}

void cgw_mqtt_subscriber_set(mosqev_t *self, void *data, const char *topic, void *msg, size_t msglen)
{
    (void)self;
    (void)data;
    
    char *payload = (char *)msg;
    long payloadlen = (long)msglen;
    
    if (!payload || msglen == 0) {
        LOG(ERR, "Invalid message data");
        return;
    }
    
    // Many syslog implementations truncate a single log line (~1KB).
    // Log header with total length, then chunk the payload over multiple lines to avoid truncation.
    LOG(INFO, "CGW: FROM-CLOUD TOPIC: %s msglen=%ld", topic, payloadlen);

    const size_t chunk_size = 900; // stay under typical syslog line limits
    size_t offset = 0;
    int chunk_idx = 0;
    while (offset < (size_t)payloadlen) {
        size_t remaining = (size_t)payloadlen - offset;
        size_t this_chunk = remaining < chunk_size ? remaining : chunk_size;
        LOG(INFO, "CGW: FROM-CLOUD PAYLOAD[%d]: %.*s", chunk_idx, (int)this_chunk, payload + offset);
        offset += this_chunk;
        chunk_idx++;
    }
    cgw_handle_msgrx(payload, payloadlen, (char *)topic);
}
