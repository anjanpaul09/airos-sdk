/*
 * DM Migration Example
 * Demonstrates how to migrate from DM-specific socket code to UnixComm library
 */

#include "unixcomm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// OLD DM Code (for comparison)
/*
bool dm_conn_send_topic_stats(char *payload, long payloadlen, dm_response_t *res, char *topic) {
    dm_request_t req;
    dm_req_init(&req);
    req.cmd = DM_CMD_SEND;
    req.data_type = DM_DATA_STATS;
    req.compress = DM_REQ_COMPRESS_IF_CFG;
    return dm_conn_send_req(&req, topic, payload, payloadlen, res);
}
*/

// NEW DM Code using UnixComm
bool dm_send_topic_stats(unixcomm_handle_t *client, const char *topic, 
                        const void *payload, size_t payloadlen, unixcomm_response_t *response) {
    if (!unixcomm_is_connected(client)) {
        fprintf(stderr, "DM client not connected\n");
        return false;
    }

    // Create request for stats
    unixcomm_request_t request;
    unixcomm_request_init(&request, "dm");
    request.command = 1; // SEND command
    request.data_type = UNIXCOMM_DATA_STATS;
    request.data_size = payloadlen;
    request.compress = 0; // No compression for now

    return unixcomm_send_request(client, &request, topic, payload, payloadlen, response);
}

// OLD DM Code (for comparison)
/*
bool dm_conn_send_stats(void *data, int data_size, dm_response_t *res) {
    dm_request_t req;
    dm_req_init(&req);
    req.cmd = DM_CMD_SEND;
    req.data_type = DM_DATA_STATS;
    req.compress = DM_REQ_COMPRESS_IF_CFG;
    return dm_conn_send_req(&req, NULL, data, data_size, res);
}
*/

// NEW DM Code using UnixComm
bool dm_send_stats(unixcomm_handle_t *client, const void *data, size_t data_size, 
                  unixcomm_response_t *response) {
    if (!unixcomm_is_connected(client)) {
        fprintf(stderr, "DM client not connected\n");
        return false;
    }

    return unixcomm_send_raw(client, "stats", data, data_size, response);
}

// OLD DM Code (for comparison)
/*
bool dm_conn_send_log(char *msg, dm_response_t *res) {
    dm_conn_t *dc = &dm_conn_log_handle;
    if (!dc->init) {
        dm_conn_open(dc);
    }
    dm_request_t req;
    dm_req_init(&req);
    req.cmd = DM_CMD_SEND;
    req.data_type = DM_DATA_LOG;
    req.compress = DM_REQ_COMPRESS_DISABLE;
    req.flags = DM_REQ_FLAG_NO_RESPONSE;
    return dm_conn_send_stream(dc, &req, NULL, msg, strlen(msg), res);
}
*/

// NEW DM Code using UnixComm
bool dm_send_log(unixcomm_handle_t *client, const char *message, unixcomm_response_t *response) {
    if (!unixcomm_is_connected(client)) {
        fprintf(stderr, "DM client not connected\n");
        return false;
    }

    return unixcomm_send_raw(client, "log", message, strlen(message), response);
}

// DM-specific functions
bool dm_send_device_info(unixcomm_handle_t *client, const void *device_info, size_t data_size, 
                        unixcomm_response_t *response) {
    return dm_send_topic_stats(client, "device", device_info, data_size, response);
}

bool dm_send_upgrade_status(unixcomm_handle_t *client, const void *upgrade_status, size_t data_size, 
                           unixcomm_response_t *response) {
    return dm_send_topic_stats(client, "upgrade", upgrade_status, data_size, response);
}

bool dm_send_alarm(unixcomm_handle_t *client, const void *alarm_data, size_t data_size, 
                  unixcomm_response_t *response) {
    if (!unixcomm_is_connected(client)) {
        fprintf(stderr, "DM client not connected\n");
        return false;
    }

    // Create request for alarm
    unixcomm_request_t request;
    unixcomm_request_init(&request, "dm");
    request.command = 1; // SEND command
    request.data_type = UNIXCOMM_DATA_ALARM;
    request.data_size = data_size;
    request.compress = 0; // No compression for now

    return unixcomm_send_request(client, &request, "alarm", alarm_data, data_size, response);
}

bool dm_send_event(unixcomm_handle_t *client, const void *event_data, size_t data_size, 
                  unixcomm_response_t *response) {
    if (!unixcomm_is_connected(client)) {
        fprintf(stderr, "DM client not connected\n");
        return false;
    }

    // Create request for event
    unixcomm_request_t request;
    unixcomm_request_init(&request, "dm");
    request.command = 1; // SEND command
    request.data_type = UNIXCOMM_DATA_EVENT;
    request.data_size = data_size;
    request.compress = 0; // No compression for now

    return unixcomm_send_request(client, &request, "event", event_data, data_size, response);
}

bool dm_send_config(unixcomm_handle_t *client, const void *config_data, size_t data_size, 
                   unixcomm_response_t *response) {
    if (!unixcomm_is_connected(client)) {
        fprintf(stderr, "DM client not connected\n");
        return false;
    }

    // Create request for config
    unixcomm_request_t request;
    unixcomm_request_init(&request, "dm");
    request.command = 1; // SEND command
    request.data_type = UNIXCOMM_DATA_CONFIG;
    request.data_size = data_size;
    request.compress = 0; // No compression for now

    return unixcomm_send_request(client, &request, "config", config_data, data_size, response);
}

// Example usage
int main() {
    // Initialize UnixComm library
    unixcomm_global_config_t global_config = {0};
    global_config.enable_debug = true;
    global_config.log_level = 1; // INFO level

    if (!unixcomm_init(&global_config)) {
        fprintf(stderr, "Failed to initialize UnixComm library\n");
        return -1;
    }

    // Create DM client
    unixcomm_config_t config;
    unixcomm_config_init(&config);
    unixcomm_config_set_socket_path(&config, "/tmp/aircnms/dm.sock");
    unixcomm_config_set_timeout(&config, 2.0);

    unixcomm_handle_t dm_client;
    if (!unixcomm_client_create(&dm_client, &config)) {
        fprintf(stderr, "Failed to create DM client\n");
        unixcomm_cleanup();
        return -1;
    }

    if (!unixcomm_connect(&dm_client)) {
        fprintf(stderr, "Failed to connect DM client\n");
        unixcomm_close(&dm_client);
        unixcomm_cleanup();
        return -1;
    }

    printf("DM client connected to server\n");

    // Send device info
    const char *device_info = "{\"device_id\": \"dm123\", \"version\": \"1.0.0\", \"status\": \"online\"}";
    unixcomm_response_t response;
    if (dm_send_device_info(&dm_client, device_info, strlen(device_info), &response)) {
        printf("Device info sent successfully\n");
    } else {
        fprintf(stderr, "Failed to send device info: %s\n", unixcomm_error_string(response.error));
    }

    // Send upgrade status
    const char *upgrade_status = "{\"upgrade_id\": \"up123\", \"status\": \"downloading\", \"progress\": 50}";
    if (dm_send_upgrade_status(&dm_client, upgrade_status, strlen(upgrade_status), &response)) {
        printf("Upgrade status sent successfully\n");
    } else {
        fprintf(stderr, "Failed to send upgrade status: %s\n", unixcomm_error_string(response.error));
    }

    // Send alarm
    const char *alarm_data = "{\"alarm_id\": \"alm123\", \"type\": \"high_cpu\", \"severity\": \"warning\"}";
    if (dm_send_alarm(&dm_client, alarm_data, strlen(alarm_data), &response)) {
        printf("Alarm sent successfully\n");
    } else {
        fprintf(stderr, "Failed to send alarm: %s\n", unixcomm_error_string(response.error));
    }

    // Send event
    const char *event_data = "{\"event_id\": \"evt123\", \"type\": \"device_restart\", \"timestamp\": 1234567890}";
    if (dm_send_event(&dm_client, event_data, strlen(event_data), &response)) {
        printf("Event sent successfully\n");
    } else {
        fprintf(stderr, "Failed to send event: %s\n", unixcomm_error_string(response.error));
    }

    // Send config
    const char *config_data = "{\"config_id\": \"cfg123\", \"type\": \"network\", \"settings\": {\"ip\": \"192.168.1.1\"}}";
    if (dm_send_config(&dm_client, config_data, strlen(config_data), &response)) {
        printf("Config sent successfully\n");
    } else {
        fprintf(stderr, "Failed to send config: %s\n", unixcomm_error_string(response.error));
    }

    // Send log message
    const char *log_message = "DM client log message";
    if (dm_send_log(&dm_client, log_message, &response)) {
        printf("Log sent successfully\n");
    } else {
        fprintf(stderr, "Failed to send log: %s\n", unixcomm_error_string(response.error));
    }

    // Send stats
    const char *stats_data = "{\"cpu_usage\": 75, \"memory_usage\": 80, \"disk_usage\": 60}";
    if (dm_send_stats(&dm_client, stats_data, strlen(stats_data), &response)) {
        printf("Stats sent successfully\n");
    } else {
        fprintf(stderr, "Failed to send stats: %s\n", unixcomm_error_string(response.error));
    }

    // Cleanup
    unixcomm_close(&dm_client);
    unixcomm_cleanup();

    printf("DM migration example completed\n");
    return 0;
}
