/*
 * SM Migration Example
 * Demonstrates how to migrate from SM-specific socket code to UnixComm library
 */

#include "unixcomm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// OLD SM Code (for comparison)
/*
bool sm_conn_send_direct(qm_compress_t compress, char *topic,
        void *data, int data_size, sm_response_t *res) {
    return sm_conn_send_custom(
            SM_DATA_RAW, compress,
            SM_REQ_FLAG_SEND_DIRECT,
            topic, data, data_size, res);
}
*/

// NEW SM Code using UnixComm
bool sm_send_direct(unixcomm_handle_t *client, const char *topic, 
                   const void *data, size_t data_size, unixcomm_response_t *response) {
    if (!unixcomm_is_connected(client)) {
        fprintf(stderr, "SM client not connected\n");
        return false;
    }

    return unixcomm_send_direct(client, topic, data, data_size, response);
}

// OLD SM Code (for comparison)
/*
bool sm_conn_send_topic_stats(char *payload, long payloadlen, sm_response_t *res, char *topic) {
    sm_request_t req;
    sm_req_init(&req);
    req.cmd = SM_CMD_SEND;
    req.data_type = SM_DATA_STATS;
    req.compress = SM_REQ_COMPRESS_IF_CFG;
    return sm_conn_send_req(&req, topic, payload, payloadlen, res);
}
*/

// NEW SM Code using UnixComm
bool sm_send_topic_stats(unixcomm_handle_t *client, const char *topic, 
                        const void *payload, size_t payloadlen, unixcomm_response_t *response) {
    if (!unixcomm_is_connected(client)) {
        fprintf(stderr, "SM client not connected\n");
        return false;
    }

    // Create request for stats
    unixcomm_request_t request;
    unixcomm_request_init(&request, "sm");
    request.command = 1; // SEND command
    request.data_type = UNIXCOMM_DATA_STATS;
    request.data_size = payloadlen;
    request.compress = 0; // No compression for now

    return unixcomm_send_request(client, &request, topic, payload, payloadlen, response);
}

// OLD SM Code (for comparison)
/*
bool sm_conn_send_stats(void *data, int data_size, sm_response_t *res) {
    sm_request_t req;
    sm_req_init(&req);
    req.cmd = SM_CMD_SEND;
    req.data_type = SM_DATA_STATS;
    req.compress = SM_REQ_COMPRESS_IF_CFG;
    return sm_conn_send_req(&req, NULL, data, data_size, res);
}
*/

// NEW SM Code using UnixComm
bool sm_send_stats(unixcomm_handle_t *client, const void *data, size_t data_size, 
                  unixcomm_response_t *response) {
    if (!unixcomm_is_connected(client)) {
        fprintf(stderr, "SM client not connected\n");
        return false;
    }

    return unixcomm_send_raw(client, "stats", data, data_size, response);
}

// OLD SM Code (for comparison)
/*
bool sm_conn_send_log(char *msg, sm_response_t *res) {
    sm_conn_t *sc = &sm_conn_log_handle;
    if (!sc->init) {
        sm_conn_open(sc);
    }
    sm_request_t req;
    sm_req_init(&req);
    req.cmd = SM_CMD_SEND;
    req.data_type = SM_DATA_LOG;
    req.compress = SM_REQ_COMPRESS_DISABLE;
    req.flags = SM_REQ_FLAG_NO_RESPONSE;
    return sm_conn_send_stream(sc, &req, NULL, msg, strlen(msg), res);
}
*/

// NEW SM Code using UnixComm
bool sm_send_log(unixcomm_handle_t *client, const char *message, unixcomm_response_t *response) {
    if (!unixcomm_is_connected(client)) {
        fprintf(stderr, "SM client not connected\n");
        return false;
    }

    return unixcomm_send_raw(client, "log", message, strlen(message), response);
}

// SM-specific functions
bool sm_send_device_stats(unixcomm_handle_t *client, const void *device_data, size_t data_size, 
                         unixcomm_response_t *response) {
    return sm_send_topic_stats(client, "device", device_data, data_size, response);
}

bool sm_send_client_stats(unixcomm_handle_t *client, const void *client_data, size_t data_size, 
                         unixcomm_response_t *response) {
    return sm_send_topic_stats(client, "client", client_data, data_size, response);
}

bool sm_send_vif_stats(unixcomm_handle_t *client, const void *vif_data, size_t data_size, 
                      unixcomm_response_t *response) {
    return sm_send_topic_stats(client, "vif", vif_data, data_size, response);
}

bool sm_send_neighbor_stats(unixcomm_handle_t *client, const void *neighbor_data, size_t data_size, 
                           unixcomm_response_t *response) {
    return sm_send_topic_stats(client, "neighbor", neighbor_data, data_size, response);
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

    // Create SM client
    unixcomm_config_t config;
    unixcomm_config_init(&config);
    unixcomm_config_set_socket_path(&config, "/tmp/aircnms/sm.sock");
    unixcomm_config_set_timeout(&config, 2.0);

    unixcomm_handle_t sm_client;
    if (!unixcomm_client_create(&sm_client, &config)) {
        fprintf(stderr, "Failed to create SM client\n");
        unixcomm_cleanup();
        return -1;
    }

    if (!unixcomm_connect(&sm_client)) {
        fprintf(stderr, "Failed to connect SM client\n");
        unixcomm_close(&sm_client);
        unixcomm_cleanup();
        return -1;
    }

    printf("SM client connected to server\n");

    // Send device stats
    const char *device_stats = "{\"cpu\": 45, \"memory\": 60, \"uptime\": 3600}";
    unixcomm_response_t response;
    if (sm_send_device_stats(&sm_client, device_stats, strlen(device_stats), &response)) {
        printf("Device stats sent successfully\n");
    } else {
        fprintf(stderr, "Failed to send device stats: %s\n", unixcomm_error_string(response.error));
    }

    // Send client stats
    const char *client_stats = "{\"clients\": [{\"mac\": \"00:11:22:33:44:55\", \"rssi\": -65}]}";
    if (sm_send_client_stats(&sm_client, client_stats, strlen(client_stats), &response)) {
        printf("Client stats sent successfully\n");
    } else {
        fprintf(stderr, "Failed to send client stats: %s\n", unixcomm_error_string(response.error));
    }

    // Send VIF stats
    const char *vif_stats = "{\"interfaces\": [{\"name\": \"wlan0\", \"tx_packets\": 1000, \"rx_packets\": 2000}]}";
    if (sm_send_vif_stats(&sm_client, vif_stats, strlen(vif_stats), &response)) {
        printf("VIF stats sent successfully\n");
    } else {
        fprintf(stderr, "Failed to send VIF stats: %s\n", unixcomm_error_string(response.error));
    }

    // Send neighbor stats
    const char *neighbor_stats = "{\"neighbors\": [{\"mac\": \"aa:bb:cc:dd:ee:ff\", \"signal\": -70}]}";
    if (sm_send_neighbor_stats(&sm_client, neighbor_stats, strlen(neighbor_stats), &response)) {
        printf("Neighbor stats sent successfully\n");
    } else {
        fprintf(stderr, "Failed to send neighbor stats: %s\n", unixcomm_error_string(response.error));
    }

    // Send log message
    const char *log_message = "SM client log message";
    if (sm_send_log(&sm_client, log_message, &response)) {
        printf("Log sent successfully\n");
    } else {
        fprintf(stderr, "Failed to send log: %s\n", unixcomm_error_string(response.error));
    }

    // Send direct message
    const char *direct_data = "Direct message from SM";
    if (sm_send_direct(&sm_client, "direct", direct_data, strlen(direct_data), &response)) {
        printf("Direct message sent successfully\n");
    } else {
        fprintf(stderr, "Failed to send direct message: %s\n", unixcomm_error_string(response.error));
    }

    // Cleanup
    unixcomm_close(&sm_client);
    unixcomm_cleanup();

    printf("SM migration example completed\n");
    return 0;
}
