/*
 * CM Migration Example
 * Demonstrates how to migrate from CM-specific socket code to UnixComm library
 */

#include "unixcomm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// OLD CM Code (for comparison)
/*
bool cm_conn_send_topic_stats(char *payload, long payloadlen, cm_response_t *res, char *topic) {
    cm_request_t req;
    cm_req_init(&req);
    req.cmd = CM_CMD_SEND;
    req.data_type = CM_DATA_STATS;
    req.compress = CM_REQ_COMPRESS_IF_CFG;
    return cm_conn_send_req(&req, topic, payload, payloadlen, res);
}
*/

// NEW CM Code using UnixComm
bool cm_send_topic_stats(unixcomm_handle_t *client, const char *topic, 
                        const void *payload, size_t payloadlen, unixcomm_response_t *response) {
    if (!unixcomm_is_connected(client)) {
        fprintf(stderr, "CM client not connected\n");
        return false;
    }

    // Create request for stats
    unixcomm_request_t request;
    unixcomm_request_init(&request, "cm");
    request.command = 1; // SEND command
    request.data_type = UNIXCOMM_DATA_STATS;
    request.data_size = payloadlen;
    request.compress = 0; // No compression for now

    return unixcomm_send_request(client, &request, topic, payload, payloadlen, response);
}

// OLD CM Code (for comparison)
/*
bool cm_conn_send_stats(void *data, int data_size, cm_response_t *res) {
    cm_request_t req;
    cm_req_init(&req);
    req.cmd = CM_CMD_SEND;
    req.data_type = CM_DATA_STATS;
    req.compress = CM_REQ_COMPRESS_IF_CFG;
    return cm_conn_send_req(&req, NULL, data, data_size, res);
}
*/

// NEW CM Code using UnixComm
bool cm_send_stats(unixcomm_handle_t *client, const void *data, size_t data_size, 
                  unixcomm_response_t *response) {
    if (!unixcomm_is_connected(client)) {
        fprintf(stderr, "CM client not connected\n");
        return false;
    }

    return unixcomm_send_raw(client, "stats", data, data_size, response);
}

// OLD CM Code (for comparison)
/*
bool cm_conn_send_log(char *msg, cm_response_t *res) {
    cm_conn_t *cc = &cm_conn_log_handle;
    if (!cc->init) {
        cm_conn_open(cc);
    }
    cm_request_t req;
    cm_req_init(&req);
    req.cmd = CM_CMD_SEND;
    req.data_type = CM_DATA_LOG;
    req.compress = CM_REQ_COMPRESS_DISABLE;
    req.flags = CM_REQ_FLAG_NO_RESPONSE;
    return cm_conn_send_stream(cc, &req, NULL, msg, strlen(msg), res);
}
*/

// NEW CM Code using UnixComm
bool cm_send_log(unixcomm_handle_t *client, const char *message, unixcomm_response_t *response) {
    if (!unixcomm_is_connected(client)) {
        fprintf(stderr, "CM client not connected\n");
        return false;
    }

    return unixcomm_send_raw(client, "log", message, strlen(message), response);
}

// CM-specific functions
bool cm_send_network_config(unixcomm_handle_t *client, const void *network_config, size_t data_size, 
                           unixcomm_response_t *response) {
    return cm_send_topic_stats(client, "network", network_config, data_size, response);
}

bool cm_send_wireless_config(unixcomm_handle_t *client, const void *wireless_config, size_t data_size, 
                            unixcomm_response_t *response) {
    return cm_send_topic_stats(client, "wireless", wireless_config, data_size, response);
}

bool cm_send_acl_config(unixcomm_handle_t *client, const void *acl_config, size_t data_size, 
                       unixcomm_response_t *response) {
    return cm_send_topic_stats(client, "acl", acl_config, data_size, response);
}

bool cm_send_rate_limit_config(unixcomm_handle_t *client, const void *rate_limit_config, size_t data_size, 
                              unixcomm_response_t *response) {
    return cm_send_topic_stats(client, "rate_limit", rate_limit_config, data_size, response);
}

bool cm_send_vlan_config(unixcomm_handle_t *client, const void *vlan_config, size_t data_size, 
                        unixcomm_response_t *response) {
    return cm_send_topic_stats(client, "vlan", vlan_config, data_size, response);
}

bool cm_send_nat_config(unixcomm_handle_t *client, const void *nat_config, size_t data_size, 
                       unixcomm_response_t *response) {
    return cm_send_topic_stats(client, "nat", nat_config, data_size, response);
}

bool cm_send_qos_config(unixcomm_handle_t *client, const void *qos_config, size_t data_size, 
                       unixcomm_response_t *response) {
    return cm_send_topic_stats(client, "qos", qos_config, data_size, response);
}

bool cm_send_security_config(unixcomm_handle_t *client, const void *security_config, size_t data_size, 
                            unixcomm_response_t *response) {
    return cm_send_topic_stats(client, "security", security_config, data_size, response);
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

    // Create CM client
    unixcomm_config_t config;
    unixcomm_config_init(&config);
    unixcomm_config_set_socket_path(&config, "/tmp/aircnms/cm.sock");
    unixcomm_config_set_timeout(&config, 2.0);

    unixcomm_handle_t cm_client;
    if (!unixcomm_client_create(&cm_client, &config)) {
        fprintf(stderr, "Failed to create CM client\n");
        unixcomm_cleanup();
        return -1;
    }

    if (!unixcomm_connect(&cm_client)) {
        fprintf(stderr, "Failed to connect CM client\n");
        unixcomm_close(&cm_client);
        unixcomm_cleanup();
        return -1;
    }

    printf("CM client connected to server\n");

    // Send network config
    const char *network_config = "{\"ip\": \"192.168.1.1\", \"netmask\": \"255.255.255.0\", \"gateway\": \"192.168.1.1\"}";
    unixcomm_response_t response;
    if (cm_send_network_config(&cm_client, network_config, strlen(network_config), &response)) {
        printf("Network config sent successfully\n");
    } else {
        fprintf(stderr, "Failed to send network config: %s\n", unixcomm_error_string(response.error));
    }

    // Send wireless config
    const char *wireless_config = "{\"ssid\": \"AirCNMS\", \"channel\": 6, \"mode\": \"802.11n\", \"security\": \"WPA2\"}";
    if (cm_send_wireless_config(&cm_client, wireless_config, strlen(wireless_config), &response)) {
        printf("Wireless config sent successfully\n");
    } else {
        fprintf(stderr, "Failed to send wireless config: %s\n", unixcomm_error_string(response.error));
    }

    // Send ACL config
    const char *acl_config = "{\"rules\": [{\"mac\": \"00:11:22:33:44:55\", \"action\": \"allow\"}, {\"mac\": \"aa:bb:cc:dd:ee:ff\", \"action\": \"deny\"}]}";
    if (cm_send_acl_config(&cm_client, acl_config, strlen(acl_config), &response)) {
        printf("ACL config sent successfully\n");
    } else {
        fprintf(stderr, "Failed to send ACL config: %s\n", unixcomm_error_string(response.error));
    }

    // Send rate limit config
    const char *rate_limit_config = "{\"limits\": [{\"mac\": \"00:11:22:33:44:55\", \"tx_rate\": 1000, \"rx_rate\": 1000}]}";
    if (cm_send_rate_limit_config(&cm_client, rate_limit_config, strlen(rate_limit_config), &response)) {
        printf("Rate limit config sent successfully\n");
    } else {
        fprintf(stderr, "Failed to send rate limit config: %s\n", unixcomm_error_string(response.error));
    }

    // Send VLAN config
    const char *vlan_config = "{\"vlans\": [{\"id\": 100, \"name\": \"guest\", \"ports\": [1, 2, 3]}]}";
    if (cm_send_vlan_config(&cm_client, vlan_config, strlen(vlan_config), &response)) {
        printf("VLAN config sent successfully\n");
    } else {
        fprintf(stderr, "Failed to send VLAN config: %s\n", unixcomm_error_string(response.error));
    }

    // Send NAT config
    const char *nat_config = "{\"enabled\": true, \"masquerade\": true, \"rules\": [{\"src\": \"192.168.1.0/24\", \"dst\": \"0.0.0.0/0\"}]}";
    if (cm_send_nat_config(&cm_client, nat_config, strlen(nat_config), &response)) {
        printf("NAT config sent successfully\n");
    } else {
        fprintf(stderr, "Failed to send NAT config: %s\n", unixcomm_error_string(response.error));
    }

    // Send QoS config
    const char *qos_config = "{\"enabled\": true, \"queues\": [{\"name\": \"high\", \"priority\": 1, \"bandwidth\": 50}]}";
    if (cm_send_qos_config(&cm_client, qos_config, strlen(qos_config), &response)) {
        printf("QoS config sent successfully\n");
    } else {
        fprintf(stderr, "Failed to send QoS config: %s\n", unixcomm_error_string(response.error));
    }

    // Send security config
    const char *security_config = "{\"firewall\": {\"enabled\": true, \"rules\": [{\"action\": \"allow\", \"src\": \"192.168.1.0/24\"}]}}";
    if (cm_send_security_config(&cm_client, security_config, strlen(security_config), &response)) {
        printf("Security config sent successfully\n");
    } else {
        fprintf(stderr, "Failed to send security config: %s\n", unixcomm_error_string(response.error));
    }

    // Send log message
    const char *log_message = "CM client log message";
    if (cm_send_log(&cm_client, log_message, &response)) {
        printf("Log sent successfully\n");
    } else {
        fprintf(stderr, "Failed to send log: %s\n", unixcomm_error_string(response.error));
    }

    // Send stats
    const char *stats_data = "{\"config_changes\": 5, \"active_connections\": 10, \"last_update\": 1234567890}";
    if (cm_send_stats(&cm_client, stats_data, strlen(stats_data), &response)) {
        printf("Stats sent successfully\n");
    } else {
        fprintf(stderr, "Failed to send stats: %s\n", unixcomm_error_string(response.error));
    }

    // Cleanup
    unixcomm_close(&cm_client);
    unixcomm_cleanup();

    printf("CM migration example completed\n");
    return 0;
}
