// File: src/managers/sm/src/sm_unixcomm_client.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ev.h>
#include <jansson.h>

#include "log.h"
#include "sm.h"
#include "unixcomm.h"

// Global variables
static unixcomm_handle_t sm_client_handle;
static bool client_connected = false;

// Initialize SM client using unixcomm
bool sm_unixcomm_client_init() {
    unixcomm_config_t config;
    
    // Initialize unixcomm library
    if (!unixcomm_init(NULL)) {
        LOG(ERR, "SM: Failed to initialize unixcomm");
        return false;
    }
    
    // Configure client
    if (!unixcomm_config_init(&config)) {
        LOG(ERR, "SM: Failed to initialize config");
        return false;
    }
    
    // Set socket path to connect to QM server
    unixcomm_config_set_socket_path(&config, "/tmp/aircnms/qm.sock");
    unixcomm_config_set_target_process(&config, UNIXCOMM_PROCESS_QM);
    unixcomm_config_set_timeout(&config, 5.0);
    
    // Create client
    if (!unixcomm_client_create(&sm_client_handle, &config)) {
        LOG(ERR, "SM: Failed to create unixcomm client");
        return false;
    }
    
    // Connect to QM server
    if (!unixcomm_connect(&sm_client_handle)) {
        LOG(ERR, "SM: Failed to connect to QM server");
        return false;
    }
    
    client_connected = true;
    LOG(INFO, "SM: Connected to QM server successfully");
    return true;
}

bool sm_send_stats_to_qm(const char *topic, void *stats_data, int data_size) {
    if (!client_connected) {
        LOG(ERR, "SM: Not connected to QM server");
        return false;
    }

    // Validate input
    if (!stats_data || data_size <= 0 || data_size > UNIXCOMM_MAX_DATA_SIZE) {
        LOG(ERR, "SM: Invalid stats data or size (%d)", data_size);
        return false;
    }

    // Create message
    unixcomm_message_t *message = unixcomm_message_create(stats_data, data_size);
    if (!message) {
        LOG(ERR, "SM: Failed to create message");
        return false;
    }

    // Set topic if provided
    if (topic && strlen(topic) > 0 && strlen(topic) < UNIXCOMM_MAX_TOPIC_LEN) {
        message->topic = strdup(topic);
        if (!message->topic) {
            LOG(ERR, "SM: Failed to allocate topic");
            unixcomm_message_destroy(message);
            return false;
        }
        message->request.topic_len = strlen(topic);
    } else {
        message->topic = NULL;
        message->request.topic_len = 0;
    }

    // Set header data_size
    message->data_size = data_size;
    message->request.data_size = data_size;

    // Set message type
    unixcomm_message_set_type(message, UNIXCOMM_MSG_NOTIFICATION);

    // Send message
    bool success = unixcomm_send_message(&sm_client_handle, message, NULL);
    if (success) {
        LOG(INFO, "SM: Successfully sent %d bytes to QM, topic: %s", data_size, topic ? topic : "[none]");
    } else {
        LOG(ERR, "SM: Failed to send message to QM");
    }

    // Cleanup
    //if (message->topic) {
      //  free(message->topic); // Explicitly free topic since unixcomm_message_destroy doesn't
    //}
    unixcomm_message_destroy(message);
    return success;
}

// Cleanup function
void sm_unixcomm_client_cleanup() {
    if (client_connected) {
        unixcomm_disconnect(&sm_client_handle);
        unixcomm_close(&sm_client_handle);
        unixcomm_cleanup();
        client_connected = false;
        LOG(INFO, "SM: UnixComm client cleaned up");
    }
}
