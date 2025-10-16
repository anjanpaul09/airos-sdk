/*
 * Process-Specific UnixComm Usage Example
 * Demonstrates how to use UnixComm with process-specific socket paths
 */

#include "unixcomm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Example: QM process creating server for SM communication
bool qm_create_server_for_sm(unixcomm_handle_t *server) {
    unixcomm_config_t config;
    unixcomm_config_init(&config);
    
    // Set target process to SM - this auto-generates /tmp/aircnms/sm.sock
    unixcomm_config_set_target_process(&config, UNIXCOMM_PROCESS_SM);
    unixcomm_config_set_timeout(&config, 2.0);
    unixcomm_config_set_max_pending(&config, 10);
    
    if (!unixcomm_config_validate(&config)) {
        fprintf(stderr, "Invalid QM server configuration\n");
        return false;
    }
    
    return unixcomm_server_create(server, &config);
}

// Example: SM process creating client to communicate with QM
bool sm_create_client_for_qm(unixcomm_handle_t *client) {
    unixcomm_config_t config;
    unixcomm_config_init(&config);
    
    // Set target process to QM - this auto-generates /tmp/aircnms/qm.sock
    unixcomm_config_set_target_process(&config, UNIXCOMM_PROCESS_QM);
    unixcomm_config_set_timeout(&config, 2.0);
    
    if (!unixcomm_config_validate(&config)) {
        fprintf(stderr, "Invalid SM client configuration\n");
        return false;
    }
    
    if (!unixcomm_client_create(client, &config)) {
        fprintf(stderr, "Failed to create SM client\n");
        return false;
    }
    
    return unixcomm_connect(client);
}

// Example: DM process creating client to communicate with QM
bool dm_create_client_for_qm(unixcomm_handle_t *client) {
    unixcomm_config_t config;
    unixcomm_config_init(&config);
    
    // Set target process to QM - this auto-generates /tmp/aircnms/qm.sock
    unixcomm_config_set_target_process(&config, UNIXCOMM_PROCESS_QM);
    unixcomm_config_set_timeout(&config, 2.0);
    
    if (!unixcomm_config_validate(&config)) {
        fprintf(stderr, "Invalid DM client configuration\n");
        return false;
    }
    
    if (!unixcomm_client_create(client, &config)) {
        fprintf(stderr, "Failed to create DM client\n");
        return false;
    }
    
    return unixcomm_connect(client);
}

// Example: CM process creating client to communicate with QM
bool cm_create_client_for_qm(unixcomm_handle_t *client) {
    unixcomm_config_t config;
    unixcomm_config_init(&config);
    
    // Set target process to QM - this auto-generates /tmp/aircnms/qm.sock
    unixcomm_config_set_target_process(&config, UNIXCOMM_PROCESS_QM);
    unixcomm_config_set_timeout(&config, 2.0);
    
    if (!unixcomm_config_validate(&config)) {
        fprintf(stderr, "Invalid CM client configuration\n");
        return false;
    }
    
    if (!unixcomm_client_create(client, &config)) {
        fprintf(stderr, "Failed to create CM client\n");
        return false;
    }
    
    return unixcomm_connect(client);
}

// Example: QM process creating client to communicate with DM
bool qm_create_client_for_dm(unixcomm_handle_t *client) {
    unixcomm_config_t config;
    unixcomm_config_init(&config);
    
    // Set target process to DM - this auto-generates /tmp/aircnms/dm.sock
    unixcomm_config_set_target_process(&config, UNIXCOMM_PROCESS_DM);
    unixcomm_config_set_timeout(&config, 2.0);
    
    if (!unixcomm_config_validate(&config)) {
        fprintf(stderr, "Invalid QM client configuration\n");
        return false;
    }
    
    if (!unixcomm_client_create(client, &config)) {
        fprintf(stderr, "Failed to create QM client\n");
        return false;
    }
    
    return unixcomm_connect(client);
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

    printf("=== Process-Specific UnixComm Usage Example ===\n\n");

    // Example 1: QM creating server for SM
    printf("1. QM creating server for SM communication:\n");
    unixcomm_handle_t qm_server;
    if (qm_create_server_for_sm(&qm_server)) {
        printf("   ✓ QM server created for SM: /tmp/aircnms/sm.sock\n");
    } else {
        fprintf(stderr, "   ✗ Failed to create QM server for SM\n");
    }

    // Example 2: SM creating client to communicate with QM
    printf("\n2. SM creating client to communicate with QM:\n");
    unixcomm_handle_t sm_client;
    if (sm_create_client_for_qm(&sm_client)) {
        printf("   ✓ SM client connected to QM: /tmp/aircnms/qm.sock\n");
        
        // Send data from SM to QM
        const char *sm_data = "SM statistics data";
        unixcomm_response_t response;
        if (unixcomm_send_data(&sm_client, sm_data, strlen(sm_data), &response)) {
            printf("   ✓ SM data sent to QM successfully\n");
        } else {
            fprintf(stderr, "   ✗ Failed to send SM data to QM\n");
        }
        
        unixcomm_close(&sm_client);
    } else {
        fprintf(stderr, "   ✗ Failed to create SM client for QM\n");
    }

    // Example 3: DM creating client to communicate with QM
    printf("\n3. DM creating client to communicate with QM:\n");
    unixcomm_handle_t dm_client;
    if (dm_create_client_for_qm(&dm_client)) {
        printf("   ✓ DM client connected to QM: /tmp/aircnms/qm.sock\n");
        
        // Send data from DM to QM
        const char *dm_data = "DM device data";
        unixcomm_response_t response;
        if (unixcomm_send_data(&dm_client, dm_data, strlen(dm_data), &response)) {
            printf("   ✓ DM data sent to QM successfully\n");
        } else {
            fprintf(stderr, "   ✗ Failed to send DM data to QM\n");
        }
        
        unixcomm_close(&dm_client);
    } else {
        fprintf(stderr, "   ✗ Failed to create DM client for QM\n");
    }

    // Example 4: CM creating client to communicate with QM
    printf("\n4. CM creating client to communicate with QM:\n");
    unixcomm_handle_t cm_client;
    if (cm_create_client_for_qm(&cm_client)) {
        printf("   ✓ CM client connected to QM: /tmp/aircnms/qm.sock\n");
        
        // Send data from CM to QM
        const char *cm_data = "CM configuration data";
        unixcomm_response_t response;
        if (unixcomm_send_data(&cm_client, cm_data, strlen(cm_data), &response)) {
            printf("   ✓ CM data sent to QM successfully\n");
        } else {
            fprintf(stderr, "   ✗ Failed to send CM data to QM\n");
        }
        
        unixcomm_close(&cm_client);
    } else {
        fprintf(stderr, "   ✗ Failed to create CM client for QM\n");
    }

    // Example 5: QM creating client to communicate with DM
    printf("\n5. QM creating client to communicate with DM:\n");
    unixcomm_handle_t qm_client;
    if (qm_create_client_for_dm(&qm_client)) {
        printf("   ✓ QM client connected to DM: /tmp/aircnms/dm.sock\n");
        
        // Send data from QM to DM
        const char *qm_data = "QM queue data";
        unixcomm_response_t response;
        if (unixcomm_send_data(&qm_client, qm_data, strlen(qm_data), &response)) {
            printf("   ✓ QM data sent to DM successfully\n");
        } else {
            fprintf(stderr, "   ✗ Failed to send QM data to DM\n");
        }
        
        unixcomm_close(&qm_client);
    } else {
        fprintf(stderr, "   ✗ Failed to create QM client for DM\n");
    }

    // Cleanup
    unixcomm_close(&qm_server);
    unixcomm_cleanup();

    printf("\n=== Process-Specific Usage Example Completed ===\n");
    return 0;
}
