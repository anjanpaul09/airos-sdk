/*
 * QM Mock Server
 * Accepts messages from SM and logs them to /tmp/qm.mock.log
 * 
 * This mock replaces the real QM process for testing SM functionality
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <poll.h>
#include <stdbool.h>
#include <jansson.h>
#include <zlib.h>

// Include the same headers as the real QM
#include "log.h"
#include "os.h"
#include "os_time.h"
#include "util.h"
#include "memutil.h"
#include "qm_conn.h"
#include "report.h"
#include "device_config.h"

#define QM_MOCK_LOG_FILE "/tmp/qm.mock.log"
#define QM_MOCK_SOCK_DIR "/tmp/aircnms/"
#define QM_MOCK_SOCK_FILENAME QM_MOCK_SOCK_DIR"qm.sock"
#define QM_MOCK_MAX_PENDING 10
#define QM_MOCK_BUFFER_SIZE (128*1024)
#define MAX_JSON_OUTPUT_SIZE (64*1024)

// Device information (similar to air_dev in real QM)
typedef struct {
    char serial_num[64];
    char device_id[64];
    char macaddr[18];
} air_device_t;

static air_device_t air_dev = {
    .serial_num = "MOCK123456789",
    .device_id = "mock-device-001",
    .macaddr = "00:11:22:33:44:55"
};

// Global variables
static int server_fd = -1;
static bool running = true;
static FILE *log_file = NULL;

// Signal handler for graceful shutdown
void signal_handler(int sig) {
    printf("\nQM Mock: Received signal %d, shutting down...\n", sig);
    running = false;
}

// Initialize logging
bool init_logging() {
    log_file = fopen(QM_MOCK_LOG_FILE, "a");
    if (!log_file) {
        fprintf(stderr, "Failed to open log file %s: %s\n", QM_MOCK_LOG_FILE, strerror(errno));
        return false;
    }
    
    // Set line buffering for immediate output
    setlinebuf(log_file);
    
    fprintf(log_file, "=== QM Mock Server Started at %s ===\n", 
             ctime(&(time_t){time(NULL)}));
    fflush(log_file);
    
    return true;
}

// Forward declaration
bool qm_send_stats_json_mock(void *qi_ptr, char *json_output);

// Decompress & Deserialize sm_stats_t (exactly like real QM)
bool decompress_deserialize_sm_stats(const uint8_t *compressed_data, size_t compressed_size, sm_stats_t *stats)
{
    if (!compressed_data || !stats) return false;

    uLongf decompressed_size = sizeof(sm_stats_t);
    uint8_t decompressed_data[sizeof(sm_stats_t)];

    /* Decompress the data */
    if (uncompress(decompressed_data, &decompressed_size, compressed_data, compressed_size) != Z_OK) {
        fprintf(stderr, "Decompression failed\n");
        return false;
    }

    /* Deserialize: Convert byte array back to struct */
    memcpy(stats, decompressed_data, sizeof(sm_stats_t));

    return true;
}

// Parse device statistics and create JSON (based on real QM)
bool parse_device_stats_json(device_report_data_t *device, char *json_output) {
    if (!device || !json_output) return false;
    
    json_t *root = json_object();
    if (!root) return false;
    
    json_t *device_root = json_object();
    if (!device_root) {
        json_decref(root);
        return false;
    }
    
    // Add device metadata
    json_object_set_new(root, "serialNum", json_string(air_dev.serial_num));
    json_object_set_new(root, "deviceId", json_string(air_dev.device_id));
    json_object_set_new(root, "macAddr", json_string(air_dev.macaddr));
    json_object_set_new(root, "tms", json_integer(device->timestamp_ms));
    
    // System info from actual data
    json_t *system_obj = json_object();
    json_object_set_new(system_obj, "uptime", json_integer(device->record.uptime));
    json_object_set_new(system_obj, "downtime", json_integer(0));
    json_object_set_new(system_obj, "totalClient", json_integer(device->record.w_util.num_sta));
    json_object_set_new(system_obj, "uplinkMb", json_integer(device->record.w_util.uplink_mb));
    json_object_set_new(system_obj, "downlinkMb", json_integer(device->record.w_util.downlink_mb));
    json_object_set_new(system_obj, "totalTrafficMb", json_integer(device->record.w_util.total_traffic_mb));
    json_object_set_new(device_root, "system", system_obj);
    
    // Memory utilization from actual data
    json_t *memUtil_obj = json_object();
    json_object_set_new(memUtil_obj, "memTotal", json_integer(device->record.mem_util.mem_total));
    json_object_set_new(memUtil_obj, "memUsed", json_integer(device->record.mem_util.mem_used));
    json_object_set_new(memUtil_obj, "swapTotal", json_integer(device->record.mem_util.swap_total));
    json_object_set_new(memUtil_obj, "swapUsed", json_integer(device->record.mem_util.swap_used));
    json_object_set_new(device_root, "memUtil", memUtil_obj);
    
    // CPU utilization from actual data
    json_t *cpuutil_obj = json_object();
    json_object_set_new(cpuutil_obj, "cpuUtil", json_integer(device->record.cpu_util.cpu_util));
    json_object_set_new(device_root, "cpuUtil", cpuutil_obj);
    
    // Filesystem utilization
    json_t *fsUtil_arr = json_array();
    for (int i = 0; i < DEVICE_FS_TYPE_QTY; i++) {
        json_t *fsUtil_obj = json_object();
        const char *fs_type_str = "UNKNOWN";
        
        switch (device->record.fs_util[i].fs_type) {
            case DEVICE_FS_TYPE_ROOTFS:
                fs_type_str = "FS_TYPE_ROOTFS";
                break;
            case DEVICE_FS_TYPE_TMPFS:
                fs_type_str = "FS_TYPE_TMPFS";
                break;
            default:
                break;
        }
        
        json_object_set_new(fsUtil_obj, "fsType", json_string(fs_type_str));
        json_object_set_new(fsUtil_obj, "fsTotal", json_integer(device->record.fs_util[i].fs_total));
        json_object_set_new(fsUtil_obj, "fsUsed", json_integer(device->record.fs_util[i].fs_used));
        json_array_append_new(fsUtil_arr, fsUtil_obj);
    }
    json_object_set_new(device_root, "fsUtil", fsUtil_arr);
    
    json_object_set_new(root, "data", device_root);
    
    // Serialize to JSON string
    char *json_str = json_dumps(root, JSON_COMPACT);
    if (!json_str) {
        json_decref(root);
        return false;
    }
    
    strncpy(json_output, json_str, MAX_JSON_OUTPUT_SIZE - 1);
    json_output[MAX_JSON_OUTPUT_SIZE - 1] = '\0';
    
    free(json_str);
    json_decref(root);
    
    return true;
}

// Parse client statistics and create JSON (based on real QM)
bool parse_client_stats_json(client_report_data_t *client, char *json_output) {
    if (!client || !json_output) return false;
    
    json_t *root = json_object();
    if (!root) return false;
    
    json_t *client_arr = json_array();
    if (!client_arr) {
        json_decref(root);
        return false;
    }
    
    // Add device metadata
    json_object_set_new(root, "serialNum", json_string(air_dev.serial_num));
    json_object_set_new(root, "deviceId", json_string(air_dev.device_id));
    json_object_set_new(root, "macAddr", json_string(air_dev.macaddr));
    json_object_set_new(root, "tms", json_integer(client->timestamp_ms));
    
    // Parse actual client data
    for (int i = 0; i < client->n_client; i++) {
        json_t *client_obj = json_object();
        char mac_str[18];
        
        // Convert MAC address to string
        snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                client->record[i].macaddr[0], client->record[i].macaddr[1],
                client->record[i].macaddr[2], client->record[i].macaddr[3],
                client->record[i].macaddr[4], client->record[i].macaddr[5]);
        
        json_object_set_new(client_obj, "macAddress", json_string(mac_str));
        json_object_set_new(client_obj, "hostname", json_string(client->record[i].hostname));
        json_object_set_new(client_obj, "ipAddress", json_string(client->record[i].ipaddr));
        json_object_set_new(client_obj, "ssid", json_string(client->record[i].ssid));
        json_object_set_new(client_obj, "isConnected", json_integer(client->record[i].is_connected));
        json_object_set_new(client_obj, "durationMs", json_integer(client->record[i].duration_ms));
        json_object_set_new(client_obj, "channel", json_integer(client->record[i].channel));
        
        // Band string
        char band[8];
        if (client->record[i].radio_type == RADIO_TYPE_2G) {
            strcpy(band, "2.4GHz");
        } else if (client->record[i].radio_type == RADIO_TYPE_5G) {
            strcpy(band, "5GHz");
        } else {
            strcpy(band, "Unknown");
        }
        json_object_set_new(client_obj, "band", json_string(band));
        
        // Client stats
        json_t *stats_obj = json_object();
        json_object_set_new(stats_obj, "rxBytes", json_integer(client->record[i].rx_bytes));
        json_object_set_new(stats_obj, "txBytes", json_integer(client->record[i].tx_bytes));
        json_object_set_new(stats_obj, "rssi", json_integer(client->record[i].rssi));
        json_object_set_new(client_obj, "stats", stats_obj);
        
        json_array_append_new(client_arr, client_obj);
    }
    
    json_object_set_new(root, "data", client_arr);
    
    // Serialize to JSON string
    char *json_str = json_dumps(root, JSON_COMPACT);
    if (!json_str) {
        json_decref(root);
        return false;
    }
    
    strncpy(json_output, json_str, MAX_JSON_OUTPUT_SIZE - 1);
    json_output[MAX_JSON_OUTPUT_SIZE - 1] = '\0';
    
    free(json_str);
    json_decref(root);
    
    return true;
}

// Parse VIF statistics and create JSON (based on real QM)
bool parse_vif_stats_json(vif_report_data_t *vif, char *json_output) {
    if (!vif || !json_output) return false;
    
    json_t *root = json_object();
    if (!root) return false;
    
    json_t *data_obj = json_object();
    json_t *radio_array = json_array();
    json_t *vif_array = json_array();
    
    if (!data_obj || !radio_array || !vif_array) {
        json_decref(root);
        return false;
    }
    
    // Add device metadata
    json_object_set_new(root, "serialNum", json_string(air_dev.serial_num));
    json_object_set_new(root, "deviceId", json_string(air_dev.device_id));
    json_object_set_new(root, "macAddr", json_string(air_dev.macaddr));
    json_object_set_new(root, "tms", json_integer(vif->timestamp_ms));
    
    // Parse radio data
    for (int i = 0; i < vif->record.n_radio; i++) {
        json_t *radio = json_object();
        if (!radio) continue;
        
        json_object_set_new(radio, "band", json_string(vif->record.radio[i].band));
        json_object_set_new(radio, "channel", json_integer(vif->record.radio[i].channel));
        json_object_set_new(radio, "txpower", json_integer(vif->record.radio[i].txpower));
        json_object_set_new(radio, "channel_utilization", json_integer(vif->record.radio[i].channel_utilization));
        
        json_array_append_new(radio_array, radio);
    }
    
    // Parse VIF data
    for (int i = 0; i < vif->record.n_vif; i++) {
        json_t *vif_obj = json_object();
        if (!vif_obj) continue;
        
        json_object_set_new(vif_obj, "radio", json_string(vif->record.vif[i].radio));
        json_object_set_new(vif_obj, "ssid", json_string(vif->record.vif[i].ssid));
        json_object_set_new(vif_obj, "statNumSta", json_integer(vif->record.vif[i].num_sta));
        json_object_set_new(vif_obj, "statUplinkMb", json_integer(vif->record.vif[i].uplink_mb));
        json_object_set_new(vif_obj, "statDownlinkMb", json_integer(vif->record.vif[i].downlink_mb));
        
        json_array_append_new(vif_array, vif_obj);
    }
    
    // Store radio and vif data inside `data`
    json_object_set_new(data_obj, "radio", radio_array);
    json_object_set_new(data_obj, "vif", vif_array);
    json_object_set_new(root, "data", data_obj);
    
    // Serialize to JSON string
    char *json_str = json_dumps(root, JSON_COMPACT);
    if (!json_str) {
        json_decref(root);
        return false;
    }
    
    strncpy(json_output, json_str, MAX_JSON_OUTPUT_SIZE - 1);
    json_output[MAX_JSON_OUTPUT_SIZE - 1] = '\0';
    
    free(json_str);
    json_decref(root);
    
    return true;
}

// Parse neighbor statistics and create JSON (based on real QM)
bool parse_neighbor_stats_json(neighbor_report_data_t *rpt, char *json_output) {
    if (!rpt || !json_output) return false;
    
    json_t *root = json_object();
    if (!root) return false;
    
    json_t *neighbor_array = json_array();
    if (!neighbor_array) {
        json_decref(root);
        return false;
    }
    
    // Add device metadata
    json_object_set_new(root, "serialNum", json_string(air_dev.serial_num));
    json_object_set_new(root, "deviceId", json_string(air_dev.device_id));
    json_object_set_new(root, "macAddr", json_string(air_dev.macaddr));
    json_object_set_new(root, "tms", json_integer(rpt->timestamp_ms));
    
    for (int itr = 0; itr < rpt->n_entry; itr++) {
        json_t *neighbor = json_object();
        if (!neighbor) continue;
        
        char band[8];
        if (rpt->record[itr].radio_type == RADIO_TYPE_2G) {
            strcpy(band, "2.4GHz");
        } else if (rpt->record[itr].radio_type == RADIO_TYPE_5G) {
            strcpy(band, "5GHz");
        } else {
            strcpy(band, "Unknown");
        }
        
        json_object_set_new(neighbor, "bssid", json_string(rpt->record[itr].bssid));
        json_object_set_new(neighbor, "ssid", json_string(rpt->record[itr].ssid));
        json_object_set_new(neighbor, "rssi", json_integer(rpt->record[itr].rssi));
        json_object_set_new(neighbor, "tsf", json_integer(rpt->record[itr].tsf));
        json_object_set_new(neighbor, "channel", json_integer(rpt->record[itr].channel));
        json_object_set_new(neighbor, "channelWidth", json_integer(rpt->record[itr].chan_width));
        json_object_set_new(neighbor, "band", json_string(band));
        
        json_array_append_new(neighbor_array, neighbor);
    }
    
    json_object_set_new(root, "data", neighbor_array);
    
    // Serialize to JSON string
    char *json_str = json_dumps(root, JSON_COMPACT);
    if (!json_str) {
        json_decref(root);
        return false;
    }
    
    strncpy(json_output, json_str, MAX_JSON_OUTPUT_SIZE - 1);
    json_output[MAX_JSON_OUTPUT_SIZE - 1] = '\0';
    
    free(json_str);
    json_decref(root);
    
    return true;
}

// Parse log message and create JSON (based on real QM)
bool parse_log_message_json(const void *data, size_t data_size, char *json_output) {
    if (!data || !json_output) return false;
    
    json_t *root = json_object();
    if (!root) return false;
    
    json_t *log_obj = json_object();
    if (!log_obj) {
        json_decref(root);
        return false;
    }
    
    // Add log metadata
    json_object_set_new(log_obj, "level", json_string("info"));
    json_object_set_new(log_obj, "message", json_string((char*)data));
    json_object_set_new(log_obj, "component", json_string("sm"));
    json_object_set_new(log_obj, "timestamp", json_integer(time(NULL)));
    
    json_object_set_new(root, "data", log_obj);
    
    // Serialize to JSON string
    char *json_str = json_dumps(root, JSON_COMPACT);
    if (!json_str) {
        json_decref(root);
        return false;
    }
    
    strncpy(json_output, json_str, MAX_JSON_OUTPUT_SIZE - 1);
    json_output[MAX_JSON_OUTPUT_SIZE - 1] = '\0';
    
    free(json_str);
    json_decref(root);
    
    return true;
}

// Process received data exactly like real QM (qm_send_stats_json)
bool process_received_data(const void *data, size_t data_size, int data_type, char *json_output) {
    if (!data || !json_output) return false;
    
    // Debug: Print received data info
    printf("DEBUG: Received data - size: %zu, data_type: %d\n", data_size, data_type);
    
    // Create a qm_item_t structure like real QM does
    typedef struct {
        qm_request_t req;
        char *topic;
        size_t size;
        void *buf;
        time_t timestamp;
    } qm_item_t;
    
    qm_item_t qi;
    memset(&qi, 0, sizeof(qi));
    
    // Set up the qm_item_t like real QM does
    qi.buf = (void*)data;
    qi.size = data_size;
    qi.timestamp = time(NULL);
    
    // Process exactly like real QM's qm_send_stats_json()
    bool result = qm_send_stats_json_mock(&qi, json_output);
    
    if (!result) {
        // If processing fails, treat as raw data
        printf("DEBUG: Processing failed, treating as raw data\n");
        snprintf(json_output, MAX_JSON_OUTPUT_SIZE, 
                "{\"type\":\"raw_data\",\"size\":%zu,\"timestamp\":%ld,\"data\":\"%.*s\"}",
                data_size, time(NULL), (int)data_size, (char*)data);
        return true;
    }
    
    return result;
}

// Mock version of qm_send_stats_json (exactly like real QM)
bool qm_send_stats_json_mock(void *qi_ptr, char *json_output) {
    // Cast to qm_item_t structure
    typedef struct {
        qm_request_t req;
        char *topic;
        size_t size;
        void *buf;
        time_t timestamp;
    } qm_item_t;
    
    qm_item_t *qi = (qm_item_t*)qi_ptr;
    bool ret;
    sm_stats_t stats;
    
    // Zero initialize stats to prevent garbage values
    memset(&stats, 0, sizeof(sm_stats_t));
    
    printf("DEBUG: Processing qm_item_t - size: %zu\n", qi->size);
    
    // Decompress and deserialize exactly like real QM
    ret = decompress_deserialize_sm_stats((const uint8_t*)qi->buf, qi->size, &stats);
    
    if (!ret) {
        printf("DEBUG: Decompression failed\n");
        return false;
    }
    
    printf("DEBUG: Decompressed stats - type: %d, size: %d\n", stats.type, stats.size);
    
    // Process the received stats exactly like real QM
    switch(stats.type) {
        case SM_T_DEVICE: 
            printf("DEBUG: Processing device stats\n");
            ret = parse_device_stats_json(&stats.u.device, json_output);
            break;
        case SM_T_VIF: 
            printf("DEBUG: Processing VIF stats\n");
            ret = parse_vif_stats_json(&stats.u.vif, json_output);
            break;
        case SM_T_CLIENT: 
            printf("DEBUG: Processing client stats\n");
            ret = parse_client_stats_json(&stats.u.client, json_output);
            break;
        case SM_T_NEIGHBOR: 
            printf("DEBUG: Processing neighbor stats\n");
            ret = parse_neighbor_stats_json(&stats.u.neighbor, json_output);
            break;
        default:
            printf("DEBUG: Unknown stats type: %d\n", stats.type);
            ret = false;
            break;
    }
    
    return ret;
}

// Log message to file with JSON output
void log_message(const char *sender, const char *topic, const void *data, size_t data_size, 
                int cmd, int data_type, int flags) {
    if (!log_file) return;
    
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    fprintf(log_file, "[%s] SENDER: %s | CMD: %d | TYPE: %d | FLAGS: 0x%x | TOPIC: %s | SIZE: %zu\n",
            timestamp, sender, cmd, data_type, flags, topic ? topic : "NULL", data_size);
    
    if (data && data_size > 0) {
        // Process the data and create JSON output
        char json_output[MAX_JSON_OUTPUT_SIZE];
        if (process_received_data(data, data_size, data_type, json_output)) {
            fprintf(log_file, "JSON OUTPUT:\n%s\n", json_output);
        } else {
            fprintf(log_file, "DATA: ");
            // Log first 200 characters of raw data
            size_t log_size = (data_size > 200) ? 200 : data_size;
            for (size_t i = 0; i < log_size; i++) {
                unsigned char c = ((unsigned char*)data)[i];
                if (c >= 32 && c <= 126) {
                    fputc(c, log_file);
                } else {
                    fprintf(log_file, "\\x%02x", c);
                }
            }
            if (data_size > 200) {
                fprintf(log_file, "... (truncated)");
            }
            fprintf(log_file, "\n");
        }
    }
    
    fprintf(log_file, "---\n");
    fflush(log_file);
}

// Handle incoming request
bool handle_request(int client_fd) {
    qm_request_t req;
    char *topic = NULL;
    void *data = NULL;
    qm_response_t res;
    bool success = false;
    
    // Read request
    if (!qm_conn_read_req(client_fd, &req, &topic, &data)) {
        fprintf(stderr, "Failed to read request from client\n");
        goto cleanup;
    }
    
    // Validate request
    if (!qm_req_valid(&req)) {
        fprintf(stderr, "Invalid request received\n");
        goto cleanup;
    }
    
    // Log the message
    log_message(req.sender, topic, data, req.data_size, req.cmd, req.data_type, req.flags);
    
    // Prepare response
    qm_res_init(&res, &req);
    res.response = QM_RESPONSE_RECEIVED;
    res.error = QM_ERROR_NONE;
    
    // Send response
    if (!qm_conn_write_res(client_fd, &res)) {
        fprintf(stderr, "Failed to send response to client\n");
        goto cleanup;
    }
    
    success = true;
    printf("QM Mock: Processed message from %s (cmd=%d, type=%d, size=%d)\n",
           req.sender, req.cmd, req.data_type, req.data_size);

cleanup:
    FREE(topic);
    FREE(data);
    return success;
}

// Create server socket
bool create_server() {
    struct sockaddr_un addr;
    char *path = QM_MOCK_SOCK_FILENAME;
    
    // Create socket directory
    mkdir(QM_MOCK_SOCK_DIR, 0755);
    errno = 0; // ignore dir exist error
    
    // Remove existing socket file
    unlink(path);
    
    server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        fprintf(stderr, "Failed to create socket: %s\n", strerror(errno));
        return false;
    }
    
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    
    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Failed to bind socket: %s\n", strerror(errno));
        close(server_fd);
        server_fd = -1;
        return false;
    }
    
    if (listen(server_fd, QM_MOCK_MAX_PENDING) < 0) {
        fprintf(stderr, "Failed to listen on socket: %s\n", strerror(errno));
        close(server_fd);
        server_fd = -1;
        return false;
    }
    
    printf("QM Mock: Server listening on %s\n", path);
    return true;
}

// Main server loop
void server_loop() {
    struct pollfd pfd;
    int client_fd;
    int ret;
    
    pfd.fd = server_fd;
    pfd.events = POLLIN;
    
    printf("QM Mock: Server started, waiting for connections...\n");
    
    while (running) {
        ret = poll(&pfd, 1, 1000); // 1 second timeout
        
        if (ret < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "Poll error: %s\n", strerror(errno));
            break;
        }
        
        if (ret == 0) continue; // Timeout
        
        if (pfd.revents & POLLIN) {
            client_fd = accept(server_fd, NULL, NULL);
            if (client_fd < 0) {
                if (errno == EINTR) continue;
                fprintf(stderr, "Accept error: %s\n", strerror(errno));
                continue;
            }
            
            printf("QM Mock: Client connected\n");
            
            // Handle the request
            if (handle_request(client_fd)) {
                printf("QM Mock: Request processed successfully\n");
            } else {
                printf("QM Mock: Failed to process request\n");
            }
            
            close(client_fd);
        }
    }
}

// Cleanup function
void cleanup() {
    if (server_fd >= 0) {
        close(server_fd);
        server_fd = -1;
    }
    
    if (log_file) {
        fprintf(log_file, "=== QM Mock Server Stopped at %s ===\n", 
                 ctime(&(time_t){time(NULL)}));
        fclose(log_file);
        log_file = NULL;
    }
    
    // Remove socket file
    unlink(QM_MOCK_SOCK_FILENAME);
    
    printf("QM Mock: Cleanup completed\n");
}

// Print usage information
void print_usage(const char *prog_name) {
    printf("Usage: %s [options]\n", prog_name);
    printf("Options:\n");
    printf("  -h, --help     Show this help message\n");
    printf("  -v, --verbose  Enable verbose output\n");
    printf("  -l, --log      Log file path (default: %s)\n", QM_MOCK_LOG_FILE);
    printf("\n");
    printf("QM Mock Server - Accepts messages from SM and logs them\n");
    printf("Log file: %s\n", QM_MOCK_LOG_FILE);
    printf("Socket: %s\n", QM_MOCK_SOCK_FILENAME);
}

int main(int argc, char *argv[]) {
    bool verbose = false;
    const char *log_path = QM_MOCK_LOG_FILE;
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = true;
        } else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--log") == 0) {
            if (i + 1 < argc) {
                log_path = argv[++i];
            } else {
                fprintf(stderr, "Error: --log requires a file path\n");
                return 1;
            }
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }
    
    printf("QM Mock Server v1.0\n");
    printf("Log file: %s\n", log_path);
    printf("Socket: %s\n", QM_MOCK_SOCK_FILENAME);
    
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Initialize logging
    if (!init_logging()) {
        fprintf(stderr, "Failed to initialize logging\n");
        return 1;
    }
    
    // Create server socket
    if (!create_server()) {
        fprintf(stderr, "Failed to create server socket\n");
        cleanup();
        return 1;
    }
    
    // Main server loop
    server_loop();
    
    // Cleanup
    cleanup();
    
    printf("QM Mock: Server stopped\n");
    return 0;
}
