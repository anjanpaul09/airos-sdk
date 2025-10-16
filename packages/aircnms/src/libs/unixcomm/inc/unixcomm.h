#ifndef UNIXCOMM_H_INCLUDED
#define UNIXCOMM_H_INCLUDED

#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <poll.h>
#include <sys/time.h>

// Version information
#define UNIXCOMM_VERSION_MAJOR 1
#define UNIXCOMM_VERSION_MINOR 0
#define UNIXCOMM_VERSION_PATCH 0

// Default configuration
#define UNIXCOMM_DEFAULT_TIMEOUT 2.0
#define UNIXCOMM_DEFAULT_MAX_PENDING 10
#define UNIXCOMM_DEFAULT_COMPACT_SIZE (64*1024)
#define UNIXCOMM_DEFAULT_SOCK_DIR "/tmp/aircnms"
#define UNIXCOMM_MAX_SOCK_PATH 256
#define UNIXCOMM_MAX_TOPIC_LEN 256
#define UNIXCOMM_MAX_DATA_SIZE (2*1024*1024)

// Error codes
typedef enum {
    UNIXCOMM_SUCCESS = 0,
    UNIXCOMM_ERROR_INVALID_PARAM = -1,
    UNIXCOMM_ERROR_MEMORY_ALLOC = -2,
    UNIXCOMM_ERROR_SOCKET_CREATE = -3,
    UNIXCOMM_ERROR_SOCKET_BIND = -4,
    UNIXCOMM_ERROR_SOCKET_LISTEN = -5,
    UNIXCOMM_ERROR_SOCKET_ACCEPT = -6,
    UNIXCOMM_ERROR_SOCKET_CONNECT = -7,
    UNIXCOMM_ERROR_SOCKET_SEND = -8,
    UNIXCOMM_ERROR_SOCKET_RECV = -9,
    UNIXCOMM_ERROR_TIMEOUT = -10,
    UNIXCOMM_ERROR_NOT_CONNECTED = -11,
    UNIXCOMM_ERROR_INVALID_DATA = -12,
    UNIXCOMM_ERROR_INTERNAL = -13
} unixcomm_error_t;

// Connection types
typedef enum {
    UNIXCOMM_TYPE_SERVER = 0,
    UNIXCOMM_TYPE_CLIENT = 1
} unixcomm_type_t;

// Process types for socket path selection
typedef enum {
    UNIXCOMM_PROCESS_QM = 0,    // Queue Manager
    UNIXCOMM_PROCESS_SM = 1,    // Statistics Manager
    UNIXCOMM_PROCESS_DM = 2,    // Device Manager
    UNIXCOMM_PROCESS_CM = 3     // Configuration Manager
} unixcomm_process_t;

// Message types
typedef enum {
    UNIXCOMM_MSG_REQUEST = 0,
    UNIXCOMM_MSG_RESPONSE = 1,
    UNIXCOMM_MSG_NOTIFICATION = 2,
    UNIXCOMM_MSG_HEARTBEAT = 3,
    UNIXCOMM_MSG_SHUTDOWN = 4
} unixcomm_msg_type_t;

// message data type
typedef enum req_data_type
{
    DATA_RAW = 0,
    DATA_TEXT,
    DATA_STATS,
    DATA_LOG,
    DATA_INI,
    DATA_CONF,
    DATA_CMD,
    DATA_ACL,
    DATA_RL,
    DATA_ALARM,
    DATA_EVENT
} data_type_t;

// Request structure
typedef struct {
    char tag[4];                    // Request tag ("REQ")
    uint32_t version;              // Protocol version
    uint32_t sequence;             // Sequence number
    uint32_t command;              // Command type
    uint32_t flags;                // Request flags
    char sender[16];               // Sender name
    uint8_t msg_type;              // Message type
    uint8_t priority;              // Message priority (0-7)
    uint8_t compress;              // Compression flag
    uint8_t reserved;              // Reserved field
    uint32_t timeout;              // Request timeout (ms)
    uint32_t data_size;            // Data size
    uint32_t topic_len;              // Topic length
    uint32_t checksum;             // Data checksum
    uint8_t data_type;              // data type
} unixcomm_request_t;

// Response structure
typedef struct {
    char tag[4];                   // Response tag ("RES")
    uint32_t version;              // Protocol version
    uint32_t sequence;             // Sequence number
    uint32_t status;               // Response status
    uint32_t error;                // Error code
    uint32_t processing_time;      // Processing time (ms)
    uint32_t queue_length;         // Queue length
    uint32_t queue_size;           // Queue size
    uint32_t connection_status;    // Connection status
    uint32_t data_size;            // Response data size
    uint32_t topic_len;              // Topic length
    uint32_t checksum;             // Response checksum
} unixcomm_response_t;

// Connection configuration
typedef struct {
    char socket_path[UNIXCOMM_MAX_SOCK_PATH];
    char socket_dir[UNIXCOMM_MAX_SOCK_PATH];
    unixcomm_process_t target_process;  // Target process for communication
    double timeout;
    int max_pending;
    size_t buffer_size;
    bool enable_compression;
    bool enable_checksum;
    bool enable_heartbeat;
    int heartbeat_interval;
    char log_prefix[32];
} unixcomm_config_t;

// Connection handle
typedef struct {
    int fd;                         // Socket file descriptor
    unixcomm_type_t type;           // Connection type
    unixcomm_config_t config;      // Configuration
    bool connected;                 // Connection status
    time_t last_activity;           // Last activity timestamp
    uint32_t sequence;              // Sequence counter
    void *private_data;             // Private data pointer
} unixcomm_handle_t;

// Message structure
typedef struct {
    unixcomm_request_t request;     // Request header
    void *data;                     // Data buffer
    char *topic;                    // Topic string
    size_t data_size;               // Data size
    time_t timestamp;               // Message timestamp
    uint32_t sender_pid;            // Sender process ID
    uint32_t receiver_pid;          // Receiver process ID
} unixcomm_message_t;

// Callback function types
typedef bool (*unixcomm_message_callback_t)(unixcomm_handle_t *handle, unixcomm_message_t *message);
typedef void (*unixcomm_error_callback_t)(unixcomm_handle_t *handle, unixcomm_error_t error);
typedef void (*unixcomm_log_callback_t)(const char *format, ...);

// Global configuration
typedef struct {
    unixcomm_log_callback_t log_callback;
    bool enable_debug;
    bool enable_trace;
    int log_level;
} unixcomm_global_config_t;

// Core API Functions

// Initialization and cleanup
bool unixcomm_init(const unixcomm_global_config_t *global_config);
void unixcomm_cleanup(void);
bool unixcomm_is_initialized(void);

// Configuration management
bool unixcomm_config_init(unixcomm_config_t *config);
bool unixcomm_config_set_socket_path(unixcomm_config_t *config, const char *path);
bool unixcomm_config_set_target_process(unixcomm_config_t *config, unixcomm_process_t process);
bool unixcomm_config_set_timeout(unixcomm_config_t *config, double timeout);
bool unixcomm_config_set_max_pending(unixcomm_config_t *config, int max_pending);
bool unixcomm_config_validate(const unixcomm_config_t *config);

// Connection management
bool unixcomm_server_create(unixcomm_handle_t *handle, const unixcomm_config_t *config);
bool unixcomm_client_create(unixcomm_handle_t *handle, const unixcomm_config_t *config);
bool unixcomm_accept(unixcomm_handle_t *server_handle, unixcomm_handle_t *client_handle);
bool unixcomm_connect(unixcomm_handle_t *handle);
bool unixcomm_disconnect(unixcomm_handle_t *handle);
bool unixcomm_close(unixcomm_handle_t *handle);
bool unixcomm_is_connected(const unixcomm_handle_t *handle);

// Message handling
bool unixcomm_send_message(unixcomm_handle_t *handle, const unixcomm_message_t *message, unixcomm_response_t *response);
bool unixcomm_receive_message(unixcomm_handle_t *handle, unixcomm_message_t *message);
bool unixcomm_send_data(unixcomm_handle_t *handle, const void *data, size_t data_size, unixcomm_response_t *response);
bool unixcomm_send_request(unixcomm_handle_t *handle, const void *data, size_t data_size, unixcomm_response_t *response);
bool unixcomm_send_notification(unixcomm_handle_t *handle, const void *data, size_t data_size);
bool unixcomm_send_heartbeat(unixcomm_handle_t *handle);

// Convenience helper: send a message to a target process in one shot
bool unixcomm_send_to_process(unixcomm_process_t process, const unixcomm_message_t *message, unixcomm_response_t *response);

// Request/Response handling
bool unixcomm_request_init(unixcomm_request_t *request, const char *sender);
bool unixcomm_response_init(unixcomm_response_t *response, const unixcomm_request_t *request);
bool unixcomm_send_request_with_header(unixcomm_handle_t *handle, const unixcomm_request_t *request, const void *data, size_t data_size, unixcomm_response_t *response);
bool unixcomm_receive_request(unixcomm_handle_t *handle, unixcomm_request_t *request, void **data);
bool unixcomm_send_response(unixcomm_handle_t *handle, const unixcomm_response_t *response);
bool unixcomm_receive_response(unixcomm_handle_t *handle, unixcomm_response_t *response);

// Message creation and management
unixcomm_message_t *unixcomm_message_create(const void *data, size_t data_size);
void unixcomm_message_destroy(unixcomm_message_t *message);
bool unixcomm_message_set_data(unixcomm_message_t *message, const void *data, size_t data_size);
bool unixcomm_message_set_type(unixcomm_message_t *message, unixcomm_msg_type_t type);

// Utility functions
const char *unixcomm_error_string(unixcomm_error_t error);
const char *unixcomm_msg_type_string(unixcomm_msg_type_t type);
bool unixcomm_set_timeout(unixcomm_handle_t *handle, double timeout);
bool unixcomm_check_connection(unixcomm_handle_t *handle);
bool unixcomm_reconnect(unixcomm_handle_t *handle);

// Callback management
bool unixcomm_set_message_callback(unixcomm_handle_t *handle, unixcomm_message_callback_t callback);
bool unixcomm_set_error_callback(unixcomm_handle_t *handle, unixcomm_error_callback_t callback);

// Polling and event handling
bool unixcomm_poll(unixcomm_handle_t *handle, int timeout_ms);
bool unixcomm_poll_multiple(unixcomm_handle_t *handles[], int num_handles, int timeout_ms);

// Statistics and monitoring
typedef struct {
    uint64_t messages_sent;
    uint64_t messages_received;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t errors;
    uint64_t reconnections;
    time_t start_time;
    time_t last_activity;
} unixcomm_stats_t;

bool unixcomm_get_stats(const unixcomm_handle_t *handle, unixcomm_stats_t *stats);
void unixcomm_reset_stats(unixcomm_handle_t *handle);

// Thread safety (optional - only if pthread is available)
#ifdef UNIXCOMM_HAVE_PTHREAD
bool unixcomm_lock_handle(unixcomm_handle_t *handle);
bool unixcomm_unlock_handle(unixcomm_handle_t *handle);
#endif

// Memory management
void *unixcomm_malloc(size_t size);
void unixcomm_free(void *ptr);
void *unixcomm_realloc(void *ptr, size_t size);

// Logging
bool unixcomm_log_set_level(int level);
void unixcomm_log_debug(const char *format, ...);
void unixcomm_log_info(const char *format, ...);
void unixcomm_log_warn(const char *format, ...);
void unixcomm_log_error(const char *format, ...);

// Compatibility macros for existing code
#define unixcomm_send_stats(handle, data, size, response) \
    unixcomm_send_data(handle, data, size, response)

#define unixcomm_send_log(handle, message, response) \
    unixcomm_send_data(handle, message, strlen(message), response)

// Legacy compatibility functions (for gradual migration)
bool unixcomm_legacy_server(int *pfd, const char *socket_path);
bool unixcomm_legacy_client(int *pfd, const char *socket_path);
bool unixcomm_legacy_accept(int listen_fd, int *accept_fd);
bool unixcomm_legacy_send(int fd, const void *data, size_t size);
bool unixcomm_legacy_receive(int fd, void *data, size_t *size);

#endif /* UNIXCOMM_H_INCLUDED */
