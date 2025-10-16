#include "../inc/unixcomm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <stdarg.h>
#include <time.h>

// Optional pthread support
#ifdef UNIXCOMM_HAVE_PTHREAD
#include <pthread.h>
#endif

// Internal structures
typedef struct {
    bool initialized;
    unixcomm_global_config_t config;
#ifdef UNIXCOMM_HAVE_PTHREAD
    pthread_mutex_t global_mutex;
#endif
} unixcomm_global_t;

static unixcomm_global_t g_unixcomm = {0};

// Internal helper functions
static bool unixcomm_create_socket_directory(const char *path);
static bool unixcomm_set_socket_timeout(int fd, double timeout);
static bool unixcomm_validate_socket_path(const char *path);
static void unixcomm_log_internal(int level, const char *format, va_list args);
static const char *unixcomm_get_process_socket_name(unixcomm_process_t process);

// Global initialization
bool unixcomm_init(const unixcomm_global_config_t *global_config) {
    if (g_unixcomm.initialized) {
        return true;
    }

    if (global_config) {
        g_unixcomm.config = *global_config;
    } else {
        // Default configuration
        g_unixcomm.config.log_callback = NULL;
        g_unixcomm.config.enable_debug = false;
        g_unixcomm.config.enable_trace = false;
        g_unixcomm.config.log_level = 2; // INFO level
    }

#ifdef UNIXCOMM_HAVE_PTHREAD
    if (pthread_mutex_init(&g_unixcomm.global_mutex, NULL) != 0) {
        return false;
    }
#endif

    g_unixcomm.initialized = true;
    return true;
}

void unixcomm_cleanup(void) {
    if (!g_unixcomm.initialized) {
        return;
    }

#ifdef UNIXCOMM_HAVE_PTHREAD
    pthread_mutex_destroy(&g_unixcomm.global_mutex);
#endif
    memset(&g_unixcomm, 0, sizeof(g_unixcomm));
}

bool unixcomm_is_initialized(void) {
    return g_unixcomm.initialized;
}

// Configuration management
bool unixcomm_config_init(unixcomm_config_t *config) {
    if (!config) return false;

    memset(config, 0, sizeof(unixcomm_config_t));
    strcpy(config->socket_dir, UNIXCOMM_DEFAULT_SOCK_DIR);
    //config->target_process = UNIXCOMM_PROCESS_QM; // Default to QM
    config->timeout = UNIXCOMM_DEFAULT_TIMEOUT;
    config->max_pending = UNIXCOMM_DEFAULT_MAX_PENDING;
    config->buffer_size = UNIXCOMM_DEFAULT_COMPACT_SIZE;
    config->enable_compression = false;
    config->enable_checksum = true;
    config->enable_heartbeat = true;
    config->heartbeat_interval = 30; // 30 seconds
    strcpy(config->log_prefix, "unixcomm");

    return true;
}

bool unixcomm_config_set_socket_path(unixcomm_config_t *config, const char *path) {
    if (!config || !path) return false;
    if (strlen(path) >= UNIXCOMM_MAX_SOCK_PATH) return false;

    strcpy(config->socket_path, path);
    return true;
}

bool unixcomm_config_set_target_process(unixcomm_config_t *config, unixcomm_process_t process) {
    if (!config) return false;
    
    config->target_process = process;
    
    // Auto-generate socket path based on process
    const char *process_name = unixcomm_get_process_socket_name(process);
    if (process_name) {
        snprintf(config->socket_path, UNIXCOMM_MAX_SOCK_PATH, "%s/%s.sock", 
                config->socket_dir, process_name);
    }
    
    return true;
}

bool unixcomm_config_set_timeout(unixcomm_config_t *config, double timeout) {
    if (!config || timeout < 0) return false;
    config->timeout = timeout;
    return true;
}

bool unixcomm_config_set_max_pending(unixcomm_config_t *config, int max_pending) {
    if (!config || max_pending < 1) return false;
    config->max_pending = max_pending;
    return true;
}

bool unixcomm_config_validate(const unixcomm_config_t *config) {
    if (!config) return false;
    if (strlen(config->socket_path) == 0) return false;
    if (config->timeout < 0) return false;
    if (config->max_pending < 1) return false;
    if (config->buffer_size < 1024) return false;
    if (config->heartbeat_interval < 1) return false;

    return true;
}

// Connection management
bool unixcomm_server_create(unixcomm_handle_t *handle, const unixcomm_config_t *config) {
    if (!handle || !config) return false;
    if (!unixcomm_config_validate(config)) return false;

    memset(handle, 0, sizeof(unixcomm_handle_t));
    handle->type = UNIXCOMM_TYPE_SERVER;
    handle->config = *config;
    handle->fd = -1;
    handle->connected = false;
    handle->sequence = 0;
    handle->last_activity = time(NULL);

    // Create socket directory
    //if (!unixcomm_create_socket_directory(config->socket_dir)) {
    if (!unixcomm_create_socket_directory(config->socket_path)) {
        return false;
    }

    // Create socket
    handle->fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (handle->fd < 0) {
        unixcomm_log_error("Failed to create socket: %s", strerror(errno));
        return false;
    }

    // Set up socket address
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, config->socket_path, sizeof(addr.sun_path) - 1);

    // Remove existing socket file
    unlink(config->socket_path);

    // Bind socket
    if (bind(handle->fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        unixcomm_log_error("Failed to bind socket: %s", strerror(errno));
        close(handle->fd);
        handle->fd = -1;
        return false;
    }

    // Listen on socket
    if (listen(handle->fd, config->max_pending) < 0) {
        unixcomm_log_error("Failed to listen on socket: %s", strerror(errno));
        close(handle->fd);
        handle->fd = -1;
        return false;
    }

    handle->connected = true;
    unixcomm_log_info("Server socket created: %s", config->socket_path);
    return true;
}

bool unixcomm_client_create(unixcomm_handle_t *handle, const unixcomm_config_t *config) {
    if (!handle || !config) return false;
    if (!unixcomm_config_validate(config)) return false;

    memset(handle, 0, sizeof(unixcomm_handle_t));
    handle->type = UNIXCOMM_TYPE_CLIENT;
    handle->config = *config;
    handle->fd = -1;
    handle->connected = false;
    handle->sequence = 0;
    handle->last_activity = time(NULL);

    return true;
}

bool unixcomm_accept(unixcomm_handle_t *server_handle, unixcomm_handle_t *client_handle) {
    if (!server_handle || !client_handle) return false;
    if (server_handle->type != UNIXCOMM_TYPE_SERVER) return false;
    if (!server_handle->connected) return false;

    memset(client_handle, 0, sizeof(unixcomm_handle_t));
    client_handle->type = UNIXCOMM_TYPE_CLIENT;
    client_handle->config = server_handle->config;
    client_handle->sequence = 0;
    client_handle->last_activity = time(NULL);

    // Accept connection
    client_handle->fd = accept(server_handle->fd, NULL, NULL);
    if (client_handle->fd < 0) {
        unixcomm_log_error("Failed to accept connection: %s", strerror(errno));
        return false;
    }

    // Set timeout
    if (!unixcomm_set_socket_timeout(client_handle->fd, server_handle->config.timeout)) {
        close(client_handle->fd);
        client_handle->fd = -1;
        return false;
    }

    client_handle->connected = true;
    unixcomm_log_info("Client connection accepted");
    return true;
}

bool unixcomm_connect(unixcomm_handle_t *handle) {
    if (!handle) return false;
    if (handle->type != UNIXCOMM_TYPE_CLIENT) return false;
    if (handle->connected) return true;

    // Create socket
    handle->fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (handle->fd < 0) {
        unixcomm_log_error("Failed to create client socket: %s", strerror(errno));
        return false;
    }

    // Set timeout
    if (!unixcomm_set_socket_timeout(handle->fd, handle->config.timeout)) {
        close(handle->fd);
        handle->fd = -1;
        return false;
    }

    // Set up socket address
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, handle->config.socket_path, sizeof(addr.sun_path) - 1);

    // Connect to server
    if (connect(handle->fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        unixcomm_log_error("Failed to connect to server: %s", strerror(errno));
        close(handle->fd);
        handle->fd = -1;
        return false;
    }

    handle->connected = true;
    handle->last_activity = time(NULL);
    unixcomm_log_info("Connected to server: %s", handle->config.socket_path);
    return true;
}

bool unixcomm_disconnect(unixcomm_handle_t *handle) {
    if (!handle) return false;
    if (!handle->connected) return true;

    if (handle->fd >= 0) {
        close(handle->fd);
        handle->fd = -1;
    }

    handle->connected = false;
    unixcomm_log_info("Disconnected from server");
    return true;
}

bool unixcomm_close(unixcomm_handle_t *handle) {
    if (!handle) return false;

    unixcomm_disconnect(handle);
    memset(handle, 0, sizeof(unixcomm_handle_t));
    return true;
}

bool unixcomm_is_connected(const unixcomm_handle_t *handle) {
    if (!handle) return false;
    return handle->connected && handle->fd >= 0;
}

// Message handling
bool unixcomm_send_message(unixcomm_handle_t *handle, const unixcomm_message_t *message, unixcomm_response_t *response) {
    if (!handle || !message) return false;
    if (!handle->connected) return false;

    // Send request header
    if (send(handle->fd, &message->request, sizeof(message->request), MSG_NOSIGNAL) != sizeof(message->request)) {
        unixcomm_log_error("Failed to send request header: %s", strerror(errno));
        return false;
    }

    // Send topic if present
    if (message->topic && message->request.topic_len > 0) {
        if (send(handle->fd, message->topic, message->request.topic_len, MSG_NOSIGNAL) != (ssize_t)message->request.topic_len) {
            unixcomm_log_error("Failed to send topic: %s", strerror(errno));
            return false;
        }
    }

    // Send data if present
    if (message->data && message->data_size > 0) {
        if (send(handle->fd, message->data, message->data_size, MSG_NOSIGNAL) != (ssize_t)message->data_size) {
            unixcomm_log_error("Failed to send data: %s", strerror(errno));
            return false;
        }
    }

    // Receive response if requested
    if (response) {
        if (recv(handle->fd, response, sizeof(unixcomm_response_t), 0) != sizeof(unixcomm_response_t)) {
            unixcomm_log_error("Failed to receive response: %s", strerror(errno));
            return false;
        }
    }

    handle->last_activity = time(NULL);
    return true;
}

bool unixcomm_receive_message(unixcomm_handle_t *handle, unixcomm_message_t *message) {
    if (!handle || !message) return false;
    if (!handle->connected) return false;

    // Receive request header
    if (recv(handle->fd, &message->request, sizeof(message->request), 0) != sizeof(message->request)) {
        unixcomm_log_error("Failed to receive request header: %s", strerror(errno));
        return false;
    }

    // Receive topic if present
    if (message->request.topic_len > 0) {
        message->topic = unixcomm_malloc(message->request.topic_len + 1);
        if (!message->topic) return false;

        if (recv(handle->fd, message->topic, message->request.topic_len, 0) != (ssize_t)message->request.topic_len) {
            unixcomm_log_error("Failed to receive topic: %s", strerror(errno));
            unixcomm_free(message->topic);
            message->topic = NULL;
            return false;
        }
        message->topic[message->request.topic_len] = '\0';
    } else {
        message->topic = NULL;
    }

    // Receive data if present
    if (message->request.data_size > 0) {
        message->data = unixcomm_malloc(message->request.data_size);
        if (!message->data) {
            unixcomm_free(message->topic);
            message->topic = NULL;
            return false;
        }

        if (recv(handle->fd, message->data, message->request.data_size, 0) != (ssize_t)message->request.data_size) {
            unixcomm_log_error("Failed to receive data: %s", strerror(errno));
            unixcomm_free(message->data);
            unixcomm_free(message->topic);
            message->data = NULL;
            message->topic = NULL;
            return false;
        }
    } else {
        message->data = NULL;
    }

    message->data_size = message->request.data_size;
    message->timestamp = time(NULL);
    handle->last_activity = time(NULL);
    return true;
}

bool unixcomm_send_data(unixcomm_handle_t *handle, const void *data, size_t data_size, unixcomm_response_t *response) {
    if (!handle || !data || data_size == 0) return false;

    unixcomm_message_t message = {0};
    unixcomm_request_t request = {0};

    // Initialize request
    strcpy(request.tag, "REQ");
    request.version = 1;
    request.sequence = ++handle->sequence;
    request.command = 1; // SEND command
    request.data_size = data_size;
    request.msg_type = UNIXCOMM_MSG_REQUEST;
    request.priority = 5; // Normal priority

    message.request = request;
    message.data = (void*)data;
    message.data_size = data_size;
    message.timestamp = time(NULL);
    message.sender_pid = getpid();

    return unixcomm_send_message(handle, &message, response);
}

bool unixcomm_send_request(unixcomm_handle_t *handle, const void *data, size_t data_size, unixcomm_response_t *response) {
    if (!handle || !data || data_size == 0) return false;

    unixcomm_message_t message = {0};
    unixcomm_request_t request = {0};

    // Initialize request
    strcpy(request.tag, "REQ");
    request.version = 1;
    request.sequence = ++handle->sequence;
    request.command = 1; // SEND command
    request.flags = 0x01; // REQUEST flag
    request.data_size = data_size;
    request.msg_type = UNIXCOMM_MSG_REQUEST;
    request.priority = 5; // Normal priority

    message.request = request;
    message.data = (void*)data;
    message.data_size = data_size;
    message.timestamp = time(NULL);
    message.sender_pid = getpid();

    return unixcomm_send_message(handle, &message, response);
}

// Request/Response handling
bool unixcomm_request_init(unixcomm_request_t *request, const char *sender) {
    if (!request) return false;

    memset(request, 0, sizeof(unixcomm_request_t));
    strcpy(request->tag, "REQ");
    request->version = 1;
    request->sequence = 0; // Will be set by caller
    request->command = 1; // SEND command
    request->msg_type = UNIXCOMM_MSG_REQUEST;
    request->priority = 5; // Normal priority
    request->timeout = 5000; // 5 seconds default timeout

    if (sender) {
        strncpy(request->sender, sender, sizeof(request->sender) - 1);
        request->sender[sizeof(request->sender) - 1] = '\0';
    }

    return true;
}

bool unixcomm_response_init(unixcomm_response_t *response, const unixcomm_request_t *request) {
    if (!response || !request) return false;

    memset(response, 0, sizeof(unixcomm_response_t));
    strcpy(response->tag, "RES");
    response->version = 1;
    response->sequence = request->sequence;
    response->status = 2; // RECEIVED
    response->error = UNIXCOMM_SUCCESS;
    response->processing_time = 0; // Will be set by caller

    return true;
}

// Message creation and management
unixcomm_message_t *unixcomm_message_create(const void *data, size_t data_size) {
    unixcomm_message_t *message = unixcomm_malloc(sizeof(unixcomm_message_t));
    if (!message) return NULL;

    memset(message, 0, sizeof(unixcomm_message_t));

    if (data && data_size > 0) {
        message->data = unixcomm_malloc(data_size);
        if (!message->data) {
            unixcomm_free(message);
            return NULL;
        }
        memcpy(message->data, data, data_size);
        message->data_size = data_size;
    }

    message->timestamp = time(NULL);
    message->sender_pid = getpid();
    return message;
}
#if 0
void unixcomm_message_destroy(unixcomm_message_t *message) {
    if (!message) return;

    unixcomm_free(message->data);
    unixcomm_free(message);
}
#endif
void unixcomm_message_destroy(unixcomm_message_t *message) {
    if (!message) {
        unixcomm_log_info("unixcomm_message_destroy: null message");
        return;
    }
    unixcomm_log_info("unixcomm_message_destroy: data=%p, topic=%p", message->data, message->topic);
    if (message->data) {
        unixcomm_free(message->data);
        message->data = NULL;
    }
    if (message->topic) {
        unixcomm_free(message->topic);
        message->topic = NULL;
    }
    // Do not free message itself (stack-allocated)
}

// Utility functions
const char *unixcomm_error_string(unixcomm_error_t error) {
    switch (error) {
        case UNIXCOMM_SUCCESS: return "Success";
        case UNIXCOMM_ERROR_INVALID_PARAM: return "Invalid parameter";
        case UNIXCOMM_ERROR_MEMORY_ALLOC: return "Memory allocation failed";
        case UNIXCOMM_ERROR_SOCKET_CREATE: return "Socket creation failed";
        case UNIXCOMM_ERROR_SOCKET_BIND: return "Socket bind failed";
        case UNIXCOMM_ERROR_SOCKET_LISTEN: return "Socket listen failed";
        case UNIXCOMM_ERROR_SOCKET_ACCEPT: return "Socket accept failed";
        case UNIXCOMM_ERROR_SOCKET_CONNECT: return "Socket connect failed";
        case UNIXCOMM_ERROR_SOCKET_SEND: return "Socket send failed";
        case UNIXCOMM_ERROR_SOCKET_RECV: return "Socket receive failed";
        case UNIXCOMM_ERROR_TIMEOUT: return "Operation timeout";
        case UNIXCOMM_ERROR_NOT_CONNECTED: return "Not connected";
        case UNIXCOMM_ERROR_INVALID_DATA: return "Invalid data";
        case UNIXCOMM_ERROR_INTERNAL: return "Internal error";
        default: return "Unknown error";
    }
}

const char *unixcomm_msg_type_string(unixcomm_msg_type_t type) {
    switch (type) {
        case UNIXCOMM_MSG_REQUEST: return "request";
        case UNIXCOMM_MSG_RESPONSE: return "response";
        case UNIXCOMM_MSG_NOTIFICATION: return "notification";
        case UNIXCOMM_MSG_HEARTBEAT: return "heartbeat";
        case UNIXCOMM_MSG_SHUTDOWN: return "shutdown";
        default: return "unknown";
    }
}

bool unixcomm_set_timeout(unixcomm_handle_t *handle, double timeout) {
    if (!handle) return false;
    if (timeout < 0) return false;

    handle->config.timeout = timeout;
    if (handle->fd >= 0) {
        return unixcomm_set_socket_timeout(handle->fd, timeout);
    }
    return true;
}

bool unixcomm_check_connection(unixcomm_handle_t *handle) {
    if (!handle) return false;
    if (!handle->connected) return false;

    // Check if socket is still valid
    struct pollfd pfd = {0};
    pfd.fd = handle->fd;
    pfd.events = 0;

    int ret = poll(&pfd, 1, 0);
    if (ret < 0) {
        unixcomm_log_error("Poll failed: %s", strerror(errno));
        return false;
    }

    if (ret > 0 && (pfd.revents & (POLLHUP | POLLERR | POLLNVAL))) {
        unixcomm_log_error("Socket is in bad state");
        handle->connected = false;
        return false;
    }

    return true;
}

bool unixcomm_reconnect(unixcomm_handle_t *handle) {
    if (!handle) return false;
    if (handle->type != UNIXCOMM_TYPE_CLIENT) return false;

    unixcomm_disconnect(handle);
    return unixcomm_connect(handle);
}

// Memory management
void *unixcomm_malloc(size_t size) {
    return malloc(size);
}

void unixcomm_free(void *ptr) {
    if (ptr) free(ptr);
}

void *unixcomm_realloc(void *ptr, size_t size) {
    return realloc(ptr, size);
}

// Logging
bool unixcomm_log_set_level(int level) {
    if (!g_unixcomm.initialized) return false;
    g_unixcomm.config.log_level = level;
    return true;
}

void unixcomm_log_debug(const char *format, ...) {
    if (!g_unixcomm.initialized || g_unixcomm.config.log_level > 0) return;
    va_list args;
    va_start(args, format);
    unixcomm_log_internal(0, format, args);
    va_end(args);
}

void unixcomm_log_info(const char *format, ...) {
    if (!g_unixcomm.initialized || g_unixcomm.config.log_level > 1) return;
    va_list args;
    va_start(args, format);
    unixcomm_log_internal(1, format, args);
    va_end(args);
}

void unixcomm_log_warn(const char *format, ...) {
    if (!g_unixcomm.initialized || g_unixcomm.config.log_level > 2) return;
    va_list args;
    va_start(args, format);
    unixcomm_log_internal(2, format, args);
    va_end(args);
}

void unixcomm_log_error(const char *format, ...) {
    if (!g_unixcomm.initialized || g_unixcomm.config.log_level > 3) return;
    va_list args;
    va_start(args, format);
    unixcomm_log_internal(3, format, args);
    va_end(args);
}

// Internal helper functions
static bool unixcomm_create_socket_directory(const char *path) {
    if (!path) return false;

    char dir_path[UNIXCOMM_MAX_SOCK_PATH];
    strncpy(dir_path, path, sizeof(dir_path) - 1);
    dir_path[sizeof(dir_path) - 1] = '\0';

    char *last_slash = strrchr(dir_path, '/');
    if (last_slash) {
        *last_slash = '\0';
    }

    if (strlen(dir_path) > 0) {
        if (mkdir(dir_path, 0755) < 0 && errno != EEXIST) {
            unixcomm_log_error("Failed to create socket directory: %s", strerror(errno));
            return false;
        }
    }

    return true;
}

static bool unixcomm_set_socket_timeout(int fd, double timeout) {
    if (fd < 0 || timeout < 0) return false;

    struct timeval tv;
    tv.tv_sec = (int)timeout;
    tv.tv_usec = (int)((timeout - (int)timeout) * 1000000.0);

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        return false;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
        return false;
    }

    return true;
}

static bool unixcomm_validate_socket_path(const char *path) {
    if (!path) return false;
    if (strlen(path) >= UNIXCOMM_MAX_SOCK_PATH) return false;
    if (strlen(path) == 0) return false;
    return true;
}

static void unixcomm_log_internal(int level, const char *format, va_list args) {
    if (!g_unixcomm.initialized) return;

    if (g_unixcomm.config.log_callback) {
        g_unixcomm.config.log_callback(format, args);
    } else {
        const char *level_str = (level == 0) ? "DEBUG" : 
                               (level == 1) ? "INFO" : 
                               (level == 2) ? "WARN" : "ERROR";
        
        printf("[%s] ", level_str);
        vprintf(format, args);
        printf("\n");
    }
}

// Additional message functions
bool unixcomm_send_notification(unixcomm_handle_t *handle, const void *data, size_t data_size) {
    if (!handle || !data || data_size == 0) return false;

    unixcomm_message_t message = {0};
    unixcomm_request_t request = {0};

    // Initialize request for notification
    strcpy(request.tag, "REQ");
    request.version = 1;
    request.sequence = ++handle->sequence;
    request.command = 1; // SEND command
    request.data_size = data_size;
    request.msg_type = UNIXCOMM_MSG_NOTIFICATION;
    request.priority = 3; // Lower priority for notifications

    message.request = request;
    message.data = (void*)data;
    message.data_size = data_size;
    message.timestamp = time(NULL);
    message.sender_pid = getpid();

    return unixcomm_send_message(handle, &message, NULL); // No response expected
}

bool unixcomm_send_heartbeat(unixcomm_handle_t *handle) {
    if (!handle) return false;

    unixcomm_message_t message = {0};
    unixcomm_request_t request = {0};

    // Initialize request for heartbeat
    strcpy(request.tag, "REQ");
    request.version = 1;
    request.sequence = ++handle->sequence;
    request.command = 1; // SEND command
    request.data_size = 0; // No data for heartbeat
    request.msg_type = UNIXCOMM_MSG_HEARTBEAT;
    request.priority = 1; // Lowest priority

    message.request = request;
    message.data = NULL;
    message.data_size = 0;
    message.timestamp = time(NULL);
    message.sender_pid = getpid();

    return unixcomm_send_message(handle, &message, NULL); // No response expected
}

bool unixcomm_message_set_type(unixcomm_message_t *message, unixcomm_msg_type_t type) {
    if (!message) return false;
    message->request.msg_type = type;
    return true;
}

// Helper function to get process socket name
static const char *unixcomm_get_process_socket_name(unixcomm_process_t process) {
    switch (process) {
        case UNIXCOMM_PROCESS_QM: return "qm";
        case UNIXCOMM_PROCESS_SM: return "sm";
        case UNIXCOMM_PROCESS_DM: return "dm";
        case UNIXCOMM_PROCESS_CM: return "cm";
        default: return NULL;
    }
}

// Convenience helper: create a client, connect to process, send message, cleanup
bool unixcomm_send_to_process(unixcomm_process_t process, const unixcomm_message_t *message, unixcomm_response_t *response) {
    unixcomm_config_t cfg;
    unixcomm_handle_t client;
    if (!unixcomm_config_init(&cfg)) return false;
    if (!unixcomm_config_set_target_process(&cfg, process)) return false;
    if (!unixcomm_client_create(&client, &cfg)) return false;
    if (!unixcomm_connect(&client)) return false;
    bool ok = unixcomm_send_message(&client, message, response);
    unixcomm_disconnect(&client);
    unixcomm_close(&client);
    return ok;
}
