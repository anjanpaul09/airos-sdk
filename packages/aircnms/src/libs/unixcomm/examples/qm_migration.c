/*
 * QM Migration Example
 * Demonstrates how to migrate from QM-specific socket code to UnixComm library
 */

#include "unixcomm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// OLD QM Code (for comparison)
/*
bool qm_conn_server(int *pfd) {
    struct sockaddr_un addr;
    char *path = QM_SOCK_FILENAME;
    int fd;

    mkdir(QM_SOCK_DIR, 0755);
    errno = 0;

    *pfd = -1;
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        LOG(ERR, "socket");
        return false;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (*path == '\0') {
        *addr.sun_path = '\0';
        strscpy(addr.sun_path+1, path+1, sizeof(addr.sun_path)-1);
    } else {
        STRSCPY(addr.sun_path, path);
        unlink(path);
    }
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        LOG(ERR, "bind");
        close(fd);
        return false;
    }
    if (listen(fd, QM_SOCK_MAX_PENDING) < 0) {
        LOG(ERR, "listen");
        close(fd);
        return false;
    }
    *pfd = fd;
    LOG(TRACE, "%s %s", __FUNCTION__, path);
    return true;
}
*/

// NEW QM Code using UnixComm
bool qm_server_init(unixcomm_handle_t *server) {
    unixcomm_config_t config;
    unixcomm_config_init(&config);
    unixcomm_config_set_socket_path(&config, "/tmp/aircnms/qm.sock");
    unixcomm_config_set_timeout(&config, 2.0);
    unixcomm_config_set_max_pending(&config, 10);

    if (!unixcomm_config_validate(&config)) {
        fprintf(stderr, "Invalid QM server configuration\n");
        return false;
    }

    return unixcomm_server_create(server, &config);
}

bool qm_client_init(unixcomm_handle_t *client) {
    unixcomm_config_t config;
    unixcomm_config_init(&config);
    unixcomm_config_set_socket_path(&config, "/tmp/aircnms/qm.sock");
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

// OLD QM Code (for comparison)
/*
bool qm_conn_send_direct(qm_compress_t compress, char *topic,
        void *data, int data_size, qm_response_t *res) {
    return qm_conn_send_custom(
            QM_DATA_RAW, compress,
            QM_REQ_FLAG_SEND_DIRECT,
            topic, data, data_size, res);
}
*/

// NEW QM Code using UnixComm
bool qm_send_direct(unixcomm_handle_t *client, const void *data, size_t data_size, 
                   unixcomm_response_t *response) {
    if (!unixcomm_is_connected(client)) {
        fprintf(stderr, "QM client not connected\n");
        return false;
    }

    return unixcomm_send_request(client, data, data_size, response);
}

// OLD QM Code (for comparison)
/*
bool qm_conn_send_stats(void *data, int data_size, qm_response_t *res) {
    qm_request_t req;
    qm_req_init(&req);
    req.cmd = QM_CMD_SEND;
    if ( strcmp(res->tag, "stats") == 0) {
        req.data_type = QM_DATA_STATS;
    } else if ( strcmp(res->tag, "conf")  == 0) {
        req.data_type = QM_DATA_CONFIG;
    } else if ( strcmp(res->tag, "alarm")  == 0) {
        req.data_type = QM_DATA_ALARM;
    } else if ( strcmp(res->tag, "event")  == 0) {
        req.data_type = QM_DATA_EVENT;
    } else {
        req.data_type = -1;
    }
    req.compress = QM_REQ_COMPRESS_IF_CFG;
    return qm_conn_send_req(&req, NULL, data, data_size, res);
}
*/

// NEW QM Code using UnixComm
bool qm_send_stats(unixcomm_handle_t *client, const void *data, size_t data_size, 
                  const char *tag, unixcomm_response_t *response) {
    if (!unixcomm_is_connected(client)) {
        fprintf(stderr, "QM client not connected\n");
        return false;
    }

    // Map tag to data type
    unixcomm_data_type_t data_type;
    if (strcmp(tag, "stats") == 0) {
        data_type = UNIXCOMM_DATA_STATS;
    } else if (strcmp(tag, "conf") == 0) {
        data_type = UNIXCOMM_DATA_CONFIG;
    } else if (strcmp(tag, "alarm") == 0) {
        data_type = UNIXCOMM_DATA_ALARM;
    } else if (strcmp(tag, "event") == 0) {
        data_type = UNIXCOMM_DATA_EVENT;
    } else {
        data_type = UNIXCOMM_DATA_RAW;
    }

    // Create request
    unixcomm_request_t request;
    unixcomm_request_init(&request, "qm");
    request.command = 1; // SEND command
    request.data_type = data_type;
    request.data_size = data_size;
    request.compress = 0; // No compression for now

    // Send request
    return unixcomm_send_request(client, &request, NULL, data, data_size, response);
}

// OLD QM Code (for comparison)
/*
bool qm_conn_send_log(char *msg, qm_response_t *res) {
    qm_conn_t *qc = &qm_conn_log_handle;
    if (!qc->init) {
        qm_conn_open(qc);
    }
    qm_request_t req;
    qm_req_init(&req);
    req.cmd = QM_CMD_SEND;
    req.data_type = QM_DATA_LOG;
    req.compress = QM_REQ_COMPRESS_DISABLE;
    req.flags = QM_REQ_FLAG_NO_RESPONSE;
    return qm_conn_send_stream(qc, &req, NULL, msg, strlen(msg), res);
}
*/

// NEW QM Code using UnixComm
bool qm_send_log(unixcomm_handle_t *client, const char *message, unixcomm_response_t *response) {
    if (!unixcomm_is_connected(client)) {
        fprintf(stderr, "QM client not connected\n");
        return false;
    }

    return unixcomm_send_raw(client, "log", message, strlen(message), response);
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

    // Create QM server
    unixcomm_handle_t qm_server;
    if (!qm_server_init(&qm_server)) {
        fprintf(stderr, "Failed to initialize QM server\n");
        unixcomm_cleanup();
        return -1;
    }

    printf("QM server started on /tmp/aircnms/qm.sock\n");

    // Create QM client
    unixcomm_handle_t qm_client;
    if (!qm_client_init(&qm_client)) {
        fprintf(stderr, "Failed to initialize QM client\n");
        unixcomm_close(&qm_server);
        unixcomm_cleanup();
        return -1;
    }

    printf("QM client connected to server\n");

    // Send test message
    const char *test_data = "Hello from QM client!";
    unixcomm_response_t response;
    if (qm_send_direct(&qm_client, test_data, strlen(test_data), &response)) {
        printf("Message sent successfully\n");
    } else {
        fprintf(stderr, "Failed to send message: %s\n", unixcomm_error_string(response.error));
    }

    // Send stats
    const char *stats_data = "{\"cpu\": 50, \"memory\": 75}";
    if (qm_send_stats(&qm_client, stats_data, strlen(stats_data), &response)) {
        printf("Stats sent successfully\n");
    } else {
        fprintf(stderr, "Failed to send stats: %s\n", unixcomm_error_string(response.error));
    }

    // Send log
    const char *log_message = "QM client log message";
    if (qm_send_log(&qm_client, log_message, &response)) {
        printf("Log sent successfully\n");
    } else {
        fprintf(stderr, "Failed to send log: %s\n", unixcomm_error_string(response.error));
    }

    // Cleanup
    unixcomm_close(&qm_client);
    unixcomm_close(&qm_server);
    unixcomm_cleanup();

    printf("QM migration example completed\n");
    return 0;
}
