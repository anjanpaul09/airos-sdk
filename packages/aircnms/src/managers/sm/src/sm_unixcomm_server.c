#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ev.h>
#include <pthread.h>
#include <signal.h>
#include <jansson.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>     // for errno
#include <string.h>    // for strerror()
#include <fcntl.h>      // for fcntl(), F_SETFL


#include "log.h"
#include "sm.h"
#include "os.h"
#include "memutil.h"
#include "unixcomm.h"

#define SOCKET_PATH "/tmp/aircnms/sm.sock"
#define MAX_UNIXCOMM_CLIENTS 10
#define MAX_LOG_BUFFER 1024

// Server state
typedef struct {
    unixcomm_handle_t server_handle;
    struct ev_loop *loop;
    ev_io server_watcher;
    unixcomm_handle_t *client_handles[MAX_UNIXCOMM_CLIENTS];
    ev_io *client_watchers[MAX_UNIXCOMM_CLIENTS];
    volatile bool running;
} server_state_t;

static server_state_t g_server = {0};

// Find free client slot
static int find_free_client_slot(void) {
    for (int i = 0; i < MAX_UNIXCOMM_CLIENTS; i++) {
        if (!g_server.client_handles[i]) {
            return i;
        }
    }
    return -1;
}

// Client I/O callback
static void client_cb(EV_P_ ev_io *w, int revents) {
    unixcomm_log_info("Entering client_cb");
    unixcomm_handle_t *client = (unixcomm_handle_t *)w->data;
    if (!client || client->fd < 0) {
        unixcomm_log_error("Client callback with invalid client data or fd");
        return;
    }

    if (revents & EV_READ) {
        unixcomm_log_info("Processing EV_READ event");
        unixcomm_message_t message = {0};

        unixcomm_log_info("Calling unixcomm_receive_message");
        if (!unixcomm_receive_message(client, &message)) {
            unixcomm_log_error("Failed to receive message");
            goto cleanup_client;
        }

        unixcomm_log_info("Message received, validating fields");
        // Validate message fields
        if (message.request.topic_len > 0 && !message.topic) {
            unixcomm_log_error("Invalid message: non-zero topic_len (%u) with null topic",
                message.request.topic_len);
            goto cleanup_message;
        }
        if (message.request.data_size > 0 && !message.data) {
            unixcomm_log_error("Invalid message: non-zero data_size (%u) with null data",
                message.request.data_size);
            goto cleanup_message;
        }
        if (message.request.topic_len > UNIXCOMM_MAX_TOPIC_LEN) {
            unixcomm_log_error("Invalid message: topic_len (%u) exceeds max (%u)",
                message.request.topic_len, UNIXCOMM_MAX_TOPIC_LEN);
            goto cleanup_message;
        }
        if (message.request.data_size > UNIXCOMM_MAX_DATA_SIZE) {
            unixcomm_log_error("Invalid message: data_size (%u) exceeds max (%u)",
                message.request.data_size, UNIXCOMM_MAX_DATA_SIZE);
            goto cleanup_message;
        }
        if (message.sender_pid == 0) {
            unixcomm_log_info("Warning: Received message with invalid PID 0");
        }

        unixcomm_log_info("Received message, data size: %zu", message.data_size);
        // Enqueue into SM queue and signal MQTT worker
        sm_item_t *si = CALLOC(1, sizeof(sm_item_t));
        if (!si) {
            unixcomm_log_error("Failed to allocate sm_item_t");
            goto cleanup_message;
        }
        // Fill request metadata
        si->req.data_type = message.request.data_type; 
        if (message.topic && message.request.topic_len) {
            si->topic = MALLOC(message.request.topic_len + 1);
            if (!si->topic) {
                unixcomm_log_error("Failed to allocate topic");
                sm_queue_item_free(si);
                goto cleanup_message;
            }
            memcpy(si->topic, message.topic, message.request.topic_len);
            si->topic[message.request.topic_len] = '\0';
        }
        if (message.data && message.data_size) {
            si->buf = MALLOC(message.data_size);
            if (!si->buf) {
                unixcomm_log_error("Failed to allocate data buffer");
                sm_queue_item_free(si);
                goto cleanup_message;
            }
            memcpy(si->buf, message.data, message.data_size);
            si->size = message.data_size;
        }
        {
            sm_response_t res = {0};
            if (!sm_queue_put(&si, &res)) {
                unixcomm_log_error("Queue put failed: error=%u", res.error);
                if (si) sm_queue_item_free(si);
            }
        }
cleanup_message:
        unixcomm_log_info("Cleaning up message");
        // Log pointers before freeing
        unixcomm_log_info("Message pointers: data=%p, topic=%p", message.data, message.topic);
        unixcomm_message_destroy(&message);
        return;

cleanup_client:
        unixcomm_log_info("Cleaning up client");
        for (int i = 0; i < MAX_UNIXCOMM_CLIENTS; i++) {
            if (g_server.client_handles[i] == client) {
                ev_io_stop(g_server.loop, g_server.client_watchers[i]);
                unixcomm_free(g_server.client_watchers[i]);
                unixcomm_close(client);
                unixcomm_free(client);
                g_server.client_handles[i] = NULL;
                g_server.client_watchers[i] = NULL;
                break;
            }
        }
    }
}

// Server accept callback
static void server_cb(EV_P_ ev_io *w, int revents) {
    if (!g_server.running) return;

    if (revents & EV_READ) {
        unixcomm_handle_t *client = unixcomm_malloc(sizeof(unixcomm_handle_t));
        if (!client) {
            unixcomm_log_error("Failed to allocate client handle");
            return;
        }

        if (unixcomm_accept(&g_server.server_handle, client)) {
            int slot = find_free_client_slot();
            if (slot >= 0) {
                ev_io *client_watcher = unixcomm_malloc(sizeof(ev_io));
                if (client_watcher) {
                    g_server.client_handles[slot] = client;
                    g_server.client_watchers[slot] = client_watcher;
                    client_watcher->data = client;
                    ev_io_init(client_watcher, client_cb, client->fd, EV_READ);
                    ev_io_start(g_server.loop, client_watcher);
                    unixcomm_log_info("New client connected");
                } else {
                    unixcomm_log_error("Failed to allocate client watcher");
                    unixcomm_close(client);
                    unixcomm_free(client);
                }
            } else {
                unixcomm_log_error("Max clients reached");
                unixcomm_close(client);
                unixcomm_free(client);
            }
        } else {
            unixcomm_free(client);
        }
    }
}

// Server initialization function
bool sm_unixcomm_server_init(void) {
    // Store event loop
    g_server.loop = EV_DEFAULT;

    // Initialize unixcomm
    unixcomm_global_config_t global_config = {
        .log_callback = NULL,
        .enable_debug = true,
        .enable_trace = false,
        .log_level = 1 // INFO level
    };

    if (!unixcomm_init(&global_config)) {
        printf("Failed to initialize unixcomm\n");
        return false;
    }

    // Initialize server configuration
    unixcomm_config_t config;
    unixcomm_config_init(&config);
    config.target_process = UNIXCOMM_PROCESS_SM; 
    unixcomm_config_set_socket_path(&config, SOCKET_PATH);
    unixcomm_config_set_timeout(&config, 5.0);
    unixcomm_config_set_max_pending(&config, 10);

    // Create server
    if (!unixcomm_server_create(&g_server.server_handle, &config)) {
        printf("Failed to create server\n");
        unixcomm_cleanup();
        return false;
    }

    // Initialize server state
    g_server.running = true;
    memset(g_server.client_handles, 0, sizeof(g_server.client_handles));
    memset(g_server.client_watchers, 0, sizeof(g_server.client_watchers));

    // Set up server watcher
    ev_io_init(&g_server.server_watcher, server_cb, g_server.server_handle.fd, EV_READ);
    ev_io_start(g_server.loop, &g_server.server_watcher);

    printf("Server initialized on %s\n", SOCKET_PATH);
    return true;
}

// Server cleanup function
void sm_unixcomm_server_cleanup(void) {
    if (!g_server.running) return;

    printf("Shutting down server...\n");

    // Close all client connections
    for (int i = 0; i < MAX_UNIXCOMM_CLIENTS; i++) {
        if (g_server.client_handles[i]) {
            ev_io_stop(g_server.loop, g_server.client_watchers[i]);
            unixcomm_free(g_server.client_watchers[i]);
            unixcomm_close(g_server.client_handles[i]);
            unixcomm_free(g_server.client_handles[i]);
            g_server.client_handles[i] = NULL;
            g_server.client_watchers[i] = NULL;
        }
    }

    // Close server
    ev_io_stop(g_server.loop, &g_server.server_watcher);
    unixcomm_close(&g_server.server_handle);
    unixcomm_cleanup();

    g_server.running = false;
    printf("Server stopped\n");
}

