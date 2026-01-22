#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <ev.h>
#include <wpa_ctrl.h>
#include <sys/socket.h>
#include <poll.h>
#include "report.h"
#include "log.h"
#include "netev.h"
#include "netev_vif_info.h"
#include "netev_client_events.h"

#define HOSTAPD_CTRL_DIR "/var/run/hostapd"
#define MAX_CTRLS 16
#define REPLY_BUF_SZ 4096
#define MAX_WORKERS 4
#define MAX_QUEUE 100
#define RECONNECT_CHECK_INTERVAL 1.0
#define RESCAN_INTERVAL 1.0  /* Periodic rescan every 1 seconds */

/* Event task types for worker threads */
typedef enum {
    EVENT_CONNECT,
    EVENT_DISCONNECT,
    EVENT_CONFIG
} event_type_t;

/* Task structure for worker queue */
typedef struct {
    event_type_t type;
    uint8_t mac[6];
    char ifname[64];
    char raw_event[REPLY_BUF_SZ];
} event_task_t;

/* Work queue for worker threads */
typedef struct {
    event_task_t queue[MAX_QUEUE];
    int head;
    int tail;
    int count;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int shutdown;
} work_queue_t;

/* libev watcher wrapper for each control socket */
typedef struct {
    ev_io watcher;
    struct wpa_ctrl *ctrl;
    char path[256];
    char ifname[64];  /* Interface name extracted from socket path */
    int active;       /* Flag to mark if watcher is active */
    time_t last_seen; /* Last time this socket was seen during rescan */
} ctrl_watcher_t;

static ctrl_watcher_t *g_watchers[MAX_CTRLS];
static int g_num_watchers = 0;
static work_queue_t g_work_queue;
static pthread_t g_workers[MAX_WORKERS];
static ev_timer g_reconnect_timer;
static ev_timer g_rescan_timer;
static const char *g_ctrl_dir = NULL;
static pthread_mutex_t g_reconnect_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_watcher_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Forward declarations */
static void hostapd_ev_cb(EV_P_ ev_io *w, int revents);
static int add_watcher_for_socket(const char *path);
static void rescan_control_sockets(void);

/* ========== Worker Thread Pool Functions ========== */

static void *worker_thread(void *arg) {
    (void)arg;

    while (1) {
        pthread_mutex_lock(&g_work_queue.mutex);

        /* Wait for work or shutdown signal */
        while (g_work_queue.count == 0 && !g_work_queue.shutdown) {
            pthread_cond_wait(&g_work_queue.cond, &g_work_queue.mutex);
        }

        /* Exit if shutdown and queue is empty */
        if (g_work_queue.shutdown && g_work_queue.count == 0) {
            pthread_mutex_unlock(&g_work_queue.mutex);
            break;
        }

        /* Dequeue task */
        event_task_t task = g_work_queue.queue[g_work_queue.head];
        g_work_queue.head = (g_work_queue.head + 1) % MAX_QUEUE;
        g_work_queue.count--;

        pthread_mutex_unlock(&g_work_queue.mutex);

        char mac_str[18] = {0};

        /* Process event */
        switch (task.type) {
            case EVENT_CONNECT:
                usleep(250 * 1000);
                
                netev_handle_client_connect(task.mac, task.ifname);
                break;
            case EVENT_DISCONNECT:
                usleep(250 * 1000);

                //char mac_str[18];
                snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                         task.mac[0], task.mac[1], task.mac[2],
                         task.mac[3], task.mac[4], task.mac[5]);

                // Check if client exists on OTHER interfaces (excluding the one reporting disconnect)
                // If check fails (error), send disconnect anyway (fail open)
                bool exists_on_other = sta_exists_on_other_iface(mac_str, task.ifname);

                if (exists_on_other) {
                    LOG(INFO, "hostapd_ev: Client %s still connected on another interface, ignoring disconnect from %s (roaming)",
                        mac_str, task.ifname);
                } else {
                    // Client not found on other interfaces - this is a real disconnect
                    netev_handle_client_disconnect(task.mac, task.ifname);
                }
                break;
            case EVENT_CONFIG:
                netev_send_vif_info();
                break;
        }
    }

    return NULL;
}

static int queue_event(event_task_t *task) {
    pthread_mutex_lock(&g_work_queue.mutex);

    if (g_work_queue.count >= MAX_QUEUE) {
        pthread_mutex_unlock(&g_work_queue.mutex);
        LOG(WARN, "hostapd_ev: work queue full, dropping event");
        return -1;
    }

    g_work_queue.queue[g_work_queue.tail] = *task;
    g_work_queue.tail = (g_work_queue.tail + 1) % MAX_QUEUE;
    g_work_queue.count++;

    pthread_cond_signal(&g_work_queue.cond);
    pthread_mutex_unlock(&g_work_queue.mutex);

    return 0;
}

/* ========== Helper Functions ========== */

static int is_socket(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISSOCK(st.st_mode);
}

static bool is_config_change_event(const char *event) {
    const char *config_events[] = {
        "AP-ENABLED",
        "AP-DISABLED",
        "AP-STA-POSSIBLE-PSK-MISMATCH",
        "INTERFACE-ENABLED",
        "INTERFACE-DISABLED",
        "ACS-STARTED",
        "ACS-COMPLETED",
        "ACS-FAILED",
        "DFS-CAC-START",
        "DFS-CAC-COMPLETED",
        "DFS-NOP-FINISHED",
        "AP-CSA-FINISHED",
        "WPS-NEW-AP-SETTINGS",
        "WPS-REG-SUCCESS",
        NULL
    };

    for (int i = 0; config_events[i] != NULL; i++) {
        if (strstr(event, config_events[i]) != NULL) {
            return true;
        }
    }
    return false;
}

static bool mac_str_to_bin(const char *mac_str, uint8_t *mac_bin) {
    unsigned int mac_values[6];

    if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x",
               &mac_values[0], &mac_values[1], &mac_values[2],
               &mac_values[3], &mac_values[4], &mac_values[5]) != 6) {
        return false;
    }

    for (int i = 0; i < 6; i++) {
        mac_bin[i] = (uint8_t)mac_values[i];
    }

    return true;
}

static bool extract_mac_address(const char *event, char *mac_out, size_t mac_len) {
    const char *mac_start = NULL;

    if (strstr(event, "AP-STA-CONNECTED")) {
        mac_start = strstr(event, "AP-STA-CONNECTED");
        if (mac_start) {
            mac_start += strlen("AP-STA-CONNECTED");
        }
    } else if (strstr(event, "AP-STA-DISCONNECTED")) {
        mac_start = strstr(event, "AP-STA-DISCONNECTED");
        if (mac_start) {
            mac_start += strlen("AP-STA-DISCONNECTED");
        }
    }

    if (!mac_start) return false;

    while (*mac_start == ' ' || *mac_start == '\t') {
        mac_start++;
    }

    int chars_copied = 0;
    for (int i = 0; i < (int)mac_len - 1 && mac_start[i] != '\0'; i++) {
        if ((mac_start[i] >= '0' && mac_start[i] <= '9') ||
            (mac_start[i] >= 'a' && mac_start[i] <= 'f') ||
            (mac_start[i] >= 'A' && mac_start[i] <= 'F') ||
            mac_start[i] == ':') {
            mac_out[chars_copied++] = mac_start[i];
        } else {
            break;
        }
    }

    mac_out[chars_copied] = '\0';
    return (chars_copied == 17);
}

static bool extract_ifname(const char *event, char *ifname_out, size_t ifname_len) {
    const char *ifname_start = strstr(event, "IFNAME=");
    if (!ifname_start) return false;

    ifname_start += strlen("IFNAME=");

    int chars_copied = 0;
    for (int i = 0; i < (int)ifname_len - 1 && ifname_start[i] != '\0'; i++) {
        if (ifname_start[i] == ' ' || ifname_start[i] == '\t' || ifname_start[i] == '<') {
            break;
        }
        ifname_out[chars_copied++] = ifname_start[i];
    }

    ifname_out[chars_copied] = '\0';
    return (chars_copied > 0);
}

/* Extract interface name from socket path (e.g., /var/run/hostapd/wlan0 -> wlan0) */
static void extract_ifname_from_path(const char *path, char *ifname, size_t ifname_len) {
    const char *last_slash = strrchr(path, '/');
    if (last_slash && *(last_slash + 1) != '\0') {
        strncpy(ifname, last_slash + 1, ifname_len - 1);
        ifname[ifname_len - 1] = '\0';
    } else {
        ifname[0] = '\0';
    }
}

/* ========== Socket Health Check ========== */

static bool is_socket_alive(ctrl_watcher_t *cw) {
    if (!cw || !cw->ctrl || !cw->active) {
        return false;
    }

    int fd = wpa_ctrl_get_fd(cw->ctrl);
    if (fd < 0) {
        return false;
    }

    struct pollfd pfd = {
        .fd = fd,
        .events = POLLIN | POLLERR | POLLHUP,
        .revents = 0
    };

    /* Use poll with zero timeout to check socket state without blocking */
    int ret = poll(&pfd, 1, 0);
    if (ret < 0) {
        LOG(ERR, "hostapd_ev: poll failed on fd %d: %s", fd, strerror(errno));
        return false;
    }

    if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
        LOG(WARN, "hostapd_ev: Socket %s (fd=%d) is dead (revents=0x%x)",
            cw->path, fd, pfd.revents);
        return false;
    }

    return true;
}

/* ========== Reconnection Logic ========== */

/* Forward declaration for use in reconnect_watcher */
static void hostapd_ev_cb(EV_P_ ev_io *w, int revents);

static int reconnect_watcher(ctrl_watcher_t *cw) {
    if (!cw) {
        return -1;
    }

    LOG(INFO, "hostapd_ev: Attempting to reconnect to %s", cw->path);

    /* Stop the old watcher */
    ev_io_stop(EV_DEFAULT, &cw->watcher);

    /* Close old control connection */
    if (cw->ctrl) {
        wpa_ctrl_detach(cw->ctrl);
        wpa_ctrl_close(cw->ctrl);
        cw->ctrl = NULL;
    }

    /* Check if socket still exists */
    if (!is_socket(cw->path)) {
        LOG(WARN, "hostapd_ev: Socket %s no longer exists", cw->path);
        cw->active = 0;
        return -1;
    }

    /* Open new control connection */
    struct wpa_ctrl *ctrl = wpa_ctrl_open(cw->path);
    if (!ctrl) {
        LOG(ERR, "hostapd_ev: Failed to reopen control socket %s: %s",
            cw->path, strerror(errno));
        cw->active = 0;
        return -1;
    }

    if (wpa_ctrl_attach(ctrl) != 0) {
        LOG(ERR, "hostapd_ev: Failed to reattach to control socket %s: %s",
            cw->path, strerror(errno));
        wpa_ctrl_close(ctrl);
        cw->active = 0;
        return -1;
    }

    cw->ctrl = ctrl;
    cw->active = 1;
    cw->last_seen = time(NULL);

    /* Re-register with libev */
    int fd = wpa_ctrl_get_fd(ctrl);
    ev_io_init(&cw->watcher, hostapd_ev_cb, fd, EV_READ);
    ev_io_start(EV_DEFAULT, &cw->watcher);

    LOG(INFO, "hostapd_ev: Successfully reconnected to %s (fd=%d)", cw->path, fd);

    /* Trigger config event to update interface info */
    event_task_t task = { .type = EVENT_CONFIG };
    strncpy(task.ifname, cw->ifname, sizeof(task.ifname) - 1);
    queue_event(&task);

    return 0;
}

static void reconnect_timer_cb(EV_P_ ev_timer *timer, int revents) {
    (void)loop;
    (void)revents;
    (void)timer;

    pthread_mutex_lock(&g_reconnect_mutex);

    for (int i = 0; i < g_num_watchers; i++) {
        if (g_watchers[i] && g_watchers[i]->active && !is_socket_alive(g_watchers[i])) {
            LOG(WARN, "hostapd_ev: Detected dead socket, attempting reconnection");
            reconnect_watcher(g_watchers[i]);
        }
    }

    pthread_mutex_unlock(&g_reconnect_mutex);
}

/* ========== Periodic Directory Scanning ========== */

static void rescan_timer_cb(EV_P_ ev_timer *timer, int revents) {
    (void)loop;
    (void)revents;
    (void)timer;

    rescan_control_sockets();
}

/* ========== Socket Management ========== */

static ctrl_watcher_t* find_watcher_by_path(const char *path) {
    for (int i = 0; i < g_num_watchers; i++) {
        if (g_watchers[i] && strcmp(g_watchers[i]->path, path) == 0) {
            return g_watchers[i];
        }
    }
    return NULL;
}

static void remove_stale_watchers(time_t current_time) {
    /* Remove watchers for sockets that no longer exist */
    for (int i = 0; i < g_num_watchers; i++) {
        if (g_watchers[i] && g_watchers[i]->last_seen < current_time) {
            /* Socket was not seen in latest scan - remove it */
            if (!is_socket(g_watchers[i]->path)) {
                LOG(INFO, "hostapd_ev: Removing watcher for disappeared socket %s",
                    g_watchers[i]->path);

                ev_io_stop(EV_DEFAULT, &g_watchers[i]->watcher);

                if (g_watchers[i]->ctrl) {
                    wpa_ctrl_detach(g_watchers[i]->ctrl);
                    wpa_ctrl_close(g_watchers[i]->ctrl);
                }

                free(g_watchers[i]);

                /* Shift remaining watchers down */
                for (int j = i; j < g_num_watchers - 1; j++) {
                    g_watchers[j] = g_watchers[j + 1];
                }
                g_watchers[g_num_watchers - 1] = NULL;
                g_num_watchers--;
                i--;  /* Check this index again since we shifted */

                /* Trigger config event to update interface list */
                event_task_t task = { .type = EVENT_CONFIG };
                queue_event(&task);
            }
        }
    }
}

static int add_watcher_for_socket(const char *path) {
    pthread_mutex_lock(&g_watcher_mutex);

    /* CHANGE 1: Extract interface name and only allow "global" */
    char ifname_check[64];
    extract_ifname_from_path(path, ifname_check, sizeof(ifname_check));
    if (strcmp(ifname_check, "global") != 0) {
        pthread_mutex_unlock(&g_watcher_mutex);
        return -1;  /* Skip non-global sockets */
    }

    /* Check if already watching this socket */
    ctrl_watcher_t *existing = find_watcher_by_path(path);
    if (existing) {
        existing->last_seen = time(NULL);
        if (existing->active) {
            pthread_mutex_unlock(&g_watcher_mutex);
            return 0;  /* Already watching and active */
        } else {
            /* Try to reactivate dead watcher */
            int result = reconnect_watcher(existing);
            pthread_mutex_unlock(&g_watcher_mutex);
            return result;
        }
    }

    if (g_num_watchers >= MAX_CTRLS) {
        LOG(ERR, "hostapd_ev: Maximum number of watchers reached");
        pthread_mutex_unlock(&g_watcher_mutex);
        return -1;
    }

    if (!is_socket(path)) {
        pthread_mutex_unlock(&g_watcher_mutex);
        return -1;
    }

    struct wpa_ctrl *ctrl = wpa_ctrl_open(path);
    if (!ctrl) {
        LOG(ERR, "hostapd_ev: Failed to open control socket %s: %s", path, strerror(errno));
        pthread_mutex_unlock(&g_watcher_mutex);
        return -1;
    }

    if (wpa_ctrl_attach(ctrl) != 0) {
        LOG(ERR, "hostapd_ev: Failed to attach to control socket %s: %s", path, strerror(errno));
        wpa_ctrl_close(ctrl);
        pthread_mutex_unlock(&g_watcher_mutex);
        return -1;
    }

    ctrl_watcher_t *cw = malloc(sizeof(ctrl_watcher_t));
    if (!cw) {
        LOG(ERR, "hostapd_ev: Memory allocation failed");
        wpa_ctrl_detach(ctrl);
        wpa_ctrl_close(ctrl);
        pthread_mutex_unlock(&g_watcher_mutex);
        return -1;
    }

    memset(cw, 0, sizeof(ctrl_watcher_t));
    cw->ctrl = ctrl;
    cw->active = 1;
    cw->last_seen = time(NULL);
    strncpy(cw->path, path, sizeof(cw->path) - 1);
    extract_ifname_from_path(path, cw->ifname, sizeof(cw->ifname));

    int fd = wpa_ctrl_get_fd(ctrl);
    ev_io_init(&cw->watcher, hostapd_ev_cb, fd, EV_READ);
    ev_io_start(EV_DEFAULT, &cw->watcher);

    g_watchers[g_num_watchers++] = cw;

    LOG(INFO, "hostapd_ev: Added watcher for %s (interface=%s, fd=%d)",
        path, cw->ifname, fd);

    pthread_mutex_unlock(&g_watcher_mutex);

    /* Trigger config event for new interface */
    event_task_t task = { .type = EVENT_CONFIG };
    strncpy(task.ifname, cw->ifname, sizeof(task.ifname) - 1);
    queue_event(&task);

    return 0;
}

static void rescan_control_sockets(void) {
    if (!g_ctrl_dir) {
        return;
    }

    pthread_mutex_lock(&g_watcher_mutex);

    time_t scan_time = time(NULL);

    DIR *d = opendir(g_ctrl_dir);
    if (!d) {
        LOG(ERR, "hostapd_ev: Cannot open directory %s: %s", g_ctrl_dir, strerror(errno));
        pthread_mutex_unlock(&g_watcher_mutex);
        return;
    }

    struct dirent *de;
    int new_sockets = 0;

    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') {
            continue;
        }

        /* CHANGE 2: Only process the "global" socket, skip all others */
        if (strcmp(de->d_name, "global") != 0) {
            continue;
        }

        char path[256];
        int written = snprintf(path, sizeof(path), "%s/%s", g_ctrl_dir, de->d_name);

        if (written < 0 || (size_t)written >= sizeof(path)) {
            LOG(WARN, "hostapd_ev: Path too long or error constructing path");
            continue;
        }

        if (is_socket(path)) {
            ctrl_watcher_t *existing = find_watcher_by_path(path);
            if (existing) {
                existing->last_seen = scan_time;
            } else {
                pthread_mutex_unlock(&g_watcher_mutex);
                if (add_watcher_for_socket(path) == 0) {
                    new_sockets++;
                }
                pthread_mutex_lock(&g_watcher_mutex);
            }
        }
    }

    closedir(d);

    /* Remove watchers for sockets that disappeared */
    remove_stale_watchers(scan_time);

    pthread_mutex_unlock(&g_watcher_mutex);

    if (new_sockets > 0) {
        LOG(INFO, "hostapd_ev: Added %d new socket watcher(s)", new_sockets);
    }
}

/* ========== libev Callback ========== */

static void hostapd_ev_cb(EV_P_ ev_io *w, int revents) {
    (void)loop;

    ctrl_watcher_t *cw = (ctrl_watcher_t *)w;

    /* Check for socket errors */
    if (revents & EV_ERROR) {
        LOG(ERR, "hostapd_ev: Socket error on %s (fd=%d), revents=0x%x",
            cw->path, w->fd, revents);
        /* Don't try to reconnect here - let the timer handle it */
        return;
    }

    if (!(revents & EV_READ)) {
        LOG(WARN, "hostapd_ev: Unexpected revents=0x%x on %s", revents, cw->path);
        return;
    }

    /* Drain all pending events from this socket */
    while (1) {
        char buf[REPLY_BUF_SZ];
        size_t len = sizeof(buf) - 1;

        int ret = wpa_ctrl_recv(cw->ctrl, buf, &len);
        if (ret != 0) {
            /* Check if this is a socket error (not just no data) */
            if (ret < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                LOG(ERR, "hostapd_ev: wpa_ctrl_recv failed on %s: %s (errno=%d)",
                    cw->path, strerror(errno), errno);
                /* Socket is likely dead - timer will handle reconnection */
            }
            break;  /* No more events or error */
        }

        buf[len] = '\0';
        printf("hostapd_ev: %s: %s\n", cw->path, buf);

        /* Parse and queue events for worker threads */
        if (strstr(buf, "AP-STA-CONNECTED")) {
            event_task_t task = { .type = EVENT_CONNECT };
            char mac_str[32] = {0};

            if (extract_mac_address(buf, mac_str, sizeof(mac_str)) &&
                mac_str_to_bin(mac_str, task.mac) &&
                extract_ifname(buf, task.ifname, sizeof(task.ifname))) {

                strncpy(task.raw_event, buf, sizeof(task.raw_event) - 1);
                printf("hostapd_ev: Queueing connect event - MAC: %s, Interface: %s\n",
                       mac_str, task.ifname);
                queue_event(&task);
            }
        }
        else if (strstr(buf, "AP-STA-DISCONNECTED")) {
            event_task_t task = { .type = EVENT_DISCONNECT };
            char mac_str[32] = {0};

            if (extract_mac_address(buf, mac_str, sizeof(mac_str)) &&
                mac_str_to_bin(mac_str, task.mac) &&
                extract_ifname(buf, task.ifname, sizeof(task.ifname))) {

                strncpy(task.raw_event, buf, sizeof(task.raw_event) - 1);
                printf("hostapd_ev: Queueing disconnect event - MAC: %s\n", mac_str);
                queue_event(&task);
            }
        }
        else if (is_config_change_event(buf)) {
            event_task_t task = { .type = EVENT_CONFIG };
            strncpy(task.raw_event, buf, sizeof(task.raw_event) - 1);
            printf("hostapd_ev: Queueing config change event\n");
            queue_event(&task);
        }
    }
}

/* ========== Public API ========== */

int hostapd_events_start(const char *ctrl_dir) {
    const char *dir = ctrl_dir ? ctrl_dir : HOSTAPD_CTRL_DIR;

    /* Store control directory for reconnection */
    g_ctrl_dir = dir;

    /* Initialize work queue */
    memset(&g_work_queue, 0, sizeof(g_work_queue));
    pthread_mutex_init(&g_work_queue.mutex, NULL);
    pthread_cond_init(&g_work_queue.cond, NULL);

    /* Start worker threads */
    for (int i = 0; i < MAX_WORKERS; i++) {
        int rc = pthread_create(&g_workers[i], NULL, worker_thread, NULL);
        if (rc != 0) {
            LOG(WARN, "hostapd_ev: Failed to create worker thread %d: %s", i, strerror(rc));
        }
    }

    /* Initial scan for existing sockets */
    rescan_control_sockets();

    if (g_num_watchers == 0) {
        LOG(WARN, "hostapd_ev: No hostapd control sockets found in %s", dir);
    }

    /* Start periodic rescan timer */
    ev_timer_init(&g_rescan_timer, rescan_timer_cb, RESCAN_INTERVAL, RESCAN_INTERVAL);
    ev_timer_start(EV_DEFAULT, &g_rescan_timer);
    LOG(INFO, "hostapd_ev: Started periodic rescan timer (interval=%.1fs)", RESCAN_INTERVAL);

    /* Start reconnection timer */
    ev_timer_init(&g_reconnect_timer, reconnect_timer_cb, RECONNECT_CHECK_INTERVAL, RECONNECT_CHECK_INTERVAL);
    ev_timer_start(EV_DEFAULT, &g_reconnect_timer);
    LOG(INFO, "hostapd_ev: Started reconnection timer (interval=%.1fs)", RECONNECT_CHECK_INTERVAL);

    return 0;
}

void hostapd_events_stop(void) {
    /* Stop timers */
    ev_timer_stop(EV_DEFAULT, &g_reconnect_timer);
    ev_timer_stop(EV_DEFAULT, &g_rescan_timer);
    
    pthread_mutex_lock(&g_reconnect_mutex);
    pthread_mutex_lock(&g_watcher_mutex);
    
    /* Stop all watchers */
    for (int i = 0; i < g_num_watchers; i++) {
        if (g_watchers[i]) {
            ev_io_stop(EV_DEFAULT, &g_watchers[i]->watcher);
            
            if (g_watchers[i]->ctrl) {
                wpa_ctrl_detach(g_watchers[i]->ctrl);
                wpa_ctrl_close(g_watchers[i]->ctrl);
            }
            
            free(g_watchers[i]);
            g_watchers[i] = NULL;
        }
    }
    g_num_watchers = 0;
    
    pthread_mutex_unlock(&g_watcher_mutex);
    pthread_mutex_unlock(&g_reconnect_mutex);
    
    /* Shutdown worker threads */
    pthread_mutex_lock(&g_work_queue.mutex);
    g_work_queue.shutdown = 1;
    pthread_cond_broadcast(&g_work_queue.cond);
    pthread_mutex_unlock(&g_work_queue.mutex);
    
    /* Wait for workers to finish */
    for (int i = 0; i < MAX_WORKERS; i++) {
        pthread_join(g_workers[i], NULL);
    }
    
    pthread_mutex_destroy(&g_work_queue.mutex);
    pthread_cond_destroy(&g_work_queue.cond);
    
    LOG(INFO, "hostapd_ev: Stopped");
}
