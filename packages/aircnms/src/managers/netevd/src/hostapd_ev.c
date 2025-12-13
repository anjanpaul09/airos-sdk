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
#include "report.h"
#include "netev.h"
#include "netev_vif_info.h"
#include "netev_client_events.h"

#define HOSTAPD_CTRL_DIR "/var/run/hostapd"
#define MAX_CTRLS 16
#define REPLY_BUF_SZ 4096
#define MAX_WORKERS 4
#define MAX_QUEUE 100

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
} ctrl_watcher_t;

static ctrl_watcher_t *g_watchers[MAX_CTRLS];
static int g_num_watchers = 0;
static work_queue_t g_work_queue;
static pthread_t g_workers[MAX_WORKERS];

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
        
        /* Process event (potentially blocking operations) */
        switch (task.type) {
            case EVENT_CONNECT:
                netev_handle_client_connect(task.mac, task.ifname);
                break;
            case EVENT_DISCONNECT:
                usleep(100 * 1000); 

                char mac_str[18];
                snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                         task.mac[0], task.mac[1], task.mac[2],
                         task.mac[3], task.mac[4], task.mac[5]);

                if (!sta_exists_on_any_iface(mac_str)) {
                    netev_handle_client_disconnect(task.mac, task.ifname);
                } else {
                    printf("hostapd_ev: Client %s still connected, ignoring disconnect\n",
                           mac_str);
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
        printf("hostapd_ev: work queue full, dropping event\n");
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

/* ========== libev Callback ========== */

static void hostapd_ev_cb(EV_P_ ev_io *w, int revents) {
    (void)loop;
    (void)revents;
    
    ctrl_watcher_t *cw = (ctrl_watcher_t *)w;
    
    /* Drain all pending events from this socket */
    while (1) {
        char buf[REPLY_BUF_SZ];
        size_t len = sizeof(buf) - 1;
        
        int ret = wpa_ctrl_recv(cw->ctrl, buf, &len);
        if (ret != 0) {
            break;  /* No more events */
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
            } else {
                printf("hostapd_ev: Failed to parse AP-STA-CONNECTED event\n");
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
                queue_event(&task);  // ← Queue immediately, NO usleep here!
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
    
    /* Initialize work queue */
    memset(&g_work_queue, 0, sizeof(g_work_queue));
    pthread_mutex_init(&g_work_queue.mutex, NULL);
    pthread_cond_init(&g_work_queue.cond, NULL);
    
    /* Start worker threads */
    for (int i = 0; i < MAX_WORKERS; i++) {
        int rc = pthread_create(&g_workers[i], NULL, worker_thread, NULL);
        if (rc != 0) {
            printf("hostapd_ev: Failed to create worker thread %d: %s\n", i, strerror(rc));
            /* Continue with fewer workers */
        }
    }
    
    /* Scan for hostapd control sockets */
    DIR *d = opendir(dir);
    if (!d) {
        printf("hostapd_ev: Cannot open directory %s: %s\n", dir, strerror(errno));
        return -1;
    }
    
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        /* Only attach to the global socket */
        if (strcmp(de->d_name, "global") != 0)
            continue;
        
        char path[256];
        size_t dir_len = strlen(dir);
        size_t name_len = strlen(de->d_name);
        
        if (dir_len + 1 + name_len + 1 > sizeof(path)) {
            continue;
        }
        
        memcpy(path, dir, dir_len);
        path[dir_len] = '/';
        memcpy(path + dir_len + 1, de->d_name, name_len);
        path[dir_len + 1 + name_len] = '\0';
        
        if (!is_socket(path))
            continue;
        
        struct wpa_ctrl *ctrl = wpa_ctrl_open(path);
        if (!ctrl) {
            printf("hostapd_ev: Failed to open control socket %s\n", path);
            continue;
        }
        
        if (wpa_ctrl_attach(ctrl) != 0) {
            printf("hostapd_ev: Failed to attach to control socket %s\n", path);
            wpa_ctrl_close(ctrl);
            continue;
        }
        
        /* Create watcher */
        ctrl_watcher_t *cw = malloc(sizeof(ctrl_watcher_t));
        if (!cw) {
            printf("hostapd_ev: Memory allocation failed\n");
            wpa_ctrl_detach(ctrl);
            wpa_ctrl_close(ctrl);
            continue;
        }
        
        cw->ctrl = ctrl;
        strncpy(cw->path, path, sizeof(cw->path) - 1);
        cw->path[sizeof(cw->path) - 1] = '\0';
        
        /* Register with libev using EV_DEFAULT */
        int fd = wpa_ctrl_get_fd(ctrl);
        ev_io_init(&cw->watcher, hostapd_ev_cb, fd, EV_READ);
        ev_io_start(EV_DEFAULT, &cw->watcher);
        
        g_watchers[g_num_watchers++] = cw;
        
        LOG(INFO,"hostapd_ev: Attached to global control (libev): %s (fd=%d)\n", path, fd);
        break;
    }
    
    closedir(d);
    
    if (g_num_watchers == 0) {
        printf("hostapd_ev: No hostapd control sockets found in %s\n", dir);
        return -1;
    }
    
    return 0;
}

void hostapd_events_stop(void) {
    /* Stop all libev watchers */
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
    
    /* Shutdown worker threads */
    pthread_mutex_lock(&g_work_queue.mutex);
    g_work_queue.shutdown = 1;
    pthread_cond_broadcast(&g_work_queue.cond);
    pthread_mutex_unlock(&g_work_queue.mutex);
   
    /* Give workers time to finish */
    usleep(500000);  // 500ms grace period

    pthread_mutex_destroy(&g_work_queue.mutex);
    pthread_cond_destroy(&g_work_queue.cond);
    
    printf("hostapd_ev: Stopped\n");
}
