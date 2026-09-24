#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <ev.h>

#include "wpa_ctrl.h"
#include "log.h"
#include "stamonitord.h"
#include "stamonitord_vif_info.h"
#include "stamonitord_client_events.h"

/* ================= CONFIG ================= */

#define HOSTAPD_DIR "/var/run/hostapd"
#define MAX_IFACES 16
#define MAX_WORKERS 4
#define MAX_QUEUE 128
#define REPLY_BUF_SZ 4096

/* ================= DATA STRUCTURES ================= */

typedef enum {
    EVENT_CONNECT,
    EVENT_DISCONNECT,
    EVENT_CONFIG
} event_type_t;

typedef struct {
    event_type_t type;
    uint8_t mac[6];
    char ifname[64];
    char raw_event[REPLY_BUF_SZ];
} event_task_t;

typedef struct {
    event_task_t queue[MAX_QUEUE];
    int head, tail, count;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int shutdown;
} work_queue_t;

typedef struct {
    char path[256];
    char ifname[64];
    struct wpa_ctrl *ctrl;
    ev_io watcher;
    int active;
} iface_ctrl_t;

/* ================= GLOBALS ================= */

static iface_ctrl_t g_ifaces[MAX_IFACES];
static int g_iface_count = 0;

static work_queue_t g_queue;
static pthread_t g_workers[MAX_WORKERS];

/* ================= WORKER ================= */

static void *worker_thread(void *arg)
{
    (void)arg;

    while (1) {
        pthread_mutex_lock(&g_queue.mutex);

        while (g_queue.count == 0 && !g_queue.shutdown)
            pthread_cond_wait(&g_queue.cond, &g_queue.mutex);

        if (g_queue.shutdown && g_queue.count == 0) {
            pthread_mutex_unlock(&g_queue.mutex);
            break;
        }

        event_task_t task = g_queue.queue[g_queue.head];
        g_queue.head = (g_queue.head + 1) % MAX_QUEUE;
        g_queue.count--;

        pthread_mutex_unlock(&g_queue.mutex);

        switch (task.type) {
        case EVENT_CONNECT:
            LOG(INFO, "CONNECT: %s", task.raw_event);
            break;

        case EVENT_DISCONNECT:
            LOG(INFO, "DISCONNECT: %s", task.raw_event);
            break;

        case EVENT_CONFIG:
            LOG(INFO, "CONFIG CHANGE");
            stamonitord_send_vif_info();
            break;
        }
    }

    return NULL;
}

static int queue_event(event_task_t *task)
{
    pthread_mutex_lock(&g_queue.mutex);

    if (g_queue.count >= MAX_QUEUE) {
        pthread_mutex_unlock(&g_queue.mutex);
        return -1;
    }

    g_queue.queue[g_queue.tail] = *task;
    g_queue.tail = (g_queue.tail + 1) % MAX_QUEUE;
    g_queue.count++;

    pthread_cond_signal(&g_queue.cond);
    pthread_mutex_unlock(&g_queue.mutex);

    return 0;
}

/* ================= PARSER ================= */

static int is_config_event(const char *e)
{
    return strstr(e, "AP-ENABLED") ||
           strstr(e, "AP-DISABLED") ||
           strstr(e, "ACS-") ||
           strstr(e, "DFS-");
}

static void dispatch_event(const char *buf)
{
    event_task_t task = {0};

    if (is_config_event(buf)) {
        task.type = EVENT_CONFIG;
    } else if (strstr(buf, "AP-STA-CONNECTED")) {
        task.type = EVENT_CONNECT;
    } else if (strstr(buf, "AP-STA-DISCONNECTED")) {
        task.type = EVENT_DISCONNECT;
    } else {
        return;
    }

    strncpy(task.raw_event, buf, sizeof(task.raw_event) - 1);
    queue_event(&task);
}

/* ================= LIBEV CALLBACK ================= */

static void hostapd_ev_cb(EV_P_ ev_io *w, int revents)
{
    iface_ctrl_t *ic = (iface_ctrl_t *)w->data;

    if (!(revents & EV_READ))
        return;

    while (1) {
        char buf[REPLY_BUF_SZ];
        size_t len = sizeof(buf) - 1;

        if (wpa_ctrl_recv(ic->ctrl, buf, &len) != 0)
            break;

        if (len == 0)
            break;

        buf[len] = '\0';

        printf("[%s] %s\n", ic->ifname, buf);

        dispatch_event(buf);
    }
}

/* ================= DISCOVERY ================= */

static int discover_ifaces(void)
{
    DIR *d = opendir(HOSTAPD_DIR);
    if (!d) {
        perror("opendir");
        return -1;
    }

    struct dirent *de;
    int count = 0;

    while ((de = readdir(d))) {
        if (de->d_name[0] == '.')
            continue;

        if (strcmp(de->d_name, "global") == 0)
            continue;

        if (count >= MAX_IFACES)
            break;

        int ret = snprintf(g_ifaces[count].path,
                        sizeof(g_ifaces[count].path),
                        "%s/%s", HOSTAPD_DIR, de->d_name);

        if (ret < 0 || ret >= (int)sizeof(g_ifaces[count].path)) {
            LOG(WARN, "Path too long, skipping: %s/%s",
                HOSTAPD_DIR, de->d_name);
            continue;
        }

        strncpy(g_ifaces[count].ifname,
                de->d_name,
                sizeof(g_ifaces[count].ifname) - 1);

        g_ifaces[count].active = 0;
        count++;
    }

    closedir(d);

    g_iface_count = count;
    return count;
}

/* ================= START WATCHERS ================= */

static void start_watchers(void)
{
    for (int i = 0; i < g_iface_count; i++) {

        iface_ctrl_t *ic = &g_ifaces[i];

        ic->ctrl = wpa_ctrl_open(ic->path);
        if (!ic->ctrl)
            continue;

        if (wpa_ctrl_attach(ic->ctrl) != 0) {
            wpa_ctrl_close(ic->ctrl);
            continue;
        }

        int fd = wpa_ctrl_get_fd(ic->ctrl);
        fcntl(fd, F_SETFL, O_NONBLOCK);

        ev_io_init(&ic->watcher, hostapd_ev_cb, fd, EV_READ);
        ic->watcher.data = ic;

        ev_io_start(EV_DEFAULT, &ic->watcher);

        ic->active = 1;

        printf("Watching %s\n", ic->ifname);
    }
}

/* ================= STOP WATCHERS ================= */

static void stop_watchers(void)
{
    for (int i = 0; i < g_iface_count; i++) {

        iface_ctrl_t *ic = &g_ifaces[i];

        if (!ic->active)
            continue;

        ev_io_stop(EV_DEFAULT, &ic->watcher);

        wpa_ctrl_detach(ic->ctrl);
        wpa_ctrl_close(ic->ctrl);

        ic->ctrl = NULL;
        ic->active = 0;
    }
}

/* ================= PUBLIC API ================= */

int hostapd_events_start(const char *ctrl_dir)
{
    (void)ctrl_dir;

    printf(">>> hostapd_events_start called\n");

    memset(&g_queue, 0, sizeof(g_queue));
    pthread_mutex_init(&g_queue.mutex, NULL);
    pthread_cond_init(&g_queue.cond, NULL);

    for (int i = 0; i < MAX_WORKERS; i++)
        pthread_create(&g_workers[i], NULL, worker_thread, NULL);

    if (discover_ifaces() <= 0) {
        printf("No interfaces found\n");
        return -1;
    }

    start_watchers();

    return 0;
}

void hostapd_events_stop(void)
{
    stop_watchers();

    pthread_mutex_lock(&g_queue.mutex);
    g_queue.shutdown = 1;
    pthread_cond_broadcast(&g_queue.cond);
    pthread_mutex_unlock(&g_queue.mutex);

    for (int i = 0; i < MAX_WORKERS; i++)
        pthread_join(g_workers[i], NULL);

    pthread_mutex_destroy(&g_queue.mutex);
    pthread_cond_destroy(&g_queue.cond);

    LOG(INFO, "hostapd_ev stopped");
}