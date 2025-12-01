#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <dirent.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <wpa_ctrl.h>
#include "report.h"
#include "netev_vif_info.h"

#define HOSTAPD_CTRL_DIR "/var/run/hostapd"
#define MAX_CTRLS 16
#define REPLY_BUF_SZ 4096

struct hostapd_ctrl_entry {
	char path[256];
	struct wpa_ctrl *ctrl;
	int fd;
};

static struct hostapd_ctrl_entry g_ctrls[MAX_CTRLS];
static int g_num_ctrls = 0;
static pthread_t g_thread;
static int g_running = 0;

static int is_socket(const char *path)
{
	struct stat st;
	if (stat(path, &st) != 0) return 0;
	return S_ISSOCK(st.st_mode);
}
#if 0
static void hostapd_scan_dir(const char *dir)
{
	DIR *d = opendir(dir);
	struct dirent *de;
	if (!d) return;
	while ((de = readdir(d)) != NULL) {
		if (de->d_name[0] == '.') continue;
		if (g_num_ctrls >= MAX_CTRLS) break;
		char path[256];
		size_t dir_len = strlen(dir);
		size_t name_len = strlen(de->d_name);
		size_t need = dir_len + 1 + name_len + 1; /* dir + '/' + name + NUL */
		if (need > sizeof(path)) {
			/* skip overly long entries to avoid truncation */
			continue;
		}
		/* Build path without snprintf to avoid truncation warnings */
		memcpy(path, dir, dir_len);
		path[dir_len] = '/';
		memcpy(path + dir_len + 1, de->d_name, name_len);
		path[dir_len + 1 + name_len] = '\0';
		if (!is_socket(path)) continue;
		/* Open control */
		struct wpa_ctrl *ctrl = wpa_ctrl_open(path);
		if (!ctrl) continue;
		if (wpa_ctrl_attach(ctrl) != 0) {
			wpa_ctrl_close(ctrl);
			continue;
		}
		g_ctrls[g_num_ctrls].ctrl = ctrl;
		g_ctrls[g_num_ctrls].fd = wpa_ctrl_get_fd(ctrl);
		strncpy(g_ctrls[g_num_ctrls].path, path, sizeof(g_ctrls[g_num_ctrls].path)-1);
		g_ctrls[g_num_ctrls].path[sizeof(g_ctrls[g_num_ctrls].path)-1] = '\0';
		printf("hostapd_ev: attached to %s\n", g_ctrls[g_num_ctrls].path);
		g_num_ctrls++;
	}
	closedir(d);
}
#endif

static void hostapd_scan_dir(const char *dir)
{
    DIR *d = opendir(dir);
    struct dirent *de;
    if (!d) return;

    while ((de = readdir(d)) != NULL) {

        /* Only attach to the global socket */
        if (strcmp(de->d_name, "global") != 0)
            continue;

        char path[256];
        size_t dir_len  = strlen(dir);
        size_t name_len = strlen(de->d_name);

        /* Check required size: dir + '/' + name + '\0' */
        if (dir_len + 1 + name_len + 1 > sizeof(path)) {
            /* Skip (would overflow) */
            continue;
        }

        /* Build path manually */
        memcpy(path, dir, dir_len);
        path[dir_len] = '/';
        memcpy(path + dir_len + 1, de->d_name, name_len);
        path[dir_len + 1 + name_len] = '\0';

        if (!is_socket(path))
            continue;

        struct wpa_ctrl *ctrl = wpa_ctrl_open(path);
        if (!ctrl)
            continue;

        if (wpa_ctrl_attach(ctrl) != 0) {
            wpa_ctrl_close(ctrl);
            continue;
        }

        g_ctrls[0].ctrl = ctrl;
        g_ctrls[0].fd   = wpa_ctrl_get_fd(ctrl);
        strncpy(g_ctrls[0].path, path, sizeof(g_ctrls[0].path) - 1);
        g_ctrls[0].path[sizeof(g_ctrls[0].path) - 1] = '\0';

        printf("hostapd_ev: attached to global control: %s\n", g_ctrls[0].path);

        g_num_ctrls = 1;
        break;
    }

    closedir(d);
}

/* Helper function to check if event is a configuration change */
static bool is_config_change_event(const char *event)
{
    /* Configuration change events that affect VIF info */
    const char *config_events[] = {
        "AP-ENABLED",           // AP interface enabled
        "AP-DISABLED",          // AP interface disabled
        "AP-STA-POSSIBLE-PSK-MISMATCH",  // Security config issue
        "INTERFACE-ENABLED",    // Interface brought up
        "INTERFACE-DISABLED",   // Interface brought down
        "ACS-STARTED",          // Automatic channel selection started
        "ACS-COMPLETED",        // Channel changed via ACS
        "ACS-FAILED",           // ACS failed
        "DFS-CAC-START",        // DFS channel availability check
        "DFS-CAC-COMPLETED",    // DFS check completed
        "DFS-NOP-FINISHED",     // DFS non-occupancy period finished
        "AP-CSA-FINISHED",      // Channel switch announcement finished
        "WPS-NEW-AP-SETTINGS",  // WPS changed AP settings
        "WPS-REG-SUCCESS",      // WPS registration (may change config)
        NULL
    };

    /* Skip STA connection/disconnection events */
    if (strstr(event, "AP-STA-CONNECTED") ||
        strstr(event, "AP-STA-DISCONNECTED") ||
        strstr(event, "STA-OPMODE-") ||
        strstr(event, "AP-STA-POLL-OK") ||
        strstr(event, "WPS-ENROLLEE-SEEN") ||
        strstr(event, "EAPOL-TX") ||
        strstr(event, "EAPOL-RX")) {
        return false;
    }

    /* Check for configuration change events */
    for (int i = 0; config_events[i] != NULL; i++) {
        if (strstr(event, config_events[i]) != NULL) {
            return true;
        }
    }

    return false;
}

static void *hostapd_ev_thread(void *arg)
{
	(void)arg;
	g_running = 1;
	while (g_running) {
		fd_set rfds;
		int maxfd = -1;
		FD_ZERO(&rfds);
		for (int i = 0; i < g_num_ctrls; i++) {
			if (g_ctrls[i].ctrl && g_ctrls[i].fd >= 0) {
				FD_SET(g_ctrls[i].fd, &rfds);
				if (g_ctrls[i].fd > maxfd) maxfd = g_ctrls[i].fd;
			}
		}
		struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
		int rc = select(maxfd + 1, &rfds, NULL, NULL, &tv);
		if (rc < 0) {
			if (errno == EINTR) continue;
			perror("hostapd_ev: select");
			break;
		}
		if (rc == 0) {
			continue; /* timeout */
		}
		for (int i = 0; i < g_num_ctrls; i++) {
			if (g_ctrls[i].ctrl && g_ctrls[i].fd >= 0 && FD_ISSET(g_ctrls[i].fd, &rfds)) {
				char buf[REPLY_BUF_SZ];
				size_t len = sizeof(buf) - 1;
				if (wpa_ctrl_recv(g_ctrls[i].ctrl, buf, &len) == 0) {
					buf[len] = '\0';
					/* Print raw event */
					printf("hostapd_ev: %s: %s\n", g_ctrls[i].path, buf);
                                        if (is_config_change_event(buf)) {
                                            printf("hostapd_ev: Config change detected, sending VIF info\n");
                                            netev_send_vif_info();
                                        }
                                } else {
					printf("hostapd_ev: recv failed on %s\n", g_ctrls[i].path);
				}
			}
		}
	}
	return NULL;
}

int hostapd_events_start(const char *ctrl_dir)
{
	const char *dir = ctrl_dir ? ctrl_dir : HOSTAPD_CTRL_DIR;
	hostapd_scan_dir(dir);
	if (g_num_ctrls == 0) {
		printf("hostapd_ev: no hostapd control sockets found in %s\n", dir);
		return -1;
	}
	int rc = pthread_create(&g_thread, NULL, hostapd_ev_thread, NULL);
	if (rc != 0) {
		perror("hostapd_ev: pthread_create");
		return -1;
	}
	return 0;
}

void hostapd_events_stop(void)
{
	g_running = 0;
	if (g_thread) pthread_join(g_thread, NULL);
	for (int i = 0; i < g_num_ctrls; i++) {
		if (g_ctrls[i].ctrl) {
			wpa_ctrl_detach(g_ctrls[i].ctrl);
			wpa_ctrl_close(g_ctrls[i].ctrl);
			g_ctrls[i].ctrl = NULL;
		}
	}
	g_num_ctrls = 0;
}
