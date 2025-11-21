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

#if 0
static int extract_hex_value(const char *dump, const char *key, char *out, size_t outsz)
{
    const char *p = strstr(dump, key);
    if (!p) return -1;
    p += strlen(key);
    const char *e = strpbrk(p, "\n\r ");
    if (!e) e = p + strlen(p);
    size_t len = e - p;
    if (len >= outsz) len = outsz - 1;
    memcpy(out, p, len);
    out[len] = 0;
    return 0;
}

static void parse_client_capabilities(const char *dump, client_capability_t *cap)
{
    // 1. PHY
    if (strstr(dump, "HE")) strcpy(cap->phy, "11ax");
    else if (strstr(dump, "VHT")) strcpy(cap->phy, "11ac");
    else if (strstr(dump, "HT")) strcpy(cap->phy, "11n");
    else strcpy(cap->phy, "legacy");

    // 2. WMM
    if (strstr(dump, "[WMM]")) strcpy(cap->wmm, "yes");
    else strcpy(cap->wmm, "no");

    // 3. PS (from capability=)
    char val[64];
    if (extract_hex_value(dump, "capability=", val, sizeof(val)) == 0) {
        unsigned cap_field = strtoul(val, NULL, 16);
        if (cap_field & 0x01) strcpy(cap->ps, "U-APSD");
        else strcpy(cap->ps, "none");
    }

    // 4. HT MCS — easy if ht_mcs_bitmask exists
    if (extract_hex_value(dump, "ht_mcs_bitmask=", val, sizeof(val)) == 0) {
        strcpy(cap->mcs, "HT-MCS");
    }

    // 5. VHT MCS map → NSS + MCS
    if (extract_hex_value(dump, "vht_mcs_map=", val, sizeof(val)) == 0) {
        unsigned v = strtoul(val, NULL, 16);
        int nss = 0;
        int max_mcs = 0;
        for (int i = 0; i < 8; i++) {
            int m = (v >> (i*2)) & 0x3;
            if (m != 3) {
                nss = i + 1;
                max_mcs = (m == 0 ? 7 : m == 1 ? 8 : 9);
            }
        }
        snprintf(cap->nss, sizeof(cap->nss), "%d", nss);
        snprintf(cap->mcs, sizeof(cap->mcs), "MCS%d", max_mcs);
    }

    // 6. Bandwidth (from vht_caps_info)
    if (extract_hex_value(dump, "vht_caps_info=", val, sizeof(val)) == 0) {
        unsigned vht = strtoul(val, NULL, 16);
        if (vht & (3 << 2)) strcpy(cap->bw, "80");
        else strcpy(cap->bw, "40");
    } else {
        strcpy(cap->bw, "20");
    }

    // 7. OFDMA (in HE)
    if (extract_hex_value(dump, "he_capab=", val, sizeof(val)) == 0) {
        strcpy(cap->ofdma, "yes");
    } else {
        strcpy(cap->ofdma, "no");
    }

    // 8. MU-MIMO (from VHT)
    if (extract_hex_value(dump, "vht_caps_info=", val, sizeof(val)) == 0) {
        unsigned vht = strtoul(val, NULL, 16);
        if (vht & (1 << 29) || vht & (1 << 30))
            strcpy(cap->mu_mimo, "yes");
        else
            strcpy(cap->mu_mimo, "no");
    }
}

static void fetch_and_parse_sta_capabilities(struct wpa_ctrl *ctrl, const char *mac)
{
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "STA %s", mac);

    char reply[4096];
    size_t reply_len = sizeof(reply) - 1;

    if (wpa_ctrl_request(ctrl, cmd, strlen(cmd), reply, &reply_len, NULL) < 0) {
        printf("hostapd_ev: STA fetch failed for %s\n", mac);
        return;
    }
    reply[reply_len] = 0;

    printf("hostapd_ev: STA dump for %s:\n%s\n", mac, reply);

    // Now parse capabilities
    client_capability_t cap;
    memset(&cap, 0, sizeof(cap));

    parse_client_capabilities(reply, &cap);

    // Print or store
    printf("capability: phy=%s mcs=%s nss=%s bw=%s wmm=%s ofdma=%s mu_mimo=%s ps=%s roaming=%s\n",
        cap.phy, cap.mcs, cap.nss, cap.bw, cap.wmm, cap.ofdma, cap.mu_mimo, cap.ps, cap.roaming);
}

static int parse_sta_mac(const char *msg, char *mac, size_t macsz)
{
    const char *p = strchr(msg, ' ');
    if (!p) return -1;
    p++;  // move past space
    if (strlen(p) < 17) return -1;
    strncpy(mac, p, 17);
    mac[17] = 0;
    return 0;
}
#endif

static int is_socket(const char *path)
{
	struct stat st;
	if (stat(path, &st) != 0) return 0;
	return S_ISSOCK(st.st_mode);
}

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
					// Client connect/disconnect events are now handled by nl80211 context
					// No need to parse AP-STA-CONNECTED/DISCONNECTED events here
        				//if (strstr(buf, "AP-STA-CONNECTED")) {
                                            //char mac[18];
                                            //if (parse_sta_mac(buf, mac, sizeof(mac)) == 0) {
                                                //fetch_and_parse_sta_capabilities(g_ctrls[i].ctrl, mac);
                                            //}
                                        //}

                                        /* Optional: For encrypted SSIDs, handshake event gives cleaner timing */
                                        //else if (strstr(buf, "EAPOL-4WAY-HS-COMPLETED")) {
                                          //  char mac[18];
                                          //  if (parse_sta_mac(buf, mac, sizeof(mac)) == 0) {
                                           //     fetch_and_parse_sta_capabilities(g_ctrls[i].ctrl, mac);
                                           // }
                                        //}
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
