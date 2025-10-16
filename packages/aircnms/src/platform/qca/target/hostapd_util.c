#include <stdio.h>

#include "os.h"
#include "log.h"
#include "kconfig.h"
#include "hostapd_util.h"

#define MODULE_ID LOG_MODULE_ID_TARGET

#if CONFIG_HOSTAP_TIMEOUT_T_SWITCH
#define CMD_TIMEOUT "timeout -t"
#else
#define CMD_TIMEOUT "timeout"
#endif

bool hostapd_client_disconnect(const char *path, const char *interface,
                               const char *disc_type, const char *mac_str, uint8_t reason)
{
    char hostapd_cmd[512];
    bool ret = false;

    snprintf(hostapd_cmd, sizeof(hostapd_cmd),
             "%s 5 hostapd_cli -p %s/hostapd-$(cat /sys/class/net/%s/parent) -i %s %s %s reason=%hhu",
             CMD_TIMEOUT, path, interface, interface, disc_type, mac_str, reason);

    ret = !cmd_log(hostapd_cmd);
    if (!ret) {
        LOGE("hostapd_cli execution failed: %s", hostapd_cmd);
    }

    return ret;
}

bool hostapd_btm_request(const char *path, const char *interface, const char *btm_req_cmd)
{
    char    hostapd_cmd[1024];
    bool    ret = false;

    snprintf(hostapd_cmd, sizeof(hostapd_cmd),
            "%s 5 hostapd_cli -p %s/hostapd-$(cat /sys/class/net/%s/parent) -i %s bss_tm_req %s",
            CMD_TIMEOUT, path, interface, interface, btm_req_cmd);

    ret = !cmd_log(hostapd_cmd);
    if (!ret) {
        LOGE("hostapd_cli execution failed: %s", hostapd_cmd);
    }


    return ret;
}

bool hostapd_rrm_set_neighbor(const char *path, const char *interface, const char *bssid, const char *nr)
{
    char    hostapd_cmd[1024];
    bool    ret = false;

    snprintf(hostapd_cmd, sizeof(hostapd_cmd),
            "%s 5 hostapd_cli -p %s/hostapd-$(cat /sys/class/net/%s/parent) -i %s "
            "set_neighbor %s nr=%s",
            CMD_TIMEOUT, path, interface, interface, bssid, nr);

    ret = !cmd_log(hostapd_cmd);
    if (!ret) {
        LOGE("hostapd_cli execution failed: %s", hostapd_cmd);
    }

    return ret;
}

bool hostapd_rrm_remove_neighbor(const char *path, const char *interface, const char *bssid)
{
    char    hostapd_cmd[1024];
    bool    ret = false;

    snprintf(hostapd_cmd, sizeof(hostapd_cmd),
            "%s 5 hostapd_cli -p %s/hostapd-$(cat /sys/class/net/%s/parent) -i %s "
            "remove_neighbor %s ",
            CMD_TIMEOUT, path, interface, interface, bssid);

    ret = !cmd_log(hostapd_cmd);
    if (!ret) {
        LOGE("hostapd_cli execution failed: %s", hostapd_cmd);
    }

    return ret;
}

bool hostapd_rrm_get_neighbors(const char *path, const char *interface, char *buf, const size_t buf_len)
{
    char    hostapd_cmd[1024];
    bool    ret = false;

    snprintf(hostapd_cmd, sizeof(hostapd_cmd),
            "%s 5 hostapd_cli -p %s/hostapd-$(cat /sys/class/net/%s/parent) -i %s "
            "show_neighbor",
            CMD_TIMEOUT, path, interface, interface);

    ret = !cmd_buf(hostapd_cmd, buf, buf_len);
    if (!ret) {
        LOGE("hostapd_cli execution failed: %s", hostapd_cmd);
    }

    return ret;
}

/* To use it first check if tx=0 is supprted for your hostapd version */
bool hostapd_remove_station(const char *path, const char *interface, const char *mac_str)
{
    char hostapd_cmd[512];
    bool ret = false;

    snprintf(hostapd_cmd, sizeof(hostapd_cmd),
             /* Send frame anyway. QCA driver won't report ATH_EVENT_BSTEERING_CLIENT_DISCONNECTED when
              * tx=0. Mentioned event is handled by BM and lack of it in this scenario can cause steering problems.
              */
             "%s 5 hostapd_cli -p %s/hostapd-$(cat /sys/class/net/%s/parent) -i %s deauthenticate %s \"reason=1\"",
             CMD_TIMEOUT, path, interface, interface, mac_str);

    ret = !cmd_log(hostapd_cmd);
    if (!ret) {
        LOGE("hostapd_cli execution failed: %s", hostapd_cmd);
    }

    return ret;
}
