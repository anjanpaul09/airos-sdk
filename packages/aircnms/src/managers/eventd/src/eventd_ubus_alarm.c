#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include "eventd.h"
#include "log.h"
#include <stdint.h>
#include <libubus.h>
#include <libubox/blobmsg_json.h>


#include <ev.h>

#define LINE_SIZE              4096
#define DEDUP_INTERVAL_SEC     3

#define READ_BUF_SIZE 8192
#define REBOOT_UPTIME_THRESHOLD_SEC 120

static char g_readbuf[READ_BUF_SIZE];
static int g_readbuf_len = 0;

typedef enum {
    STATE_UNKNOWN = -1,
    STATE_DOWN = 0,
    STATE_UP = 1
} state_t;

/*
 * Global daemon state
 */
struct daemon_state {

    state_t lan_state;
    state_t wan_state;

    time_t last_event_time;

    char last_event[128];
};

static struct daemon_state g_state = {
    .lan_state = STATE_UNKNOWN,
    .wan_state = STATE_UNKNOWN,
};

static FILE *g_fp = NULL;
static int g_fd = -1;

static ev_io g_io_watcher;

enum {
    SYSINFO_UPTIME,
    __SYSINFO_MAX
};

static const struct blobmsg_policy sysinfo_policy[] = {
    [SYSINFO_UPTIME] = {
        .name = "uptime",
        .type = BLOBMSG_TYPE_INT32
    },
};

static void system_info_cb(struct ubus_request *req,
                           int type,
                           struct blob_attr *msg)
{
    uint64_t *uptime = (uint64_t *)req->priv;
    struct blob_attr *tb[__SYSINFO_MAX];

    blobmsg_parse(sysinfo_policy,
                  __SYSINFO_MAX,
                  tb,
                  blob_data(msg),
                  blob_len(msg));

    if (tb[SYSINFO_UPTIME])
        *uptime = blobmsg_get_u32(tb[SYSINFO_UPTIME]);
}

static int get_system_uptime(uint64_t *uptime)
{
    struct ubus_context *ctx;
    uint32_t id;
    int ret;

    if (!uptime)
        return -EINVAL;

    *uptime = 0;

    ctx = ubus_connect(NULL);
    if (!ctx) {
        LOG(ERR, "Failed to connect to ubus");
        return -ENODEV;
    }

    ret = ubus_lookup_id(ctx, "system", &id);
    if (ret) {
        LOG(ERR, "Failed to lookup system object");
        ubus_free(ctx);
        return ret;
    }

    ret = ubus_invoke(ctx,
                      id,
                      "info",
                      NULL,
                      system_info_cb,
                      uptime,
                      3000);

    if (ret)
        LOG(ERR, "ubus invoke failed: %d", ret);

    ubus_free(ctx);

    return ret;
}


void check_and_send_reboot_alarm(void)
{
    uint64_t uptime = 0;
    int ret;

    ret = get_system_uptime(&uptime);
    if (ret != 0) {
        LOG(WARN, "Failed to get system uptime");
        return;
    }

    LOG(INFO, "System uptime: %llu sec",
        (unsigned long long)uptime);

    /*
     * If uptime is small, system likely just rebooted.
     */
    if (uptime <= REBOOT_UPTIME_THRESHOLD_SEC) {

        LOG(INFO,
            "Detected recent reboot (uptime=%llu sec)",
            (unsigned long long)uptime);

        send_alarm(ALARM_TYPE_CRITICAL,
                           "device rebooted");
    }
}

/*
 * Timestamp helper
 */
static const char *timestamp(void)
{
    static char buf[64];

    time_t now;
    struct tm *tm;

    now = time(NULL);

    tm = localtime(&now);

    strftime(buf,
             sizeof(buf),
             "%Y-%m-%d %H:%M:%S",
             tm);

    return buf;
}

/*
 * Deduplicate repeated alarms
 */
static int is_duplicate(const char *event)
{
    time_t now = time(NULL);

    if (!strcmp(event, g_state.last_event)) {

        if ((now - g_state.last_event_time)
            < DEDUP_INTERVAL_SEC) {

            return 1;
        }
    }

    strncpy(g_state.last_event,
            event,
            sizeof(g_state.last_event) - 1);

    g_state.last_event[sizeof(g_state.last_event) - 1] = '\0';

    g_state.last_event_time = now;

    return 0;
}
                
static void process_lan_link_event(int type)
{
    const char *detail = NULL;

    if (type == 1)
        detail = "LAN LINK UP";
    else if (type == 2)
        detail = "LAN LINK DOWN";

    if (detail)
        send_alert(ALERT_TYPE_INTERFACE, detail);
}

/*
 * Alarm print
 */
static void print_alarm(const char *alarm,
                        const char *details)
{
    if (is_duplicate(alarm))
        return;

    printf("\n================================================\n");
    printf("[%s]\n", timestamp());
    printf("ALARM : %s\n", alarm);

    if (details)
        printf("DETAIL: %s\n", details);

    printf("================================================\n");

    fflush(stdout);
}

/*
 * Process ubus monitor line
 */
/*
 * Parse ubus monitor line
 */
static void process_line(const char *line)
{
    /*
     * Debug raw line
     */
    //printf("LINE=[%s]\n", line);

    /*
     * We only care about notifications/events
     */
    if (!strstr(line, "notify"))
        return;

    /*
     * Ignore noisy ubus introspection
     */
    if (strstr(line, "signature") ||
        strstr(line, "objpath") ||
        strstr(line, "objtype"))
        return;

    /*
     * LAN / BRIDGE LINK UP
     */
    if (strstr(line, "link_up")) {

        if (strstr(line, "lan") ||
            strstr(line, "br-lan") ||
            strstr(line, "br-mgmt")) {

            if (g_state.lan_state != STATE_UP) {

                g_state.lan_state = STATE_UP;

                print_alarm("LAN LINK UP", line);
                process_lan_link_event(1); /* UP */
            }
        }

        /*
         * WAN LINK UP
         */
        else if (strstr(line, "wan")) {

            if (g_state.wan_state != STATE_UP) {

                g_state.wan_state = STATE_UP;

                print_alarm("WAN LINK UP", line);
            }
        }
    }

    /*
     * LAN / BRIDGE LINK DOWN
     */
    else if (strstr(line, "link_down")) {

        if (strstr(line, "lan") ||
            strstr(line, "br-lan") ||
            strstr(line, "br-mgmt")) {

            if (g_state.lan_state != STATE_DOWN) {

                g_state.lan_state = STATE_DOWN;

                print_alarm("LAN LINK DOWN", line);
                process_lan_link_event(2); /* DOWN */
            }
        }

        /*
         * WAN LINK DOWN
         */
        else if (strstr(line, "wan")) {

            if (g_state.wan_state != STATE_DOWN) {

                g_state.wan_state = STATE_DOWN;

                print_alarm("WAN LINK DOWN", line);
            }
        }
    }

#if 0
    /*
     * WIFI EVENTS
     */
    else if (strstr(line, "hostapd") ||
             strstr(line, "wlan") ||
             strstr(line, "wifi")) {

        print_alarm("WIFI EVENT", line);
    }

    /*
     * FIREWALL EVENTS
     */
    else if (strstr(line, "firewall")) {

        print_alarm("FIREWALL EVENT", line);
    }

    /*
     * SERVICE EVENTS
     */
    else if (strstr(line, "service")) {

        print_alarm("SERVICE EVENT", line);
    }

    /*
     * REBOOT / SHUTDOWN
     */
    else if (

        (strstr(line, "request") &&
         strstr(line, "reboot")) ||

        strstr(line, "shutdown") ||
        strstr(line, "halt")
    ) {

        print_alarm("SYSTEM REBOOT/SHUTDOWN", line);
    }
#endif
}

static void ubus_monitor_cb(EV_P_ ev_io *w, int revents)
{
    char tmp[1024];

    int n;
    int start;
    int i;

    n = read(w->fd, tmp, sizeof(tmp) - 1);
    if (n <= 0)
        return;

    /*
     * Prevent overflow
     */
    if ((g_readbuf_len + n) >= READ_BUF_SIZE)
        g_readbuf_len = 0;

    memcpy(g_readbuf + g_readbuf_len,
           tmp,
           n);

    g_readbuf_len += n;

    g_readbuf[g_readbuf_len] = '\0';

    start = 0;

    /*
     * Extract complete lines
     */
    for (i = 0; i < g_readbuf_len; i++) {

        if (g_readbuf[i] == '\n') {

            g_readbuf[i] = '\0';

            /*
             * Process complete line
             */
            process_line(&g_readbuf[start]);

            start = i + 1;
        }
    }

    /*
     * Move remaining partial line
     */
    if (start > 0) {

        memmove(g_readbuf,
                g_readbuf + start,
                g_readbuf_len - start);

        g_readbuf_len -= start;
    }
}

/*
 * Initialize alarm module
 */
int ubus_alarm_init(struct ev_loop *loop)
{
    printf("================================================\n");
    printf("UBUS ALARM MODULE INIT\n");
    printf("================================================\n");

    /*
     * Start ubus monitor
     */
    g_fp = popen("ubus monitor", "r");
    if (!g_fp) {

        perror("popen");

        return -1;
    }

    /* Disable stdio buffering */
    setvbuf(g_fp, NULL, _IONBF, 0);

    g_fd = fileno(g_fp);

    /*
     * Register libev watcher
     */
    ev_io_init(&g_io_watcher,
               ubus_monitor_cb,
               g_fd,
               EV_READ);

    ev_io_start(loop, &g_io_watcher);

    return 0;
}

/*
 * Cleanup
 */
void ubus_alarm_cleanup(struct ev_loop *loop)
{
    ev_io_stop(loop, &g_io_watcher);

    if (g_fp) {

        pclose(g_fp);

        g_fp = NULL;
    }
}
