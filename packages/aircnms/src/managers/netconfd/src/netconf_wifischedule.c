/*
 * netconf_wifischedule.c
 *
 * Reads /etc/config/wifi-schedule, checks per-interface schedules
 * every 60 seconds using the existing libev loop, and enables or
 * disables wireless interfaces via UCI.
 *
 * Entry point: netconf_wifischedule_init(loop)
 * Called from main.c after ev_loop initialisation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ev.h>

#include "log.h"
#include "netconf.h"

/* ------------------------------------------------------------------ */
/*  Constants / types                                                   */
/* ------------------------------------------------------------------ */

#define WIFI_SCHEDULE_CONFIG  "/etc/config/wifi-schedule"
#define MAX_INTERFACES        10
#define MAX_SCHEDULES         7
#define IST_OFFSET_SEC        (5 * 3600 + 30 * 60)  /* UTC+05:30 */

typedef struct {
    char day[4];        /* "mon", "tue", … */
    int  day_num;       /* 0=Sun, 1=Mon, … 6=Sat */
    int  enabled;
    int  start_hour;
    int  start_min;
    int  end_hour;
    int  end_min;
} ws_schedule_t;

typedef struct {
    char         interface[32];
    ws_schedule_t schedules[MAX_SCHEDULES];
    int          schedule_count;
    int          current_state;   /* -1=unknown, 0=disabled, 1=enabled */
    int          is_schedule;     /* 0=ignore schedule rules, 1=enforce */
} ws_iface_t;

static ws_iface_t  g_ifaces[MAX_INTERFACES];
static int         g_iface_count = 0;

/* ------------------------------------------------------------------ */
/*  Helpers                                                             */
/* ------------------------------------------------------------------ */

/* Map 3-letter day abbreviation → tm_wday value (0=Sun…6=Sat). */
static int day_to_num(const char *day)
{
    if (strcmp(day, "sun") == 0) return 0;
    if (strcmp(day, "mon") == 0) return 1;
    if (strcmp(day, "tue") == 0) return 2;
    if (strcmp(day, "wed") == 0) return 3;
    if (strcmp(day, "thu") == 0) return 4;
    if (strcmp(day, "fri") == 0) return 5;
    if (strcmp(day, "sat") == 0) return 6;
    return -1;
}

/* Parse one schedule token: "day,enabled,start,end"  e.g. "mon,1,08:00,18:00" */
static int parse_schedule(const char *token, ws_schedule_t *sched)
{
    char day[10] = {0}, start[10] = {0}, end[10] = {0};
    int  enabled = 0;

    if (sscanf(token, "%9[^,],%d,%9[^,],%9s", day, &enabled, start, end) < 2)
        return -1;

    strncpy(sched->day, day, 3);
    sched->day[3]   = '\0';
    sched->day_num  = day_to_num(sched->day);
    sched->enabled  = enabled;

    if (enabled && start[0] && end[0]) {
        sscanf(start, "%d:%d", &sched->start_hour, &sched->start_min);
        sscanf(end,   "%d:%d", &sched->end_hour,   &sched->end_min);
    } else {
        sched->start_hour = sched->start_min = 0;
        sched->end_hour   = sched->end_min   = 0;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Config loader                                                       */
/* ------------------------------------------------------------------ */

static int load_wifi_schedule_config(const char *config_file)
{
    FILE *fp = fopen(config_file, "r");
    if (!fp) {
        LOG(ERR, "wifischedule: cannot open %s", config_file);
        return -1;
    }

    /* Build into a temp table so we can transplant current_state values */
    ws_iface_t  new_ifaces[MAX_INTERFACES];
    int         new_count = 0;
    memset(new_ifaces, 0, sizeof(new_ifaces));

    char         line[256];
    ws_iface_t  *cur = NULL;

    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = '\0';

        if (line[0] == '\0' || line[0] == '#')
            continue;

        if (strstr(line, "config ssid_schedule")) {
            char iface[32] = {0};
            if (sscanf(line, "config ssid_schedule '%31[^']'", iface) == 1) {
                if (new_count >= MAX_INTERFACES) {
                    LOG(ERR, "wifischedule: too many interfaces, max=%d", MAX_INTERFACES);
                    break;
                }
                cur = &new_ifaces[new_count++];
                strncpy(cur->interface, iface, sizeof(cur->interface) - 1);
                cur->schedule_count = 0;
                cur->is_schedule = 1; /* Default to enabled if missing */

                /* Carry over the known runtime state to avoid spurious transitions */
                cur->current_state = -1;
                for (int k = 0; k < g_iface_count; k++) {
                    if (strcmp(g_ifaces[k].interface, iface) == 0) {
                        cur->current_state = g_ifaces[k].current_state;
                        break;
                    }
                }
            }
        }
        else if (strstr(line, "option is_schedule") && cur) {
            int is_sched = 1;
            if (sscanf(line, " option is_schedule '%d'", &is_sched) == 1) {
                cur->is_schedule = is_sched;
            }
        }
        else if (strstr(line, "list schedule") && cur) {
            char token[128] = {0};
            if (sscanf(line, " list schedule '%127[^']'", token) == 1) {
                if (cur->schedule_count < MAX_SCHEDULES) {
                    ws_schedule_t *s = &cur->schedules[cur->schedule_count];
                    if (parse_schedule(token, s) == 0)
                        cur->schedule_count++;
                }
            }
        }
    }

    fclose(fp);

    memcpy(g_ifaces, new_ifaces, sizeof(ws_iface_t) * new_count);
    g_iface_count = new_count;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  State control                                                       */
/* ------------------------------------------------------------------ */

/*
 * get_interface_actual_state - read UCI wireless.<iface>.disabled and
 * return 1 (enabled) or 0 (disabled).  Returns -1 on failure.
 *
 * Used to seed current_state on first encounter so the scheduler
 * doesn't blindly change state when it doesn't yet know what's real.
 */
static int get_interface_actual_state(const char *iface)
{
    char cmd[128];
    char result[8] = {0};
    FILE *fp;

    snprintf(cmd, sizeof(cmd),
             "uci get wireless.%s.disabled 2>/dev/null", iface);

    fp = popen(cmd, "r");
    if (!fp)
        return -1;

    if (fgets(result, sizeof(result), fp) == NULL) {
        pclose(fp);
        return -1;
    }
    pclose(fp);

    /* disabled=0 means the interface IS enabled; disabled=1 means disabled */
    int disabled = atoi(result);
    return disabled ? 0 : 1;
}

static void set_interface_state(const char *iface, int enable)
{
    char cmd[256];
    int  ret;

    LOG(INFO, "wifischedule: [%s] applying to %s",
        enable ? "ENABLE" : "DISABLE", iface);

    /* Step 1: set UCI option */
    snprintf(cmd, sizeof(cmd),
             "uci set wireless.%s.disabled=%d", iface, enable ? 0 : 1);
    ret = system(cmd);
    if (ret != 0)
        LOG(ERR, "wifischedule: 'uci set' failed for %s (ret=%d)", iface, ret);

    /* Step 2: commit */
    ret = system("uci commit wireless");
    if (ret != 0)
        LOG(ERR, "wifischedule: 'uci commit wireless' failed (ret=%d)", ret);

    /* Step 3: reload interface */
    snprintf(cmd, sizeof(cmd), "wifi reload %s", iface);
    ret = system(cmd);
    if (ret != 0)
        LOG(ERR, "wifischedule: 'wifi reload %s' failed (ret=%d)", iface, ret);
    else
        LOG(INFO, "wifischedule: [%s] done for %s",
            enable ? "ENABLE" : "DISABLE", iface);
}

/* Returns current time adjusted to IST (UTC+05:30). */
static struct tm *get_ist_time(void)
{
    time_t now = time(NULL) + IST_OFFSET_SEC;
    return gmtime(&now);
}

/* Returns 1 if iface should currently be enabled, 0 otherwise. */
static int should_be_enabled(ws_iface_t *iface)
{
    struct tm *tm_info = get_ist_time();

    int current_day = tm_info->tm_wday;
    int current_min = tm_info->tm_hour * 60 + tm_info->tm_min;

    for (int i = 0; i < iface->schedule_count; i++) {
        ws_schedule_t *s = &iface->schedules[i];
        if (s->day_num != current_day)
            continue;

        if (!s->enabled)
            return 0;   /* explicitly disabled all day */

        int start_min = s->start_hour * 60 + s->start_min;
        int end_min   = s->end_hour   * 60 + s->end_min;

        return (current_min >= start_min && current_min < end_min) ? 1 : 0;
    }

    return 0;   /* no schedule entry for today → disabled */
}

/* ------------------------------------------------------------------ */
/*  Periodic check                                                      */
/* ------------------------------------------------------------------ */

static void check_schedules(void)
{
    /* Re-read config on every tick so UCI changes are picked up immediately */
    load_wifi_schedule_config(WIFI_SCHEDULE_CONFIG);

    struct tm *tm_info = get_ist_time();
    char       ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S IST", tm_info);

    LOG(INFO, "wifischedule: checking schedules at %s", ts);

    for (int i = 0; i < g_iface_count; i++) {
        ws_iface_t *iface       = &g_ifaces[i];

        /* If scheduling is toggled off for this interface, ignore it entirely */
        if (!iface->is_schedule)
            continue;

        int         should_enab = should_be_enabled(iface);

        /* First encounter: read real UCI state instead of assuming unknown means 0 */
        if (iface->current_state == -1) {
            int actual = get_interface_actual_state(iface->interface);
            if (actual >= 0) {
                iface->current_state = actual;
                LOG(INFO, "wifischedule: %s seeded actual state=%d",
                    iface->interface, actual);
            }
        }

        LOG(INFO, "wifischedule: %s current=%d should=%d",
            iface->interface, iface->current_state, should_enab);

        if (iface->current_state == should_enab)
            continue;

        LOG(INFO, "wifischedule: %s state change: %s -> %s",
            iface->interface,
            iface->current_state == 1 ? "enabled" : "disabled",
            should_enab ? "enabled" : "disabled");

        set_interface_state(iface->interface, should_enab);
        iface->current_state = should_enab;
    }
}

/* ------------------------------------------------------------------ */
/*  libev timer callback                                                */
/* ------------------------------------------------------------------ */

static ev_timer g_schedule_timer;

static void wifischedule_timer_cb(EV_P_ ev_timer *w, int revents)
{
    (void)loop;
    (void)w;
    (void)revents;

    check_schedules();
}

/* ------------------------------------------------------------------ */
/*  Public entry point                                                  */
/* ------------------------------------------------------------------ */

/**
 * netconf_wifischedule_init - load wifi-schedule config and start the
 * 60-second periodic check on the given libev loop.
 *
 * Must be called after the ev_loop is created and before ev_run().
 */
void netconf_wifischedule_init(struct ev_loop *loop)
{
    if (load_wifi_schedule_config(WIFI_SCHEDULE_CONFIG) < 0) {
        LOG(ERR, "wifischedule: init failed, scheduler not started");
        return;
    }

    /* Immediate check on startup */
    check_schedules();

    /* Repeat every 60 seconds */
    ev_timer_init(&g_schedule_timer, wifischedule_timer_cb, 30.0, 30.0);
    ev_timer_start(loop, &g_schedule_timer);

    LOG(INFO, "wifischedule: scheduler started (%d interface(s), 60 s interval)",
        g_iface_count);
}
