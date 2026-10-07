#include <libubus.h>
#include <libubox/blobmsg.h>
#include <ev.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>

#include "stamonitord.h"
#include "log.h"
#include "info_events.h"
#include "stamonitord_history.h"
#include "stamonitord_nl80211.h"
#include "dhcp_fp.h"

/* Shared ubus context */
static struct ubus_context *g_stamonitord_ubus_ctx = NULL;
static struct ev_io g_stamonitord_ubus_watcher;
static struct ubus_object g_stamonitord_ubus_object;
static bool g_stamonitord_ubus_object_added = false;

enum {
    STAINFO_MACADDR,
    __STAINFO_MAX
};

static const struct blobmsg_policy stainfo_policy[__STAINFO_MAX] = {
    [STAINFO_MACADDR] = { .name = "macaddr", .type = BLOBMSG_TYPE_STRING },
};

struct mac_list {
    uint8_t (*items)[6];
    size_t count;
    size_t cap;
};

static bool parse_macaddr(const char *macaddr_str, uint8_t macaddr[6])
{
    unsigned int b[6];

    if (!macaddr_str || !macaddr)
        return false;

    if (sscanf(macaddr_str, "%02x:%02x:%02x:%02x:%02x:%02x",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
        return false;

    for (int i = 0; i < 6; i++) {
        if (b[i] > 0xff)
            return false;
        macaddr[i] = (uint8_t)b[i];
    }

    return true;
}

static void mac_list_add(struct mac_list *list, const uint8_t mac[6])
{
    for (size_t i = 0; i < list->count; i++) {
        if (memcmp(list->items[i], mac, 6) == 0)
            return;
    }

    if (list->count == list->cap) {
        size_t cap = list->cap ? list->cap * 2 : 16;
        uint8_t (*items)[6] = realloc(list->items, cap * sizeof(*items));
        if (!items)
            return;
        list->items = items;
        list->cap = cap;
    }

    memcpy(list->items[list->count], mac, 6);
    list->count++;
}

static void mac_list_add_cb(const uint8_t mac[6], void *ctx)
{
    mac_list_add(ctx, mac);
}

static void append_stainfo(struct blob_buf *b, const uint8_t macaddr[6])
{
    char mac_str[18] = {0};
    char ipaddr[IPADDR_MAX_LEN] = {0};
    char hostname[HOSTNAME_MAX_LEN] = {0};
    char dhcp_options[128] = {0};
    char dhcp_vendor[64] = {0};
    char osinfo[256] = "unknown";
    char ifname[IFNAMSIZ] = {0};
    int link_id = -1;
    time_t connect_time = 0;
    bool found = false;
    bool connected;

    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5]);

    if (stamonitord_history_lookup_client_identity(macaddr,
                                                   ipaddr,
                                                   sizeof(ipaddr),
                                                   hostname,
                                                   sizeof(hostname),
                                                   dhcp_options,
                                                   sizeof(dhcp_options),
                                                   dhcp_vendor,
                                                   sizeof(dhcp_vendor))) {
        found = true;
    }

    if (!ipaddr[0] || strcmp(ipaddr, "0.0.0.0") == 0 ||
        !hostname[0] || strcmp(hostname, "unknown") == 0) {
        if (stamonitord_history_fill_identity_from_leases_and_arp(macaddr,
                                                                 ipaddr,
                                                                 sizeof(ipaddr),
                                                                 hostname,
                                                                 sizeof(hostname))) {
            found = true;
        }
    }

    if (dhcp_options[0]) {
        char *os_info = get_os_info(dhcp_options,
                                    dhcp_vendor[0] ? dhcp_vendor : NULL);
        if (os_info && os_info[0]) {
            snprintf(osinfo, sizeof(osinfo), "%s", os_info);
            found = true;
        }
    }

    if ((ipaddr[0] && strcmp(ipaddr, "0.0.0.0") != 0) ||
        (hostname[0] && strcmp(hostname, "unknown") != 0 && strcmp(hostname, "*") != 0) ||
        (osinfo[0] && strcmp(osinfo, "unknown") != 0)) {
        found = true;
    }

    connected = stamonitord_nl80211_get_sta(macaddr, ifname, sizeof(ifname),
                                            &link_id, &connect_time);
    if (connected)
        found = true;

    blobmsg_add_string(b, "macaddr", mac_str);
    blobmsg_add_string(b, "hostname", (hostname[0] && strcmp(hostname, "*") != 0) ? hostname : "unknown");
    blobmsg_add_string(b, "ipAddress", ipaddr[0] ? ipaddr : "0.0.0.0");
    blobmsg_add_string(b, "osInfo", osinfo);
    blobmsg_add_string(b, "clientType", "wireless");
    blobmsg_add_string(b, "ifname", ifname);
    blobmsg_add_u8(b, "associated", connected);
    if (connected && link_id >= 0)
        blobmsg_add_u32(b, "linkId", (uint32_t)link_id);
    if (connected && connect_time > 0)
        blobmsg_add_u32(b, "connectTime", (uint32_t)connect_time);
    blobmsg_add_u8(b, "found", found);
}

static int ubus_get_stainfo_handler(struct ubus_context *ctx,
                                    struct ubus_object *obj,
                                    struct ubus_request_data *req,
                                    const char *method,
                                    struct blob_attr *msg)
{
    struct blob_attr *tb[__STAINFO_MAX];
    uint8_t macaddr[6] = {0};
    struct blob_buf b = {};

    (void)obj;
    (void)method;

    blobmsg_parse(stainfo_policy, __STAINFO_MAX, tb, blob_data(msg), blob_len(msg));

    if (!tb[STAINFO_MACADDR] ||
        !parse_macaddr(blobmsg_get_string(tb[STAINFO_MACADDR]), macaddr)) {
        return UBUS_STATUS_INVALID_ARGUMENT;
    }

    blob_buf_init(&b, 0);
    append_stainfo(&b, macaddr);
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);

    return UBUS_STATUS_OK;
}

struct if_radio {
    char ifname[IFNAMSIZ];
    char ssid[SSID_MAX_LEN];
    char band[8];
};

static void trim_line(char *s)
{
    char *start;
    char *end;

    if (!s)
        return;

    start = s;
    while (*start == ' ' || *start == '\t')
        start++;
    if (start != s)
        memmove(s, start, strlen(start) + 1);

    end = s + strlen(s);
    while (end > s && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\n' || end[-1] == '\r'))
        end--;
    *end = '\0';
}

static bool read_cmd_line(const char *cmd, char *out, size_t out_len)
{
    FILE *fp;

    if (!out || out_len == 0)
        return false;

    out[0] = '\0';
    fp = popen(cmd, "r");
    if (!fp)
        return false;

    if (!fgets(out, out_len, fp))
        out[0] = '\0';
    pclose(fp);
    trim_line(out);
    return out[0] != '\0';
}

static void lookup_if_radio(struct if_radio *cache, size_t *ncache, size_t cap,
                            const char *ifname, char *ssid, size_t ssid_len,
                            char *band, size_t band_len)
{
    char cmd[256];
    char line[128];
    int freq;

    if (!ssid || ssid_len == 0 || !band || band_len == 0)
        return;

    snprintf(ssid, ssid_len, "unknown");
    snprintf(band, band_len, "UNKNOWN");

    if (!ifname || !ifname[0] || !cache || !ncache)
        return;

    for (size_t i = 0; i < *ncache; i++) {
        if (!strcmp(cache[i].ifname, ifname)) {
            snprintf(ssid, ssid_len, "%s", cache[i].ssid);
            snprintf(band, band_len, "%s", cache[i].band);
            return;
        }
    }

    snprintf(cmd, sizeof(cmd), "iw dev %s info 2>/dev/null | grep ssid | cut -d ' ' -f 2-", ifname);
    if (read_cmd_line(cmd, line, sizeof(line)) && line[0])
        snprintf(ssid, ssid_len, "%s", line);

    snprintf(cmd, sizeof(cmd),
             "iw dev %s info 2>/dev/null | awk -F'[()]' '/channel/ {print $2}' | awk '{print $1}'",
             ifname);
    freq = 0;
    if (read_cmd_line(cmd, line, sizeof(line)))
        freq = atoi(line);
    if (freq >= 2400 && freq <= 2500)
        snprintf(band, band_len, "BAND2G");
    else if (freq >= 5000 && freq <= 6000)
        snprintf(band, band_len, "BAND5G");

    if (*ncache < cap) {
        snprintf(cache[*ncache].ifname, sizeof(cache[*ncache].ifname), "%s", ifname);
        snprintf(cache[*ncache].ssid, sizeof(cache[*ncache].ssid), "%s", ssid);
        snprintf(cache[*ncache].band, sizeof(cache[*ncache].band), "%s", band);
        (*ncache)++;
    }
}

static void append_client_summary(struct blob_buf *b, const uint8_t macaddr[6],
                                  struct if_radio *cache, size_t *ncache, size_t cap)
{
    char mac_str[18] = {0};
    char ipaddr[IPADDR_MAX_LEN] = {0};
    char hostname[HOSTNAME_MAX_LEN] = {0};
    char ifname[IFNAMSIZ] = {0};
    char ssid[SSID_MAX_LEN] = "unknown";
    char band[8] = "UNKNOWN";

    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5]);

    if (!stamonitord_history_lookup_station_ip(macaddr, ipaddr, sizeof(ipaddr))) {
        stamonitord_history_fill_identity_from_leases_and_arp(macaddr,
                                                             ipaddr, sizeof(ipaddr),
                                                             hostname, sizeof(hostname));
    }

    if (stamonitord_nl80211_get_sta(macaddr, ifname, sizeof(ifname), NULL, NULL))
        lookup_if_radio(cache, ncache, cap, ifname, ssid, sizeof(ssid), band, sizeof(band));

    blobmsg_add_string(b, "mac", mac_str);
    blobmsg_add_string(b, "ip", ipaddr[0] ? ipaddr : "0.0.0.0");
    blobmsg_add_string(b, "ssid", ssid);
    blobmsg_add_string(b, "band", band);
}

static int ubus_get_all_stainfo_handler(struct ubus_context *ctx,
                                        struct ubus_object *obj,
                                        struct ubus_request_data *req,
                                        const char *method,
                                        struct blob_attr *msg)
{
    struct mac_list list = {};
    struct if_radio cache[16];
    size_t ncache = 0;
    struct blob_buf b = {};
    void *stations;

    (void)obj;
    (void)method;
    (void)msg;

    stamonitord_nl80211_foreach_sta(mac_list_add_cb, &list);

    blob_buf_init(&b, 0);
    blobmsg_add_u32(&b, "count", (uint32_t)list.count);
    stations = blobmsg_open_array(&b, "stations");
    for (size_t i = 0; i < list.count; i++) {
        void *entry = blobmsg_open_table(&b, NULL);
        append_client_summary(&b, list.items[i], cache, &ncache, sizeof(cache) / sizeof(cache[0]));
        blobmsg_close_table(&b, entry);
    }
    blobmsg_close_array(&b, stations);

    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
    free(list.items);

    return UBUS_STATUS_OK;
}

static void ubus_io_cb(EV_P_ struct ev_io *w, int revents)
{
    (void)loop;
    (void)w;
    (void)revents;

    if (g_stamonitord_ubus_ctx)
        ubus_handle_event(g_stamonitord_ubus_ctx);
}

static bool stamonitord_register_ubus_object(void)
{
    static struct ubus_method methods[] = {
        UBUS_METHOD("get_stainfo", ubus_get_stainfo_handler, stainfo_policy),
        UBUS_METHOD_NOARG("get_all_stainfo", ubus_get_all_stainfo_handler),
        UBUS_METHOD("client.identity", ubus_get_stainfo_handler, stainfo_policy),
    };
    static struct ubus_object_type object_type =
        UBUS_OBJECT_TYPE("stamond", methods);

    g_stamonitord_ubus_object.name = "stamond";
    g_stamonitord_ubus_object.type = &object_type;
    g_stamonitord_ubus_object.methods = methods;
    g_stamonitord_ubus_object.n_methods = sizeof(methods) / sizeof(methods[0]);

    if (ubus_add_object(g_stamonitord_ubus_ctx, &g_stamonitord_ubus_object) != 0) {
        LOG(ERR, "Failed to add stamond ubus object");
        return false;
    }

    g_stamonitord_ubus_object_added = true;

    if (g_stamonitord_ubus_ctx->sock.fd < 0) {
        LOG(ERR, "Invalid stamond ubus fd");
        return false;
    }

    ev_io_init(&g_stamonitord_ubus_watcher, ubus_io_cb,
               g_stamonitord_ubus_ctx->sock.fd, EV_READ);
    ev_io_start(EV_DEFAULT, &g_stamonitord_ubus_watcher);

    return true;
}

/* Helper: callback for ubus responses */
static void response_callback(struct ubus_request *req, int type, struct blob_attr *msg)
{
    (void)req;
    (void)type;
    if (!msg) {
        LOG(DEBUG, "No response received");
        return;
    }
    // Response handling if needed
}

/* Helper: call a ubus method */
static int call_ubus_method(const char *object, const char *method, struct blob_buf *b)
{
    uint32_t id;
    int ret;

    if (!g_stamonitord_ubus_ctx) {
        LOG(ERR, "UBus context not initialized");
        return -1;
    }

    ret = ubus_lookup_id(g_stamonitord_ubus_ctx, object, &id);
    if (ret) {
        LOG(ERR, "Failed to find object '%s': %s", object, ubus_strerror(ret));
        return ret;
    }

    LOG(DEBUG, "Calling %s.%s", object, method);
    ret = ubus_invoke(g_stamonitord_ubus_ctx, id, method,
                      b ? b->head : NULL,
                      response_callback, NULL, 3000);

    if (ret) {
        LOG(ERR, "ubus_invoke failed: %s", ubus_strerror(ret));
    }

    return ret;
}

/* Publish info event to cgwd via netinfo method */
bool stamonitord_publish_info_event(void *buf, size_t size)
{
    int online_status;
    
    // Check if we're online before attempting
    online_status = air_check_online_status();
    if (!online_status) {
        LOG(INFO, "AIRCNMS status is offline, Stamonitord skipping info");
        return false;
    }

    if (!buf || size == 0) {
        LOG(ERR, "Invalid parameters in stamonitord_publish_info_event");
        return false;
    }

    // Log event type for debugging
    if (size >= sizeof(info_event_type_t)) {
        info_event_type_t event_type = *(info_event_type_t *)buf;
        LOG(INFO, "Publishing info event type=%d size=%zu to cgwd.netinfo", event_type, size);
    } else {
        LOG(ERR, "Event buffer too small: size=%zu", size);
        return false;
    }

    struct blob_buf b = {};
    blob_buf_init(&b, 0);
    
    blobmsg_add_field(&b, BLOBMSG_TYPE_UNSPEC, "data", buf, size);
    blobmsg_add_u32(&b, "size", size);

    int ret = call_ubus_method("cgwd", "netinfo", &b);
    blob_buf_free(&b);

    if (ret != 0) {
        LOG(ERR, "Failed to send info event to cgwd.netinfo: %d", ret);
        return false;
    }

    LOG(DEBUG, "Successfully sent info event to cgwd.netinfo");
    return true;
}

/* Initialize ubus TX service */
bool stamonitord_ubus_tx_service_init(void)
{
    if (g_stamonitord_ubus_ctx) {
        LOG(DEBUG, "UBus context already initialized");
        return true;
    }

    g_stamonitord_ubus_ctx = ubus_connect(NULL);
    if (!g_stamonitord_ubus_ctx) {
        LOG(ERR, "Failed to connect to ubus");
        return false;
    }

    if (!stamonitord_register_ubus_object()) {
        ubus_free(g_stamonitord_ubus_ctx);
        g_stamonitord_ubus_ctx = NULL;
        return false;
    }

    LOG(INFO, "stamonitord: Connected to ubus");
    return true;
}

/* Cleanup ubus TX service */
void stamonitord_ubus_tx_service_cleanup(void)
{
    if (g_stamonitord_ubus_ctx) {
        ev_io_stop(EV_DEFAULT, &g_stamonitord_ubus_watcher);
        if (g_stamonitord_ubus_object_added) {
            ubus_remove_object(g_stamonitord_ubus_ctx, &g_stamonitord_ubus_object);
            g_stamonitord_ubus_object_added = false;
        }
        ubus_free(g_stamonitord_ubus_ctx);
        g_stamonitord_ubus_ctx = NULL;
    }
}
