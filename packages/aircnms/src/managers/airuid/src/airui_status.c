#include "airui_status.h"

#include <stdbool.h>
#include <ctype.h>
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/wait.h>
#include <unistd.h>
#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>

#include "airui_response.h"
#include "airui_mode.h"
#include "airui_ubus_client.h"

#define AIRUI_TEXT_LIMIT 32768

struct status_data {
    struct ubus_context *ctx;
    const char *kind;
};

enum {
    CLIENT_MACADDR,
    __CLIENT_MAX
};

static const struct blobmsg_policy client_policy[__CLIENT_MAX] = {
    [CLIENT_MACADDR] = { .name = "macaddr", .type = BLOBMSG_TYPE_STRING },
};

struct disconnect_result {
    const char *macaddr;
    const char *interface;
    uint32_t reconnect_block_seconds;
};

struct ethernet_link {
    bool available;
    bool carrier;
    char network[32];
    char interface[32];
    char device[32];
    char duplex[16];
    uint32_t speed_mbps;
    uint32_t mtu;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t rx_errors;
    uint64_t tx_errors;
    uint64_t rx_dropped;
    uint64_t tx_dropped;
};

static char *read_stream(FILE *fp)
{
    char *buf;
    size_t used = 0;

    if (!fp) {
        return NULL;
    }

    buf = calloc(1, AIRUI_TEXT_LIMIT + 1);
    if (!buf) {
        return NULL;
    }

    while (used < AIRUI_TEXT_LIMIT) {
        size_t got = fread(buf + used, 1, AIRUI_TEXT_LIMIT - used, fp);

        used += got;
        if (got == 0) {
            break;
        }
    }

    buf[used] = '\0';
    return buf;
}

static char *read_text_file(const char *path)
{
    FILE *fp;
    char *text;

    fp = fopen(path, "r");
    if (!fp) {
        return NULL;
    }

    text = read_stream(fp);
    fclose(fp);
    return text;
}

static bool read_sysfs_value(const char *device,
                             const char *name,
                             char *value,
                             size_t value_len)
{
    char path[160];
    char *newline;
    FILE *fp;

    if (!device || !device[0] || !name || !value || value_len == 0) {
        return false;
    }

    snprintf(path, sizeof(path), "/sys/class/net/%s/%s", device, name);
    fp = fopen(path, "r");
    if (!fp) {
        return false;
    }

    if (!fgets(value, value_len, fp)) {
        fclose(fp);
        return false;
    }
    fclose(fp);

    newline = strpbrk(value, "\r\n");
    if (newline) {
        *newline = '\0';
    }

    return value[0] != '\0';
}

static bool read_sysfs_u64(const char *device,
                           const char *name,
                           uint64_t *value)
{
    char text[64];
    char *end = NULL;
    unsigned long long parsed;

    if (!value || !read_sysfs_value(device, name, text, sizeof(text))) {
        return false;
    }

    parsed = strtoull(text, &end, 10);
    if (!end || end == text || *end != '\0') {
        return false;
    }

    *value = (uint64_t)parsed;
    return true;
}

static bool ethernet_speed(const char *device, uint32_t *speed_mbps)
{
    uint64_t speed;

    if (!read_sysfs_u64(device, "speed", &speed) || speed == 0 ||
        speed > UINT32_MAX) {
        return false;
    }

    *speed_mbps = (uint32_t)speed;
    return true;
}

static bool interface_runtime(struct ubus_context *ctx,
                              const char *network,
                              char *device,
                              size_t device_len,
                              bool *up)
{
    struct airui_ubus_result result = {};
    struct json_object *root = NULL;
    struct json_object *value = NULL;
    char object[96];
    const char *name = NULL;
    bool found = false;

    snprintf(object, sizeof(object), "network.interface.%s", network);
    if (airui_ubus_call_json(ctx, object, "status", NULL, &result) ||
        !result.json) {
        goto out;
    }

    root = json_tokener_parse(result.json);
    if (!root) {
        goto out;
    }

    if (json_object_object_get_ex(root, "l3_device", &value)) {
        name = json_object_get_string(value);
    }
    if ((!name || !name[0]) &&
        json_object_object_get_ex(root, "device", &value)) {
        name = json_object_get_string(value);
    }
    if (!name || !name[0] || strlen(name) >= device_len) {
        goto out;
    }

    snprintf(device, device_len, "%s", name);
    if (up) {
        *up = json_object_object_get_ex(root, "up", &value) &&
              json_object_get_boolean(value);
    }
    found = true;

out:
    if (root) {
        json_object_put(root);
    }
    airui_ubus_result_free(&result);
    return found;
}

static bool resolve_physical_device(const char *logical,
                                    char *physical,
                                    size_t physical_len,
                                    uint32_t *speed_mbps)
{
    char bridge_path[128];
    char device_path[128];
    char base[32];
    DIR *dir;
    struct dirent *entry;
    char candidate[32] = {};
    uint32_t candidate_speed = 0;

    if (strlen(logical) >= sizeof(base)) {
        return false;
    }
    memcpy(base, logical, strlen(logical) + 1);
    if (strchr(base, '.')) {
        *strchr(base, '.') = '\0';
        snprintf(device_path, sizeof(device_path), "/sys/class/net/%s", base);
        if (access(device_path, F_OK) == 0) {
            snprintf(physical, physical_len, "%s", base);
            ethernet_speed(base, speed_mbps);
            return true;
        }
    }

    snprintf(device_path, sizeof(device_path), "/sys/class/net/%s", logical);
    snprintf(bridge_path, sizeof(bridge_path),
             "/sys/class/net/%s/brif", logical);

    if (access(device_path, F_OK) == 0 && access(bridge_path, F_OK) != 0) {
        snprintf(physical, physical_len, "%s", logical);
        ethernet_speed(logical, speed_mbps);
        return true;
    }

    dir = opendir(bridge_path);
    if (dir) {
        while ((entry = readdir(dir)) != NULL) {
            uint32_t speed = 0;
            uint64_t carrier = 0;
            bool has_speed;

            if (entry->d_name[0] == '.' ||
                strlen(entry->d_name) >= sizeof(candidate) ||
                strncmp(entry->d_name, "phy", 3) == 0 ||
                strncmp(entry->d_name, "wlan", 4) == 0) {
                continue;
            }

            has_speed = ethernet_speed(entry->d_name, &speed);

            if (!candidate[0] || (has_speed && candidate_speed == 0)) {
                memcpy(candidate, entry->d_name, strlen(entry->d_name) + 1);
                candidate_speed = speed;
            }

            if (read_sysfs_u64(entry->d_name, "carrier", &carrier) && carrier) {
                memcpy(candidate, entry->d_name, strlen(entry->d_name) + 1);
                candidate_speed = speed;
                break;
            }
        }
        closedir(dir);
    }

    if (candidate[0]) {
        snprintf(physical, physical_len, "%s", candidate);
        *speed_mbps = candidate_speed;
        return true;
    }

    return false;
}

static void collect_ethernet_link(struct ubus_context *ctx,
                                  struct ethernet_link *link)
{
    static const char *networks[] = { "wan", "lan", "mgmt" };
    char logical[32] = {};
    char physical[32] = {};
    uint64_t value;
    size_t i;

    memset(link, 0, sizeof(*link));

    for (i = 0; i < sizeof(networks) / sizeof(networks[0]); i++) {
        bool interface_up = false;
        uint32_t speed_mbps = 0;

        logical[0] = '\0';
        physical[0] = '\0';
        if (interface_runtime(ctx, networks[i], logical, sizeof(logical),
                              &interface_up) &&
            resolve_physical_device(logical, physical, sizeof(physical),
                                    &speed_mbps)) {
            snprintf(link->network, sizeof(link->network), "%s", networks[i]);
            snprintf(link->interface, sizeof(link->interface), "%s", logical);
            snprintf(link->device, sizeof(link->device), "%s", physical);
            link->carrier = interface_up;
            link->speed_mbps = speed_mbps;
            break;
        }
    }

    if (!link->device[0]) {
        return;
    }

    link->available = true;
    if (read_sysfs_u64(link->device, "carrier", &value)) {
        link->carrier = value != 0;
    }
    if (!read_sysfs_value(link->device, "duplex", link->duplex,
                          sizeof(link->duplex))) {
        link->duplex[0] = '\0';
    } else if (link->duplex[0]) {
        link->duplex[0] = (char)toupper((unsigned char)link->duplex[0]);
    }
    if (read_sysfs_u64(link->device, "mtu", &value) && value <= UINT32_MAX) {
        link->mtu = (uint32_t)value;
    }
    read_sysfs_u64(link->device, "statistics/rx_bytes", &link->rx_bytes);
    read_sysfs_u64(link->device, "statistics/tx_bytes", &link->tx_bytes);
    read_sysfs_u64(link->device, "statistics/rx_errors", &link->rx_errors);
    read_sysfs_u64(link->device, "statistics/tx_errors", &link->tx_errors);
    read_sysfs_u64(link->device, "statistics/rx_dropped", &link->rx_dropped);
    read_sysfs_u64(link->device, "statistics/tx_dropped", &link->tx_dropped);
}

static void add_ethernet_link(struct blob_buf *b,
                              const struct ethernet_link *link)
{
    void *table = blobmsg_open_table(b, "uplink");

    blobmsg_add_u8(b, "available", link->available);
    if (link->network[0]) {
        blobmsg_add_string(b, "network", link->network);
    }
    if (link->interface[0]) {
        blobmsg_add_string(b, "interface", link->interface);
    }
    if (link->device[0]) {
        blobmsg_add_string(b, "device", link->device);
    }
    blobmsg_add_u8(b, "carrier", link->carrier);
    if (link->speed_mbps) {
        blobmsg_add_u32(b, "speed_mbps", link->speed_mbps);
    }
    if (link->duplex[0]) {
        blobmsg_add_string(b, "duplex", link->duplex);
    }
    if (link->mtu) {
        blobmsg_add_u32(b, "mtu", link->mtu);
    }
    blobmsg_add_u64(b, "rx_bytes", link->rx_bytes);
    blobmsg_add_u64(b, "tx_bytes", link->tx_bytes);
    blobmsg_add_u64(b, "rx_errors", link->rx_errors);
    blobmsg_add_u64(b, "tx_errors", link->tx_errors);
    blobmsg_add_u64(b, "rx_dropped", link->rx_dropped);
    blobmsg_add_u64(b, "tx_dropped", link->tx_dropped);
    blobmsg_close_table(b, table);
}

static char *read_command(const char *command)
{
    FILE *fp;
    char *text;

    fp = popen(command, "r");
    if (!fp) {
        return NULL;
    }

    text = read_stream(fp);
    pclose(fp);
    return text;
}

static void add_empty_table(struct blob_buf *b, const char *name)
{
    void *t = blobmsg_open_table(b, name);
    blobmsg_close_table(b, t);
}

static void add_json_or_table(struct blob_buf *b, const char *name, const char *json)
{
    struct json_object *obj;

    if (!json) {
        add_empty_table(b, name);
        return;
    }

    obj = json_tokener_parse(json);
    if (!obj || !blobmsg_add_json_element(b, name, obj)) {
        if (obj) {
            json_object_put(obj);
        }
        add_empty_table(b, name);
        return;
    }

    json_object_put(obj);
}

static void add_failed_call(struct blob_buf *b, const char *name, int status)
{
    void *t = blobmsg_open_table(b, name);

    blobmsg_add_u8(b, "available", false);
    blobmsg_add_u32(b, "status", (uint32_t)status);
    blobmsg_add_string(b, "message", ubus_strerror(status));
    blobmsg_close_table(b, t);
}

static void add_call_result(struct blob_buf *b,
                            struct ubus_context *ctx,
                            const char *name,
                            const char *object,
                            const char *method,
                            struct blob_buf *request)
{
    struct airui_ubus_result result;
    int ret;

    ret = airui_ubus_call_json(ctx, object, method, request, &result);
    if (ret) {
        add_failed_call(b, name, ret);
        return;
    }

    add_json_or_table(b, name, result.json);
    airui_ubus_result_free(&result);
}

static void add_uci_config(struct blob_buf *b,
                           struct ubus_context *ctx,
                           const char *name,
                           const char *config)
{
    struct blob_buf req = {};

    blob_buf_init(&req, 0);
    blobmsg_add_string(&req, "config", config);
    add_call_result(b, ctx, name, "uci", "get", &req);
    blob_buf_free(&req);
}

static void add_interface_status(struct blob_buf *b,
                                 struct ubus_context *ctx,
                                 const char *name,
                                 const char *iface)
{
    char object[96];

    snprintf(object, sizeof(object), "network.interface.%s", iface);
    add_call_result(b, ctx, name, object, "status", NULL);
}

static void add_string_file(struct blob_buf *b, const char *name, const char *path)
{
    char *text = read_text_file(path);

    blobmsg_add_string(b, name, text ? text : "");
    free(text);
}

static void add_string_command(struct blob_buf *b, const char *name, const char *command)
{
    char *text = read_command(command);

    blobmsg_add_string(b, name, text ? text : "");
    free(text);
}

static void add_wireless_bundle(struct blob_buf *b, struct ubus_context *ctx)
{
    void *wireless = blobmsg_open_table(b, "wireless");

    add_uci_config(b, ctx, "uci", "wireless");
    add_call_result(b, ctx, "runtime", "network.wireless", "status", NULL);
    blobmsg_close_table(b, wireless);
}

static bool valid_mac_address(const char *value)
{
    size_t i;

    if (!value || strlen(value) != 17) {
        return false;
    }

    for (i = 0; i < 17; i++) {
        if ((i + 1) % 3 == 0) {
            if (value[i] != ':') {
                return false;
            }
        } else if (!isxdigit((unsigned char)value[i])) {
            return false;
        }
    }

    return true;
}

static bool valid_interface_name(const char *value)
{
    const unsigned char *p = (const unsigned char *)value;

    if (!value || !value[0] || strlen(value) >= 32) {
        return false;
    }

    for (; *p; p++) {
        if (!isalnum(*p) && *p != '_' && *p != '-' && *p != '.') {
            return false;
        }
    }

    return true;
}

static bool find_station_interface(const char *macaddr, char *interface, size_t size)
{
    char *stations;
    char *copy;
    char *line;
    char *saveptr = NULL;
    bool found = false;

    stations = read_command("for sock in /var/run/hostapd/phy*-ap* /var/run/hostapd/wlan*; do [ -S \"$sock\" ] || continue; ifname=${sock##*/}; /usr/sbin/hostapd_cli -p /var/run/hostapd -i \"$ifname\" all_sta 2>/dev/null | sed \"s/^/interface $ifname /\"; done");
    copy = stations ? strdup(stations) : NULL;

    for (line = copy ? strtok_r(copy, "\n", &saveptr) : NULL;
         line;
         line = strtok_r(NULL, "\n", &saveptr)) {
        char ifname[32] = {};
        char mac[18] = {};

        if (sscanf(line, "interface %31s %17s", ifname, mac) == 2 &&
            valid_interface_name(ifname) && valid_mac_address(mac) &&
            !strcasecmp(mac, macaddr)) {
            snprintf(interface, size, "%s", ifname);
            found = true;
            break;
        }
    }

    free(copy);
    free(stations);
    return found;
}

static void disconnect_builder(struct blob_buf *b, void *user)
{
    struct disconnect_result *result = user;

    blobmsg_add_string(b, "macaddr", result->macaddr);
    blobmsg_add_string(b, "interface", result->interface);
    blobmsg_add_u8(b, "disconnected", true);
    blobmsg_add_u32(b, "reconnect_block_seconds",
                    result->reconnect_block_seconds);
}

static void add_client_identities(struct blob_buf *b,
                                  struct ubus_context *ctx,
                                  const char *stations)
{
    char seen[128][18] = {};
    size_t seen_count = 0;
    char *copy;
    char *line;
    char *saveptr = NULL;
    void *identities;

    identities = blobmsg_open_table(b, "client_identities");
    copy = stations ? strdup(stations) : NULL;

    for (line = copy ? strtok_r(copy, "\n", &saveptr) : NULL;
         line && seen_count < 128;
         line = strtok_r(NULL, "\n", &saveptr)) {
        struct airui_ubus_result result = {};
        struct blob_buf request = {};
        char *token;
        char *token_save = NULL;
        const char *mac = NULL;
        size_t i;
        bool duplicate = false;

        for (token = strtok_r(line, " \t", &token_save);
             token;
             token = strtok_r(NULL, " \t", &token_save)) {
            if (valid_mac_address(token)) {
                mac = token;
                break;
            }
        }

        if (!mac) {
            continue;
        }

        for (i = 0; i < seen_count; i++) {
            if (!strcasecmp(seen[i], mac)) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) {
            continue;
        }

        snprintf(seen[seen_count], sizeof(seen[seen_count]), "%s", mac);
        mac = seen[seen_count++];

        blob_buf_init(&request, 0);
        blobmsg_add_string(&request, "macaddr", mac);
        if (!airui_ubus_call_json(ctx, "stamond", "client.identity", &request, &result)) {
            add_json_or_table(b, mac, result.json);
            airui_ubus_result_free(&result);
        }
        blob_buf_free(&request);
    }

    free(copy);
    blobmsg_close_table(b, identities);
}

static void status_builder(struct blob_buf *b, void *user)
{
    struct status_data *data = user;
    struct ethernet_link link;
    struct ubus_context *ctx = data ? data->ctx : NULL;
    const char *kind = data ? data->kind : "summary";
    char *wireless_stations;
    void *interfaces;

    if (!ctx) {
        return;
    }

    blobmsg_add_string(b, "kind", kind);
    add_call_result(b, ctx, "board", "system", "board", NULL);
    add_call_result(b, ctx, "system", "system", "info", NULL);
    add_uci_config(b, ctx, "network", "network");
    add_uci_config(b, ctx, "version", "version");
    add_wireless_bundle(b, ctx);
    airui_mode_add_snapshot(b, ctx);

    interfaces = blobmsg_open_table(b, "interfaces");
    add_interface_status(b, ctx, "lan", "lan");
    add_interface_status(b, ctx, "wan", "wan");
    add_interface_status(b, ctx, "mgmt", "mgmt");
    add_interface_status(b, ctx, "nat_network", "nat_network");
    blobmsg_close_table(b, interfaces);

    collect_ethernet_link(ctx, &link);
    add_ethernet_link(b, &link);

    /* Every status endpoint exposes the same canonical snapshot. This keeps
     * repeated metrics identical while preserving the legacy method names. */
    add_string_file(b, "proc_stat", "/proc/stat");
    add_string_file(b, "proc_cpuinfo", "/proc/cpuinfo");
    add_string_file(b, "proc_net_dev", "/proc/net/dev");
    add_string_command(b, "wireless_survey", "iw_bin=$(command -v iw 2>/dev/null); [ -n \"$iw_bin\" ] || exit 0; for dev in /sys/class/net/phy*-ap* /sys/class/net/wlan*; do [ -e \"$dev\" ] || continue; ifname=${dev##*/}; \"$iw_bin\" dev \"$ifname\" survey dump 2>/dev/null | sed \"s/^/interface $ifname /\"; done");
    add_call_result(b, ctx, "leases", "luci-rpc", "getDHCPLeases", NULL);
    add_string_command(b, "neigh4", "/sbin/ip -4 neigh show 2>/dev/null");
    add_string_command(b, "neigh6", "/sbin/ip -6 neigh show 2>/dev/null");
    wireless_stations = read_command("for sock in /var/run/hostapd/phy*-ap* /var/run/hostapd/wlan*; do [ -S \"$sock\" ] || continue; ifname=${sock##*/}; /usr/sbin/hostapd_cli -p /var/run/hostapd -i \"$ifname\" all_sta 2>/dev/null | sed \"s/^/interface $ifname /\"; done");
    blobmsg_add_string(b, "wireless_stations", wireless_stations ? wireless_stations : "");
    add_client_identities(b, ctx, wireless_stations);
    free(wireless_stations);
}

static int airui_status_reply(struct ubus_context *ctx,
                              struct ubus_object *obj,
                              struct ubus_request_data *req,
                              const char *method,
                              struct blob_attr *msg,
                              const char *kind)
{
    struct status_data data = {
        .ctx = ctx,
        .kind = kind,
    };

    (void)obj;
    (void)method;
    (void)msg;

    airui_reply_ok_schema(ctx, req, status_builder, &data, "live", kind);
    return 0;
}

int airui_status_summary(struct ubus_context *ctx,
                         struct ubus_object *obj,
                         struct ubus_request_data *req,
                         const char *method,
                         struct blob_attr *msg)
{
    return airui_status_reply(ctx, obj, req, method, msg, "summary");
}

int airui_status_device_status(struct ubus_context *ctx,
                               struct ubus_object *obj,
                               struct ubus_request_data *req,
                               const char *method,
                               struct blob_attr *msg)
{
    return airui_status_reply(ctx, obj, req, method, msg, "device_status");
}

int airui_status_clients(struct ubus_context *ctx,
                         struct ubus_object *obj,
                         struct ubus_request_data *req,
                         const char *method,
                         struct blob_attr *msg)
{
    return airui_status_reply(ctx, obj, req, method, msg, "clients");
}

int airui_status_client_disconnect(struct ubus_context *ctx,
                                   struct ubus_object *obj,
                                   struct ubus_request_data *req,
                                   const char *method,
                                   struct blob_attr *msg)
{
    struct blob_attr *tb[__CLIENT_MAX] = {};
    struct disconnect_result result = {};
    char interface[32] = {};
    char command[768];
    const char *macaddr;
    int status;

    (void)obj;
    (void)method;

    if (!msg) {
        airui_reply_error(ctx, req, "invalid_argument", "macaddr",
                          "A client MAC address is required");
        return 0;
    }

    blobmsg_parse(client_policy, __CLIENT_MAX, tb,
                  blobmsg_data(msg), blobmsg_data_len(msg));
    if (!tb[CLIENT_MACADDR]) {
        airui_reply_error(ctx, req, "invalid_argument", "macaddr",
                          "A client MAC address is required");
        return 0;
    }

    macaddr = blobmsg_get_string(tb[CLIENT_MACADDR]);
    if (!valid_mac_address(macaddr)) {
        airui_reply_error(ctx, req, "invalid_argument", "macaddr",
                          "Invalid client MAC address");
        return 0;
    }

    if (!find_station_interface(macaddr, interface, sizeof(interface))) {
        airui_reply_error(ctx, req, "not_found", "macaddr",
                          "Client is not currently associated");
        return 0;
    }

    snprintf(command, sizeof(command),
             "for sock in /var/run/hostapd/phy*-ap* /var/run/hostapd/wlan*; do "
             "[ -S \"$sock\" ] || continue; ifname=${sock##*/}; "
             "/usr/sbin/hostapd_cli -p /var/run/hostapd -i \"$ifname\" "
             "deny_acl ADD_MAC %s >/dev/null 2>&1 || exit 1; done",
             macaddr);
    status = system(command);
    if (status == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        airui_reply_error(ctx, req, "disconnect_failed", "macaddr",
                          "Hostapd could not temporarily block the client");
        return 0;
    }

    snprintf(command, sizeof(command),
             "for sock in /var/run/hostapd/phy*-ap* /var/run/hostapd/wlan*; do "
             "[ -S \"$sock\" ] || continue; ifname=${sock##*/}; "
             "/usr/sbin/hostapd_cli -p /var/run/hostapd -i \"$ifname\" "
             "deauthenticate %s >/dev/null 2>&1 || exit 1; done",
             macaddr);
    status = system(command);
    if (status == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        snprintf(command, sizeof(command),
                 "for sock in /var/run/hostapd/phy*-ap* /var/run/hostapd/wlan*; do "
                 "[ -S \"$sock\" ] || continue; ifname=${sock##*/}; "
                 "/usr/sbin/hostapd_cli -p /var/run/hostapd -i \"$ifname\" "
                 "deny_acl DEL_MAC %s >/dev/null 2>&1; done",
                 macaddr);
        system(command);
        airui_reply_error(ctx, req, "disconnect_failed", "macaddr",
                          "Hostapd could not disconnect the client");
        return 0;
    }

    snprintf(command, sizeof(command),
             "(sleep 60; for sock in /var/run/hostapd/phy*-ap* /var/run/hostapd/wlan*; do "
             "[ -S \"$sock\" ] || continue; ifname=${sock##*/}; "
             "/usr/sbin/hostapd_cli -p /var/run/hostapd -i \"$ifname\" "
             "deny_acl DEL_MAC %s >/dev/null 2>&1; done) &",
             macaddr);
    system(command);

    result.macaddr = macaddr;
    result.interface = interface;
    result.reconnect_block_seconds = 60;
    airui_reply_ok_schema(ctx, req, disconnect_builder, &result,
                          "live", "client_disconnect");
    return 0;
}

int airui_status_statistics(struct ubus_context *ctx,
                            struct ubus_object *obj,
                            struct ubus_request_data *req,
                            const char *method,
                            struct blob_attr *msg)
{
    return airui_status_reply(ctx, obj, req, method, msg, "statistics");
}
