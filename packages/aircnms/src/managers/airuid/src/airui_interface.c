#include "airui_interface.h"
#include "airui_apply_status.h"

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>

#include "airui_response.h"
#include "airui_ubus_client.h"

#define AIRUI_IFACE_SOURCE "airui.network"
#define AIRUI_IFACE_SCHEMA "airui.interface.v1"
#define MAX_PLAN_ITEMS 24
#define MAX_APPLY_SERVICES 4
#define DEFAULT_ROLLBACK_TIMEOUT 30
#define MIN_ROLLBACK_TIMEOUT 5
#define MAX_ROLLBACK_TIMEOUT 300

enum {
    IFACE_TYPE,
    IFACE_NAME,
    IFACE_VLAN_ID,
    IFACE_PARENT_DEVICE,
    IFACE_BRIDGE_NAME,
    IFACE_PROTO,
    IFACE_IPADDR,
    IFACE_NETMASK,
    IFACE_DHCP,
    IFACE_FIREWALL,
    IFACE_DRY_RUN,
    IFACE_FORCE,
    IFACE_DELETE_SSID_MAPPINGS,
    IFACE_REMOVE_UNUSED_MASQ,
    __IFACE_MAX
};

enum {
    DHCP_ENABLED,
    DHCP_START,
    DHCP_LIMIT,
    DHCP_LEASETIME,
    __DHCP_MAX
};

enum {
    FW_ENABLED,
    FW_ZONE,
    FW_INPUT,
    FW_OUTPUT,
    FW_FORWARD,
    FW_ALLOW_DHCP,
    FW_ALLOW_DNS,
    FW_FORWARD_TO,
    FW_ENABLE_MASQ,
    __FW_MAX
};

enum {
    APPLY_COMMIT,
    APPLY_RESTART,
    APPLY_SERVICES,
    APPLY_ROLLBACK_TIMEOUT,
    __APPLY_MAX
};

enum {
    MAP_SECTION,
    MAP_NETWORK,
    MAP_DRY_RUN,
    __MAP_MAX
};

static const struct blobmsg_policy iface_policy[__IFACE_MAX] = {
    [IFACE_TYPE] = { .name = "type", .type = BLOBMSG_TYPE_STRING },
    [IFACE_NAME] = { .name = "name", .type = BLOBMSG_TYPE_STRING },
    [IFACE_VLAN_ID] = { .name = "vlan_id", .type = BLOBMSG_TYPE_INT32 },
    [IFACE_PARENT_DEVICE] = { .name = "parent_device", .type = BLOBMSG_TYPE_STRING },
    [IFACE_BRIDGE_NAME] = { .name = "bridge_name", .type = BLOBMSG_TYPE_STRING },
    [IFACE_PROTO] = { .name = "proto", .type = BLOBMSG_TYPE_STRING },
    [IFACE_IPADDR] = { .name = "ipaddr", .type = BLOBMSG_TYPE_STRING },
    [IFACE_NETMASK] = { .name = "netmask", .type = BLOBMSG_TYPE_STRING },
    [IFACE_DHCP] = { .name = "dhcp", .type = BLOBMSG_TYPE_TABLE },
    [IFACE_FIREWALL] = { .name = "firewall", .type = BLOBMSG_TYPE_TABLE },
    [IFACE_DRY_RUN] = { .name = "dry_run", .type = BLOBMSG_TYPE_BOOL },
    [IFACE_FORCE] = { .name = "force", .type = BLOBMSG_TYPE_BOOL },
    [IFACE_DELETE_SSID_MAPPINGS] = { .name = "delete_ssid_mappings", .type = BLOBMSG_TYPE_BOOL },
    [IFACE_REMOVE_UNUSED_MASQ] = { .name = "remove_unused_masq", .type = BLOBMSG_TYPE_BOOL },
};

static const struct blobmsg_policy dhcp_policy[__DHCP_MAX] = {
    [DHCP_ENABLED] = { .name = "enabled", .type = BLOBMSG_TYPE_BOOL },
    [DHCP_START] = { .name = "start", .type = BLOBMSG_TYPE_INT32 },
    [DHCP_LIMIT] = { .name = "limit", .type = BLOBMSG_TYPE_INT32 },
    [DHCP_LEASETIME] = { .name = "leasetime", .type = BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy fw_policy[__FW_MAX] = {
    [FW_ENABLED] = { .name = "enabled", .type = BLOBMSG_TYPE_BOOL },
    [FW_ZONE] = { .name = "zone", .type = BLOBMSG_TYPE_STRING },
    [FW_INPUT] = { .name = "input", .type = BLOBMSG_TYPE_STRING },
    [FW_OUTPUT] = { .name = "output", .type = BLOBMSG_TYPE_STRING },
    [FW_FORWARD] = { .name = "forward", .type = BLOBMSG_TYPE_STRING },
    [FW_ALLOW_DHCP] = { .name = "allow_dhcp", .type = BLOBMSG_TYPE_BOOL },
    [FW_ALLOW_DNS] = { .name = "allow_dns", .type = BLOBMSG_TYPE_BOOL },
    [FW_FORWARD_TO] = { .name = "forward_to", .type = BLOBMSG_TYPE_STRING },
    [FW_ENABLE_MASQ] = { .name = "enable_masquerade_on_uplink", .type = BLOBMSG_TYPE_BOOL },
};

static const struct blobmsg_policy apply_policy[__APPLY_MAX] = {
    [APPLY_COMMIT] = { .name = "commit", .type = BLOBMSG_TYPE_BOOL },
    [APPLY_RESTART] = { .name = "restart", .type = BLOBMSG_TYPE_BOOL },
    [APPLY_SERVICES] = { .name = "services", .type = BLOBMSG_TYPE_ARRAY },
    [APPLY_ROLLBACK_TIMEOUT] = { .name = "rollback_timeout", .type = BLOBMSG_TYPE_INT32 },
};

static const struct blobmsg_policy map_policy[__MAP_MAX] = {
    [MAP_SECTION] = { .name = "section", .type = BLOBMSG_TYPE_STRING },
    [MAP_NETWORK] = { .name = "network", .type = BLOBMSG_TYPE_STRING },
    [MAP_DRY_RUN] = { .name = "dry_run", .type = BLOBMSG_TYPE_BOOL },
};

struct config_data {
    const char *network_json;
    const char *dhcp_json;
    const char *firewall_json;
    const char *wireless_json;
    const char *interfaces_json;
    const char *devices_json;
};

struct plan_data {
    const char *operation;
    const char *type;
    const char *name;
    bool dry_run;
    bool changed;
    const char *plan[MAX_PLAN_ITEMS];
    size_t plan_count;
    const char *requires_restart[4];
    size_t restart_count;
    const char *risk;
    const char *uci_json;
    const char *commit_network_json;
    const char *commit_dhcp_json;
    const char *commit_firewall_json;
    const char *commit_wireless_json;
    const char *reload_json;
};

static void reply_iface_error(struct ubus_context *ctx,
                              struct ubus_request_data *req,
                              const char *code,
                              const char *field,
                              const char *message)
{
    airui_reply_error_schema(ctx, req, code, field, message,
                             AIRUI_IFACE_SOURCE, AIRUI_IFACE_SCHEMA);
}

static bool valid_iface_name(const char *name)
{
    const char *p;

    if (!name || !name[0]) {
        return false;
    }

    for (p = name; *p; p++) {
        if ((*p >= 'a' && *p <= 'z') ||
            (*p >= '0' && *p <= '9') ||
            *p == '_') {
            continue;
        }
        return false;
    }

    return true;
}

static bool valid_device_name(const char *name)
{
    const char *p;

    if (!name || !name[0]) {
        return false;
    }

    for (p = name; *p; p++) {
        if ((*p >= 'a' && *p <= 'z') ||
            (*p >= 'A' && *p <= 'Z') ||
            (*p >= '0' && *p <= '9') ||
            *p == '_' || *p == '-' || *p == '.') {
            continue;
        }
        return false;
    }

    return true;
}

static bool valid_bridge_name(const char *name)
{
    return name && strncmp(name, "br-", 3) == 0 && valid_device_name(name);
}

static bool valid_ipv4(const char *value, uint32_t *out)
{
    struct in_addr addr;

    if (!value || inet_pton(AF_INET, value, &addr) != 1) {
        return false;
    }

    if (out) {
        *out = ntohl(addr.s_addr);
    }
    return true;
}

static bool valid_netmask(uint32_t mask)
{
    uint32_t inverse = ~mask;

    return mask != 0 && mask != UINT32_MAX &&
           (inverse & (inverse + 1U)) == 0;
}

static bool dhcp_range_fits(uint32_t ip, uint32_t mask, int start, int limit)
{
    uint32_t network = ip & mask;
    uint32_t broadcast = network | ~mask;
    uint32_t first = network + (uint32_t)start;
    uint32_t last;

    if (start < 1 || limit < 1) {
        return false;
    }

    last = first + (uint32_t)limit - 1;
    return first > network && last < broadcast && last >= first;
}

static void plan_add(struct plan_data *plan, const char *item)
{
    if (plan->plan_count < MAX_PLAN_ITEMS) {
        plan->plan[plan->plan_count++] = item;
    }
}

static void restart_add(struct plan_data *plan, const char *service)
{
    if (plan->restart_count < 4) {
        plan->requires_restart[plan->restart_count++] = service;
    }
}

static void add_json_object(struct blob_buf *b,
                            const char *name,
                            const char *json,
                            bool sanitize)
{
    struct json_object *obj;
    void *empty;

    if (!json) {
        empty = blobmsg_open_table(b, name);
        blobmsg_close_table(b, empty);
        return;
    }

    obj = json_tokener_parse(json);
    if (!obj) {
        empty = blobmsg_open_table(b, name);
        blobmsg_close_table(b, empty);
        return;
    }

    if (sanitize && json_object_is_type(obj, json_type_object)) {
        json_object_object_foreach(obj, key, val) {
            (void)val;
            if (strstr(key, "key") || strstr(key, "password") ||
                strstr(key, "secret")) {
                json_object_object_add(obj, key, json_object_new_string("******"));
            }
        }
    }

    if (!blobmsg_add_json_element(b, name, obj)) {
        empty = blobmsg_open_table(b, name);
        blobmsg_close_table(b, empty);
    }
    json_object_put(obj);
}

static int uci_get_config(struct ubus_context *ctx,
                          const char *config,
                          struct airui_ubus_result *result)
{
    struct blob_buf query = {};
    int ret;

    blob_buf_init(&query, 0);
    blobmsg_add_string(&query, "config", config);
    ret = airui_ubus_call_json(ctx, "uci", "get", &query, result);
    blob_buf_free(&query);
    return ret;
}

static int uci_section_exists(struct ubus_context *ctx,
                              const char *config,
                              const char *section)
{
    struct blob_buf query = {};
    struct airui_ubus_result result = {};
    struct json_object *root = NULL;
    struct json_object *values = NULL;
    int exists = 0;
    int ret;

    blob_buf_init(&query, 0);
    blobmsg_add_string(&query, "config", config);
    blobmsg_add_string(&query, "section", section);
    ret = airui_ubus_call_json(ctx, "uci", "get", &query, &result);
    blob_buf_free(&query);

    if (ret == 0 && result.json) {
        root = json_tokener_parse(result.json);

        if (root &&
            json_object_object_get_ex(root, "values", &values) &&
            json_object_is_type(values, json_type_object) &&
            json_object_object_length(values) > 0) {
            exists = 1;
        }
    }

    if (root) {
        json_object_put(root);
    }

    airui_ubus_result_free(&result);
    return exists;
}

static int uci_add_named(struct ubus_context *ctx,
                         const char *config,
                         const char *type,
                         const char *name,
                         struct blob_buf *values,
                         struct airui_ubus_result *result)
{
    struct blob_buf b = {};
    int ret;

    blob_buf_init(&b, 0);
    blobmsg_add_string(&b, "config", config);
    blobmsg_add_string(&b, "type", type);
    blobmsg_add_string(&b, "name", name);
    if (values && values->head) {
        blobmsg_add_field(&b, BLOBMSG_TYPE_TABLE, "values",
                          blobmsg_data(values->head),
                          blobmsg_data_len(values->head));
    }
    ret = airui_ubus_call_json(ctx, "uci", "add", &b, result);
    blob_buf_free(&b);
    return ret;
}

static int uci_set_values(struct ubus_context *ctx,
                          const char *config,
                          const char *section,
                          struct blob_buf *values,
                          struct airui_ubus_result *result)
{
    struct blob_buf b = {};
    int ret;

    blob_buf_init(&b, 0);
    blobmsg_add_string(&b, "config", config);
    blobmsg_add_string(&b, "section", section);
    if (values && values->head) {
        blobmsg_add_field(&b, BLOBMSG_TYPE_TABLE, "values",
                          blobmsg_data(values->head),
                          blobmsg_data_len(values->head));
    }
    ret = airui_ubus_call_json(ctx, "uci", "set", &b, result);
    blob_buf_free(&b);
    return ret;
}

static int uci_delete_section(struct ubus_context *ctx,
                              const char *config,
                              const char *section,
                              struct airui_ubus_result *result)
{
    struct blob_buf b = {};
    int ret;

    blob_buf_init(&b, 0);
    blobmsg_add_string(&b, "config", config);
    blobmsg_add_string(&b, "section", section);
    ret = airui_ubus_call_json(ctx, "uci", "delete", &b, result);
    blob_buf_free(&b);
    return ret;
}

static int uci_commit_config(struct ubus_context *ctx,
                             const char *config,
                             struct airui_ubus_result *result)
{
    struct blob_buf b = {};
    int ret;

    blob_buf_init(&b, 0);
    blobmsg_add_string(&b, "config", config);
    ret = airui_ubus_call_json(ctx, "uci", "commit", &b, result);
    blob_buf_free(&b);
    return ret;
}

static void uci_revert_config(struct ubus_context *ctx, const char *config)
{
    struct blob_buf b = {};
    struct airui_ubus_result result = {};

    blob_buf_init(&b, 0);
    blobmsg_add_string(&b, "config", config);
    airui_ubus_call_json(ctx, "uci", "revert", &b, &result);
    airui_ubus_result_free(&result);
    blob_buf_free(&b);
}

static void revert_interface_changes(struct ubus_context *ctx)
{
    uci_revert_config(ctx, "network");
    uci_revert_config(ctx, "dhcp");
    uci_revert_config(ctx, "firewall");
    uci_revert_config(ctx, "wireless");
}

static void add_common_managed_values(struct blob_buf *values, const char *type)
{
    blobmsg_add_string(values, "airui_managed", "1");
    blobmsg_add_string(values, "airui_type", type);
}

static void add_config_builder(struct blob_buf *b, void *user)
{
    struct config_data *data = user;
    void *uci;
    void *runtime;
    void *capabilities;
    void *detected;
    void *bridges;
    void *vlans;
    void *routes;
    void *firewall;

    uci = blobmsg_open_table(b, "uci");
    add_json_object(b, "network", data ? data->network_json : NULL, true);
    add_json_object(b, "dhcp", data ? data->dhcp_json : NULL, true);
    add_json_object(b, "firewall", data ? data->firewall_json : NULL, true);
    add_json_object(b, "wireless", data ? data->wireless_json : NULL, true);
    blobmsg_close_table(b, uci);

    runtime = blobmsg_open_table(b, "runtime");
    add_json_object(b, "interfaces", data ? data->interfaces_json : NULL, false);
    add_json_object(b, "devices", data ? data->devices_json : NULL, false);
    bridges = blobmsg_open_table(b, "bridges");
    blobmsg_close_table(b, bridges);
    vlans = blobmsg_open_table(b, "vlans");
    blobmsg_close_table(b, vlans);
    routes = blobmsg_open_table(b, "routes");
    blobmsg_close_table(b, routes);
    firewall = blobmsg_open_table(b, "firewall");
    blobmsg_close_table(b, firewall);
    blobmsg_close_table(b, runtime);

    capabilities = blobmsg_open_table(b, "capabilities");
    blobmsg_add_u8(b, "supports_vlan", true);
    blobmsg_add_u8(b, "supports_nat", true);
    blobmsg_add_u8(b, "supports_dhcp", true);
    blobmsg_add_u8(b, "supports_firewall", true);
    blobmsg_add_u8(b, "supports_ssid_mapping", true);
    blobmsg_close_table(b, capabilities);

    detected = blobmsg_open_table(b, "detected");
    blobmsg_add_string(b, "uplink_device", "wan");
    blobmsg_add_string(b, "uplink_network", "lan");
    blobmsg_add_string(b, "uplink_firewall_zone", "wan");
    blobmsg_close_table(b, detected);
}

static void plan_builder(struct blob_buf *b, void *user)
{
    struct plan_data *data = user;
    void *plan;
    void *restarts;

    if (!data) {
        return;
    }

    blobmsg_add_string(b, "operation", data->operation ? data->operation : "");
    blobmsg_add_string(b, "type", data->type ? data->type : "");
    blobmsg_add_string(b, "name", data->name ? data->name : "");
    blobmsg_add_u8(b, "dry_run", data->dry_run);
    blobmsg_add_u8(b, "changed", data->changed);

    plan = blobmsg_open_array(b, "plan");
    for (size_t i = 0; i < data->plan_count; i++) {
        blobmsg_add_string(b, NULL, data->plan[i]);
    }
    blobmsg_close_array(b, plan);

    restarts = blobmsg_open_array(b, "requires_restart");
    for (size_t i = 0; i < data->restart_count; i++) {
        blobmsg_add_string(b, NULL, data->requires_restart[i]);
    }
    blobmsg_close_array(b, restarts);

    blobmsg_add_string(b, "risk", data->risk ? data->risk : "network_reload");
    add_json_object(b, "uci_action", data->uci_json, false);
    add_json_object(b, "commit_network", data->commit_network_json, false);
    add_json_object(b, "commit_dhcp", data->commit_dhcp_json, false);
    add_json_object(b, "commit_firewall", data->commit_firewall_json, false);
    add_json_object(b, "commit_wireless", data->commit_wireless_json, false);
    add_json_object(b, "reload", data->reload_json, false);
}

static bool validate_vlan_bridge(struct ubus_context *ctx,
                                 struct ubus_request_data *req,
                                 struct blob_attr **tb,
                                 struct plan_data *plan,
                                 bool creating)
{
    const char *name;
    const char *parent;
    const char *bridge;
    int vlan_id;

    if (!tb[IFACE_NAME] || !tb[IFACE_VLAN_ID] ||
        !tb[IFACE_PARENT_DEVICE] || !tb[IFACE_BRIDGE_NAME]) {
        reply_iface_error(ctx, req, "VALIDATION_FAILED", NULL,
                          "vlan_bridge requires name, vlan_id, parent_device, and bridge_name");
        return false;
    }

    name = blobmsg_get_string(tb[IFACE_NAME]);
    parent = blobmsg_get_string(tb[IFACE_PARENT_DEVICE]);
    bridge = blobmsg_get_string(tb[IFACE_BRIDGE_NAME]);
    vlan_id = blobmsg_get_u32(tb[IFACE_VLAN_ID]);

    if (!valid_iface_name(name)) {
        reply_iface_error(ctx, req, "VALIDATION_FAILED", "name",
                          "Interface name must use lowercase letters, numbers, and underscore only");
        return false;
    }

    if (creating && uci_section_exists(ctx, "network", name)) {
        reply_iface_error(ctx, req, "VALIDATION_FAILED", "name",
                          "Network interface already exists");
        return false;
    }
    if (!creating && !uci_section_exists(ctx, "network", name)) {
        reply_iface_error(ctx, req, "NOT_FOUND", "name",
                          "Network interface does not exist");
        return false;
    }

    if (vlan_id < 1 || vlan_id > 4094) {
        reply_iface_error(ctx, req, "VALIDATION_FAILED", "vlan_id",
                          "VLAN ID must be between 1 and 4094");
        return false;
    }

    if (!valid_device_name(parent)) {
        reply_iface_error(ctx, req, "VALIDATION_FAILED", "parent_device",
                          "Parent device contains unsupported characters");
        return false;
    }

    if (!valid_bridge_name(bridge)) {
        reply_iface_error(ctx, req, "VALIDATION_FAILED", "bridge_name",
                          "Bridge name must start with br- and contain only safe device characters");
        return false;
    }

    plan_add(plan, creating ? "create network vlan device" : "update network vlan device");
    plan_add(plan, creating ? "create network bridge device" : "update network bridge device");
    plan_add(plan, creating ? "create network interface" : "update network interface");
    plan_add(plan, "create or update firewall zone when enabled");
    restart_add(plan, "network");
    restart_add(plan, "firewall");
    return true;
}

static bool validate_nat(struct ubus_context *ctx,
                         struct ubus_request_data *req,
                         struct blob_attr **tb,
                         struct blob_attr **dhcp,
                         struct plan_data *plan,
                         bool creating)
{
    const char *name;
    const char *bridge;
    const char *ipaddr;
    const char *netmask;
    uint32_t ip;
    uint32_t mask;

    if (!tb[IFACE_NAME] || !tb[IFACE_BRIDGE_NAME] ||
        !tb[IFACE_IPADDR] || !tb[IFACE_NETMASK]) {
        reply_iface_error(ctx, req, "VALIDATION_FAILED", NULL,
                          "nat requires name, bridge_name, ipaddr, and netmask");
        return false;
    }

    name = blobmsg_get_string(tb[IFACE_NAME]);
    bridge = blobmsg_get_string(tb[IFACE_BRIDGE_NAME]);
    ipaddr = blobmsg_get_string(tb[IFACE_IPADDR]);
    netmask = blobmsg_get_string(tb[IFACE_NETMASK]);

    if (!valid_iface_name(name)) {
        reply_iface_error(ctx, req, "VALIDATION_FAILED", "name",
                          "Interface name must use lowercase letters, numbers, and underscore only");
        return false;
    }

    if (creating && uci_section_exists(ctx, "network", name)) {
        reply_iface_error(ctx, req, "VALIDATION_FAILED", "name",
                          "Network interface already exists");
        return false;
    }
    if (!creating && !uci_section_exists(ctx, "network", name)) {
        reply_iface_error(ctx, req, "NOT_FOUND", "name",
                          "Network interface does not exist");
        return false;
    }

    if (!valid_bridge_name(bridge)) {
        reply_iface_error(ctx, req, "VALIDATION_FAILED", "bridge_name",
                          "Bridge name must start with br- and contain only safe device characters");
        return false;
    }

    if (!valid_ipv4(ipaddr, &ip) || !valid_ipv4(netmask, &mask) ||
        !valid_netmask(mask)) {
        reply_iface_error(ctx, req, "VALIDATION_FAILED", "ipaddr",
                          "NAT IP address and netmask must be valid IPv4 values");
        return false;
    }

    if (dhcp[DHCP_ENABLED] && blobmsg_get_bool(dhcp[DHCP_ENABLED])) {
        int start = dhcp[DHCP_START] ? blobmsg_get_u32(dhcp[DHCP_START]) : 100;
        int limit = dhcp[DHCP_LIMIT] ? blobmsg_get_u32(dhcp[DHCP_LIMIT]) : 100;

        if (!dhcp_range_fits(ip, mask, start, limit)) {
            reply_iface_error(ctx, req, "VALIDATION_FAILED", "dhcp",
                              "DHCP range must fit inside the NAT subnet");
            return false;
        }
    }

    plan_add(plan, creating ? "create network bridge device" : "update network bridge device");
    plan_add(plan, creating ? "create static network interface" : "update static network interface");
    plan_add(plan, "create or update DHCP scope when enabled");
    plan_add(plan, "create or update firewall zone, rules, forwarding, and uplink masquerade");
    restart_add(plan, "network");
    restart_add(plan, "dnsmasq");
    restart_add(plan, "firewall");
    return true;
}

static void parse_nested(struct blob_attr **tb,
                         struct blob_attr **dhcp,
                         struct blob_attr **fw)
{
    memset(dhcp, 0, sizeof(struct blob_attr *) * __DHCP_MAX);
    memset(fw, 0, sizeof(struct blob_attr *) * __FW_MAX);

    if (tb[IFACE_DHCP]) {
        blobmsg_parse(dhcp_policy, __DHCP_MAX, dhcp,
                      blobmsg_data(tb[IFACE_DHCP]), blobmsg_data_len(tb[IFACE_DHCP]));
    }
    if (tb[IFACE_FIREWALL]) {
        blobmsg_parse(fw_policy, __FW_MAX, fw,
                      blobmsg_data(tb[IFACE_FIREWALL]), blobmsg_data_len(tb[IFACE_FIREWALL]));
    }
}

static bool validate_interface_payload(struct ubus_context *ctx,
                                       struct ubus_request_data *req,
                                       struct blob_attr **tb,
                                       struct blob_attr **dhcp,
                                       struct blob_attr **fw,
                                       struct plan_data *plan,
                                       bool creating)
{
    const char *type;

    if (!tb[IFACE_TYPE]) {
        reply_iface_error(ctx, req, "VALIDATION_FAILED", "type",
                          "Interface type is required");
        return false;
    }

    parse_nested(tb, dhcp, fw);

    type = blobmsg_get_string(tb[IFACE_TYPE]);
    plan->type = type;
    plan->name = tb[IFACE_NAME] ? blobmsg_get_string(tb[IFACE_NAME]) : "";
    plan->risk = "network_reload";

    if (strcmp(type, "vlan_bridge") == 0) {
        return validate_vlan_bridge(ctx, req, tb, plan, creating);
    }
    if (strcmp(type, "nat") == 0) {
        return validate_nat(ctx, req, tb, dhcp, plan, creating);
    }

    reply_iface_error(ctx, req, "VALIDATION_FAILED", "type",
                      "Interface type must be vlan_bridge or nat");
    return false;
}

static int apply_vlan_bridge(struct ubus_context *ctx,
                             struct blob_attr **tb,
                             struct blob_attr **fw,
                             struct airui_ubus_result *result,
                             bool creating)
{
    struct blob_buf values = {};
    char vlan_dev_section[64];
    char bridge_section[64];
    char vlan_dev_name[64];
    const char *name = blobmsg_get_string(tb[IFACE_NAME]);
    const char *parent = blobmsg_get_string(tb[IFACE_PARENT_DEVICE]);
    const char *bridge = blobmsg_get_string(tb[IFACE_BRIDGE_NAME]);
    const char *zone = fw[FW_ZONE] ? blobmsg_get_string(fw[FW_ZONE]) : name;
    int vlan_id = blobmsg_get_u32(tb[IFACE_VLAN_ID]);
    int ret;

    snprintf(vlan_dev_section, sizeof(vlan_dev_section), "%s_dev", name);
    snprintf(bridge_section, sizeof(bridge_section), "br_%s", name);
    snprintf(vlan_dev_name, sizeof(vlan_dev_name), "%s.%d", parent, vlan_id);

    blob_buf_init(&values, 0);
    blobmsg_add_string(&values, "name", vlan_dev_name);
    blobmsg_add_string(&values, "type", "8021q");
    blobmsg_add_string(&values, "ifname", parent);
    blobmsg_add_u32(&values, "vid", vlan_id);
    add_common_managed_values(&values, "vlan_bridge");
    ret = creating ?
          uci_add_named(ctx, "network", "device", vlan_dev_section, &values, result) :
          uci_set_values(ctx, "network", vlan_dev_section, &values, result);
    blob_buf_free(&values);
    if (ret) {
        return ret;
    }

    blob_buf_init(&values, 0);
    blobmsg_add_string(&values, "name", bridge);
    blobmsg_add_string(&values, "type", "bridge");
    blobmsg_add_string(&values, "bridge_empty", "1");
    {
        void *ports = blobmsg_open_array(&values, "ports");
        blobmsg_add_string(&values, NULL, vlan_dev_name);
        blobmsg_close_array(&values, ports);
    }
    add_common_managed_values(&values, "vlan_bridge");
    ret = creating ?
          uci_add_named(ctx, "network", "device", bridge_section, &values, result) :
          uci_set_values(ctx, "network", bridge_section, &values, result);
    blob_buf_free(&values);
    if (ret) {
        return ret;
    }

    blob_buf_init(&values, 0);
    blobmsg_add_string(&values, "device", bridge);
    blobmsg_add_string(&values, "proto", tb[IFACE_PROTO] ? blobmsg_get_string(tb[IFACE_PROTO]) : "none");
    add_common_managed_values(&values, "vlan_bridge");
    ret = creating ?
          uci_add_named(ctx, "network", "interface", name, &values, result) :
          uci_set_values(ctx, "network", name, &values, result);
    blob_buf_free(&values);
    if (ret) {
        return ret;
    }

    if (!fw[FW_ENABLED] || blobmsg_get_bool(fw[FW_ENABLED])) {
        blob_buf_init(&values, 0);
        blobmsg_add_string(&values, "name", zone);
        blobmsg_add_string(&values, "network", name);
        blobmsg_add_string(&values, "input", fw[FW_INPUT] ? blobmsg_get_string(fw[FW_INPUT]) : "REJECT");
        blobmsg_add_string(&values, "output", fw[FW_OUTPUT] ? blobmsg_get_string(fw[FW_OUTPUT]) : "ACCEPT");
        blobmsg_add_string(&values, "forward", fw[FW_FORWARD] ? blobmsg_get_string(fw[FW_FORWARD]) : "REJECT");
        add_common_managed_values(&values, "vlan_bridge");
        ret = creating ?
              uci_add_named(ctx, "firewall", "zone", zone, &values, result) :
              uci_set_values(ctx, "firewall", zone, &values, result);
        blob_buf_free(&values);
    }

    return ret;
}

static int apply_nat(struct ubus_context *ctx,
                     struct blob_attr **tb,
                     struct blob_attr **dhcp,
                     struct blob_attr **fw,
                     struct airui_ubus_result *result,
                     bool creating)
{
    struct blob_buf values = {};
    char dev_section[64];
    char dhcp_rule[64];
    char dns_rule[64];
    char forwarding[64];
    const char *name = blobmsg_get_string(tb[IFACE_NAME]);
    const char *bridge = blobmsg_get_string(tb[IFACE_BRIDGE_NAME]);
    const char *zone = fw[FW_ZONE] ? blobmsg_get_string(fw[FW_ZONE]) : name;
    const char *forward_to = fw[FW_FORWARD_TO] ? blobmsg_get_string(fw[FW_FORWARD_TO]) : "wan";
    int ret;

    snprintf(dev_section, sizeof(dev_section), "%s_dev", name);
    snprintf(dhcp_rule, sizeof(dhcp_rule), "%s_dhcp", zone);
    snprintf(dns_rule, sizeof(dns_rule), "%s_dns", zone);
    snprintf(forwarding, sizeof(forwarding), "%s_to_%s", zone, forward_to);

    blob_buf_init(&values, 0);
    blobmsg_add_string(&values, "name", bridge);
    blobmsg_add_string(&values, "type", "bridge");
    blobmsg_add_string(&values, "bridge_empty", "1");
    add_common_managed_values(&values, "nat");
    ret = creating ?
          uci_add_named(ctx, "network", "device", dev_section, &values, result) :
          uci_set_values(ctx, "network", dev_section, &values, result);
    blob_buf_free(&values);
    if (ret) {
        return ret;
    }

    blob_buf_init(&values, 0);
    blobmsg_add_string(&values, "device", bridge);
    blobmsg_add_string(&values, "proto", "static");
    blobmsg_add_string(&values, "ipaddr", blobmsg_get_string(tb[IFACE_IPADDR]));
    blobmsg_add_string(&values, "netmask", blobmsg_get_string(tb[IFACE_NETMASK]));
    add_common_managed_values(&values, "nat");
    ret = creating ?
          uci_add_named(ctx, "network", "interface", name, &values, result) :
          uci_set_values(ctx, "network", name, &values, result);
    blob_buf_free(&values);
    if (ret) {
        return ret;
    }

    if (!dhcp[DHCP_ENABLED] || blobmsg_get_bool(dhcp[DHCP_ENABLED])) {
        blob_buf_init(&values, 0);
        blobmsg_add_string(&values, "interface", name);
        blobmsg_add_u32(&values, "start", dhcp[DHCP_START] ? blobmsg_get_u32(dhcp[DHCP_START]) : 100);
        blobmsg_add_u32(&values, "limit", dhcp[DHCP_LIMIT] ? blobmsg_get_u32(dhcp[DHCP_LIMIT]) : 100);
        blobmsg_add_string(&values, "leasetime", dhcp[DHCP_LEASETIME] ? blobmsg_get_string(dhcp[DHCP_LEASETIME]) : "12h");
        add_common_managed_values(&values, "nat");
        ret = creating ?
              uci_add_named(ctx, "dhcp", "dhcp", name, &values, result) :
              uci_set_values(ctx, "dhcp", name, &values, result);
        blob_buf_free(&values);
        if (ret) {
            return ret;
        }
    }

    blob_buf_init(&values, 0);
    blobmsg_add_string(&values, "name", zone);
    blobmsg_add_string(&values, "network", name);
    blobmsg_add_string(&values, "input", fw[FW_INPUT] ? blobmsg_get_string(fw[FW_INPUT]) : "REJECT");
    blobmsg_add_string(&values, "output", fw[FW_OUTPUT] ? blobmsg_get_string(fw[FW_OUTPUT]) : "ACCEPT");
    blobmsg_add_string(&values, "forward", fw[FW_FORWARD] ? blobmsg_get_string(fw[FW_FORWARD]) : "REJECT");
    add_common_managed_values(&values, "nat");
    ret = creating ?
          uci_add_named(ctx, "firewall", "zone", zone, &values, result) :
          uci_set_values(ctx, "firewall", zone, &values, result);
    blob_buf_free(&values);
    if (ret) {
        return ret;
    }

    if (fw[FW_ALLOW_DHCP] && blobmsg_get_bool(fw[FW_ALLOW_DHCP])) {
        blob_buf_init(&values, 0);
        blobmsg_add_string(&values, "name", "Allow-NAT-DHCP");
        blobmsg_add_string(&values, "src", zone);
        blobmsg_add_string(&values, "proto", "udp");
        blobmsg_add_string(&values, "dest_port", "67");
        blobmsg_add_string(&values, "target", "ACCEPT");
        add_common_managed_values(&values, "nat");
        ret = creating ?
              uci_add_named(ctx, "firewall", "rule", dhcp_rule, &values, result) :
              uci_set_values(ctx, "firewall", dhcp_rule, &values, result);
        blob_buf_free(&values);
        if (ret) {
            return ret;
        }
    }

    if (fw[FW_ALLOW_DNS] && blobmsg_get_bool(fw[FW_ALLOW_DNS])) {
        blob_buf_init(&values, 0);
        blobmsg_add_string(&values, "name", "Allow-NAT-DNS");
        blobmsg_add_string(&values, "src", zone);
        blobmsg_add_string(&values, "proto", "tcp udp");
        blobmsg_add_string(&values, "dest_port", "53");
        blobmsg_add_string(&values, "target", "ACCEPT");
        add_common_managed_values(&values, "nat");
        ret = creating ?
              uci_add_named(ctx, "firewall", "rule", dns_rule, &values, result) :
              uci_set_values(ctx, "firewall", dns_rule, &values, result);
        blob_buf_free(&values);
        if (ret) {
            return ret;
        }
    }

    blob_buf_init(&values, 0);
    blobmsg_add_string(&values, "src", zone);
    blobmsg_add_string(&values, "dest", forward_to);
    add_common_managed_values(&values, "nat");
    ret = creating ?
          uci_add_named(ctx, "firewall", "forwarding", forwarding, &values, result) :
          uci_set_values(ctx, "firewall", forwarding, &values, result);
    blob_buf_free(&values);
    return ret;
}

static int interface_upsert(struct ubus_context *ctx,
                            struct ubus_request_data *req,
                            struct blob_attr *msg,
                            const char *operation,
                            bool creating,
                            bool force_dry_run)
{
    struct blob_attr *tb[__IFACE_MAX];
    struct blob_attr *dhcp[__DHCP_MAX];
    struct blob_attr *fw[__FW_MAX];
    struct plan_data plan = {};
    struct airui_ubus_result action = {};
    bool dry_run;
    int ret;

    blobmsg_parse(iface_policy, __IFACE_MAX, tb,
                  msg ? blob_data(msg) : NULL,
                  msg ? blob_len(msg) : 0);

    dry_run = force_dry_run ||
              (tb[IFACE_DRY_RUN] && blobmsg_get_bool(tb[IFACE_DRY_RUN]));
    plan.operation = operation;
    plan.dry_run = dry_run;
    plan.changed = !dry_run;

    if (!validate_interface_payload(ctx, req, tb, dhcp, fw, &plan, creating)) {
        return 0;
    }

    if (!dry_run) {
        if (strcmp(plan.type, "vlan_bridge") == 0) {
            ret = apply_vlan_bridge(ctx, tb, fw, &action, creating);
        } else {
            ret = apply_nat(ctx, tb, dhcp, fw, &action, creating);
        }
        if (ret) {
            revert_interface_changes(ctx);
            reply_iface_error(ctx, req, "BACKEND_FAILED", "uci", ubus_strerror(ret));
            airui_ubus_result_free(&action);
            return 0;
        }
        plan.uci_json = action.json;
    }

    airui_reply_ok_schema(ctx, req, plan_builder, &plan,
                          AIRUI_IFACE_SOURCE, AIRUI_IFACE_SCHEMA);
    airui_ubus_result_free(&action);
    return 0;
}

int airui_network_interface_config(struct ubus_context *ctx,
                                   struct ubus_object *obj,
                                   struct ubus_request_data *req,
                                   const char *method,
                                   struct blob_attr *msg)
{
    struct airui_ubus_result network = {};
    struct airui_ubus_result dhcp = {};
    struct airui_ubus_result firewall = {};
    struct airui_ubus_result wireless = {};
    struct airui_ubus_result interfaces = {};
    struct airui_ubus_result devices = {};
    struct config_data data;

    (void)obj;
    (void)method;
    (void)msg;

    uci_get_config(ctx, "network", &network);
    uci_get_config(ctx, "dhcp", &dhcp);
    uci_get_config(ctx, "firewall", &firewall);
    uci_get_config(ctx, "wireless", &wireless);
    airui_ubus_call_json(ctx, "network.interface", "dump", NULL, &interfaces);
    airui_ubus_call_json(ctx, "network.device", "status", NULL, &devices);

    data.network_json = network.json;
    data.dhcp_json = dhcp.json;
    data.firewall_json = firewall.json;
    data.wireless_json = wireless.json;
    data.interfaces_json = interfaces.json;
    data.devices_json = devices.json;

    airui_reply_ok_schema(ctx, req, add_config_builder, &data,
                          AIRUI_IFACE_SOURCE, AIRUI_IFACE_SCHEMA);

    airui_ubus_result_free(&network);
    airui_ubus_result_free(&dhcp);
    airui_ubus_result_free(&firewall);
    airui_ubus_result_free(&wireless);
    airui_ubus_result_free(&interfaces);
    airui_ubus_result_free(&devices);
    return 0;
}

int airui_network_interface_validate(struct ubus_context *ctx,
                                     struct ubus_object *obj,
                                     struct ubus_request_data *req,
                                     const char *method,
                                     struct blob_attr *msg)
{
    (void)obj;
    (void)method;
    return interface_upsert(ctx, req, msg, "validate", true, true);
}

int airui_network_interface_add(struct ubus_context *ctx,
                                struct ubus_object *obj,
                                struct ubus_request_data *req,
                                const char *method,
                                struct blob_attr *msg)
{
    (void)obj;
    (void)method;
    return interface_upsert(ctx, req, msg, "add", true, false);
}

int airui_network_interface_set(struct ubus_context *ctx,
                                struct ubus_object *obj,
                                struct ubus_request_data *req,
                                const char *method,
                                struct blob_attr *msg)
{
    (void)obj;
    (void)method;
    return interface_upsert(ctx, req, msg, "set", false, false);
}

int airui_network_interface_delete(struct ubus_context *ctx,
                                   struct ubus_object *obj,
                                   struct ubus_request_data *req,
                                   const char *method,
                                   struct blob_attr *msg)
{
    struct blob_attr *tb[__IFACE_MAX];
    struct plan_data plan = {};
    struct airui_ubus_result action = {};
    char dev_section[64];
    char bridge_section[64];
    bool dry_run;
    const char *name;

    (void)obj;
    (void)method;

    blobmsg_parse(iface_policy, __IFACE_MAX, tb,
                  msg ? blob_data(msg) : NULL,
                  msg ? blob_len(msg) : 0);

    if (!tb[IFACE_NAME]) {
        reply_iface_error(ctx, req, "VALIDATION_FAILED", "name",
                          "Interface name is required");
        return 0;
    }

    name = blobmsg_get_string(tb[IFACE_NAME]);
    if (!valid_iface_name(name)) {
        reply_iface_error(ctx, req, "VALIDATION_FAILED", "name",
                          "Interface name must use lowercase letters, numbers, and underscore only");
        return 0;
    }

    if (strcmp(name, "lan") == 0 || strcmp(name, "wan") == 0 ||
        strcmp(name, "loopback") == 0 || strcmp(name, "management") == 0) {
        reply_iface_error(ctx, req, "PROTECTED_INTERFACE", "name",
                          "Core management interfaces cannot be deleted");
        return 0;
    }

    if (!uci_section_exists(ctx, "network", name)) {
        reply_iface_error(ctx, req, "NOT_FOUND", "name",
                          "Network interface does not exist");
        return 0;
    }

    dry_run = tb[IFACE_DRY_RUN] && blobmsg_get_bool(tb[IFACE_DRY_RUN]);
    plan.operation = "delete";
    plan.name = name;
    plan.type = "interface";
    plan.dry_run = dry_run;
    plan.changed = !dry_run;
    plan.risk = "network_reload";
    plan_add(&plan, "delete network interface");
    plan_add(&plan, "delete owned bridge and VLAN device sections");
    plan_add(&plan, "delete owned DHCP and firewall sections");
    plan_add(&plan, "refuse SSID mappings unless delete_ssid_mappings is true");
    restart_add(&plan, "network");
    restart_add(&plan, "dnsmasq");
    restart_add(&plan, "firewall");

    if (!dry_run) {
        int ret = 0;

        snprintf(dev_section, sizeof(dev_section), "%s_dev", name);
        snprintf(bridge_section, sizeof(bridge_section), "br_%s", name);
        ret = uci_delete_section(ctx, "network", name, &action);
        if (!ret && uci_section_exists(ctx, "network", dev_section))
            ret = uci_delete_section(ctx, "network", dev_section, &action);
        if (!ret && uci_section_exists(ctx, "network", bridge_section))
            ret = uci_delete_section(ctx, "network", bridge_section, &action);
        if (!ret && uci_section_exists(ctx, "dhcp", name))
            ret = uci_delete_section(ctx, "dhcp", name, &action);
        if (!ret && uci_section_exists(ctx, "firewall", name))
            ret = uci_delete_section(ctx, "firewall", name, &action);
        if (ret) {
            revert_interface_changes(ctx);
            reply_iface_error(ctx, req, "BACKEND_FAILED", "uci", ubus_strerror(ret));
            airui_ubus_result_free(&action);
            return 0;
        }
        plan.uci_json = action.json;
    }

    airui_reply_ok_schema(ctx, req, plan_builder, &plan,
                          AIRUI_IFACE_SOURCE, AIRUI_IFACE_SCHEMA);
    airui_ubus_result_free(&action);
    return 0;
}

static bool command_succeeded(int status)
{
    return status != -1 && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static bool backup_configs(void)
{
    return command_succeeded(system("cp -f /etc/config/network /etc/config/network.airui.bak")) &&
           command_succeeded(system("cp -f /etc/config/dhcp /etc/config/dhcp.airui.bak")) &&
           command_succeeded(system("cp -f /etc/config/firewall /etc/config/firewall.airui.bak")) &&
           command_succeeded(system("cp -f /etc/config/wireless /etc/config/wireless.airui.bak"));
}

static bool restore_configs(void)
{
    return command_succeeded(system("cp -f /etc/config/network.airui.bak /etc/config/network")) &&
           command_succeeded(system("cp -f /etc/config/dhcp.airui.bak /etc/config/dhcp")) &&
           command_succeeded(system("cp -f /etc/config/firewall.airui.bak /etc/config/firewall")) &&
           command_succeeded(system("cp -f /etc/config/wireless.airui.bak /etc/config/wireless"));
}

static bool valid_apply_service(const char *service)
{
    return strcmp(service, "network") == 0 ||
           strcmp(service, "dnsmasq") == 0 ||
           strcmp(service, "firewall") == 0 ||
           strcmp(service, "wireless") == 0;
}

static int restart_apply_service(struct ubus_context *ctx, const char *service,
                                 struct airui_ubus_result *network_result)
{
    char command[96];

    if (strcmp(service, "network") == 0) {
        bool recovered = false;
        return airui_network_reload_with_recovery(ctx, network_result, 15,
                                                   &recovered);
    }
    if (strcmp(service, "wireless") == 0)
        return command_succeeded(system("wifi reload")) ? 0 : -1;

    snprintf(command, sizeof(command), "/etc/init.d/%s restart", service);
    return command_succeeded(system(command)) ? 0 : -1;
}

static bool apply_service_healthy(struct ubus_context *ctx, const char *service)
{
    struct airui_ubus_result result = {};
    struct json_object *root = NULL;
    struct json_object *interfaces = NULL;
    char command[96];
    int ret;

    if (strcmp(service, "network") == 0) {
        ret = airui_ubus_call_json(ctx, "network.interface", "dump", NULL, &result);
        if (ret == 0 && result.json)
            root = json_tokener_parse(result.json);
        if (root)
            json_object_object_get_ex(root, "interface", &interfaces);
        if (!interfaces || !json_object_is_type(interfaces, json_type_array))
            ret = -1;
        if (ret == 0) {
            size_t i;
            bool connected = false;

            for (i = 0; i < json_object_array_length(interfaces); i++) {
                struct json_object *entry = json_object_array_get_idx(interfaces, i);
                struct json_object *name = NULL;
                struct json_object *up = NULL;

                if (!entry ||
                    !json_object_object_get_ex(entry, "interface", &name) ||
                    !json_object_object_get_ex(entry, "up", &up))
                    continue;
                if (strcmp(json_object_get_string(name), "loopback") != 0 &&
                    json_object_get_boolean(up)) {
                    connected = true;
                    break;
                }
            }
            if (!connected)
                ret = -1;
        }
        if (root)
            json_object_put(root);
        airui_ubus_result_free(&result);
        return ret == 0;
    }
    if (strcmp(service, "wireless") == 0)
        return command_succeeded(system("wifi status >/dev/null 2>&1"));
    if (strcmp(service, "firewall") == 0)
        return command_succeeded(system("/sbin/fw4 check >/dev/null 2>&1"));

    snprintf(command, sizeof(command), "/etc/init.d/%s running >/dev/null 2>&1", service);
    return command_succeeded(system(command));
}

static bool services_healthy(struct ubus_context *ctx,
                             const char **services, size_t count)
{
    size_t i;

    for (i = 0; i < count; i++) {
        if (!apply_service_healthy(ctx, services[i]))
            return false;
    }
    return true;
}

static bool wait_for_services(struct ubus_context *ctx,
                              const char **services, size_t count,
                              int timeout)
{
    int elapsed;

    for (elapsed = 0; elapsed <= timeout; elapsed++) {
        if (services_healthy(ctx, services, count))
            return true;
        if (elapsed < timeout)
            sleep(1);
    }
    return false;
}

static bool recover_services(struct ubus_context *ctx,
                             const char **services, size_t count)
{
    struct airui_ubus_result ignored = {};
    size_t i;
    bool restarted = true;

    for (i = 0; i < count; i++) {
        if (restart_apply_service(ctx, services[i], &ignored) != 0)
            restarted = false;
        airui_ubus_result_free(&ignored);
    }
    return restarted && wait_for_services(ctx, services, count, 10);
}

int airui_network_interface_apply(struct ubus_context *ctx,
                                  struct ubus_object *obj,
                                  struct ubus_request_data *req,
                                  const char *method,
                                  struct blob_attr *msg)
{
    struct blob_attr *tb[__APPLY_MAX];
    struct plan_data plan = {};
    struct airui_ubus_result commit_network = {};
    struct airui_ubus_result commit_dhcp = {};
    struct airui_ubus_result commit_firewall = {};
    struct airui_ubus_result commit_wireless = {};
    struct airui_ubus_result reload = {};
    bool commit = true;
    bool restart = true;
    const char *services[MAX_APPLY_SERVICES] = {
        "network", "dnsmasq", "firewall"
    };
    size_t service_count = 3;
    int rollback_timeout = DEFAULT_ROLLBACK_TIMEOUT;
    int ret = 0;

    (void)obj;
    (void)method;

    blobmsg_parse(apply_policy, __APPLY_MAX, tb,
                  msg ? blob_data(msg) : NULL,
                  msg ? blob_len(msg) : 0);

    if (tb[APPLY_COMMIT]) {
        commit = blobmsg_get_bool(tb[APPLY_COMMIT]);
    }
    if (tb[APPLY_RESTART]) {
        restart = blobmsg_get_bool(tb[APPLY_RESTART]);
    }
    if (tb[APPLY_ROLLBACK_TIMEOUT]) {
        rollback_timeout = blobmsg_get_u32(tb[APPLY_ROLLBACK_TIMEOUT]);
        if (rollback_timeout < MIN_ROLLBACK_TIMEOUT ||
            rollback_timeout > MAX_ROLLBACK_TIMEOUT) {
            reply_iface_error(ctx, req, "VALIDATION_FAILED", "rollback_timeout",
                              "Rollback timeout must be between 5 and 300 seconds");
            return 0;
        }
    }
    if (tb[APPLY_SERVICES]) {
        struct blob_attr *cur;
        int rem;

        service_count = 0;
        blobmsg_for_each_attr(cur, tb[APPLY_SERVICES], rem) {
            const char *service;

            if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING ||
                service_count >= MAX_APPLY_SERVICES) {
                reply_iface_error(ctx, req, "VALIDATION_FAILED", "services",
                                  "Services must contain at most four service names");
                return 0;
            }
            service = blobmsg_get_string(cur);
            if (!valid_apply_service(service)) {
                reply_iface_error(ctx, req, "VALIDATION_FAILED", "services",
                                  "Service must be network, dnsmasq, firewall, or wireless");
                return 0;
            }
            services[service_count++] = service;
        }
        if (restart && service_count == 0) {
            reply_iface_error(ctx, req, "VALIDATION_FAILED", "services",
                              "At least one service is required when restart is enabled");
            return 0;
        }
    }

    plan.operation = "apply";
    plan.type = "interface";
    plan.name = "";
    plan.dry_run = false;
    plan.changed = commit || restart;
    plan.risk = "network_reload";
    plan_add(&plan, "backup /etc/config/network, dhcp, firewall, wireless");
    plan_add(&plan, "commit touched configs");
    plan_add(&plan, "restart the requested services");
    plan_add(&plan, "verify service health and non-loopback network connectivity");
    plan_add(&plan, "retry service recovery, then restore backup on timeout");
    for (size_t i = 0; i < service_count; i++)
        restart_add(&plan, services[i]);

    if (!backup_configs()) {
        reply_iface_error(ctx, req, "BACKUP_FAILED", NULL,
                          "Could not create a complete configuration backup");
        return 0;
    }
    airui_apply_begin("network_interfaces");

    if (commit) {
        ret = uci_commit_config(ctx, "network", &commit_network);
        if (!ret) ret = uci_commit_config(ctx, "dhcp", &commit_dhcp);
        if (!ret) ret = uci_commit_config(ctx, "firewall", &commit_firewall);
        if (!ret) ret = uci_commit_config(ctx, "wireless", &commit_wireless);
    }

    if (!ret && restart) {
        size_t i;

        for (i = 0; i < service_count && !ret; i++)
            ret = restart_apply_service(ctx, services[i], &reload);

        if (!ret && !wait_for_services(ctx, services, service_count,
                                       rollback_timeout)) {
            /* Try one explicit recovery before restoring the old config. */
            if (!recover_services(ctx, services, service_count))
                ret = -1;
        }
    }

    if (ret) {
        const char *rollback_services[MAX_APPLY_SERVICES] = {
            "network", "dnsmasq", "firewall", "wireless"
        };
        bool restored = restore_configs();
        bool recovered = restored &&
            recover_services(ctx, rollback_services, MAX_APPLY_SERVICES);

        airui_apply_rolled_back(recovered ?
            "Apply failed; previous network configuration restored" :
            "Apply failed; rollback service recovery also failed");
        airui_reply_error_schema(ctx, req,
                                 recovered ? "apply_rolled_back" : "recovery_failed",
                                 NULL,
                                 recovered ?
                                 "Apply failed; previous configuration was restored" :
                                 "Apply failed and services did not recover after rollback",
                                 AIRUI_IFACE_SOURCE, AIRUI_IFACE_SCHEMA);
        airui_ubus_result_free(&commit_network);
        airui_ubus_result_free(&commit_dhcp);
        airui_ubus_result_free(&commit_firewall);
        airui_ubus_result_free(&commit_wireless);
        airui_ubus_result_free(&reload);
        return 0;
    }

    plan.commit_network_json = commit_network.json;
    plan.commit_dhcp_json = commit_dhcp.json;
    plan.commit_firewall_json = commit_firewall.json;
    plan.commit_wireless_json = commit_wireless.json;
    plan.reload_json = reload.json;

    airui_reply_ok_schema(ctx, req, plan_builder, &plan,
                          AIRUI_IFACE_SOURCE, AIRUI_IFACE_SCHEMA);
    airui_apply_success("Network interface configuration applied");

    airui_ubus_result_free(&commit_network);
    airui_ubus_result_free(&commit_dhcp);
    airui_ubus_result_free(&commit_firewall);
    airui_ubus_result_free(&commit_wireless);
    airui_ubus_result_free(&reload);
    return 0;
}

int airui_network_interface_map_ssid(struct ubus_context *ctx,
                                     struct ubus_object *obj,
                                     struct ubus_request_data *req,
                                     const char *method,
                                     struct blob_attr *msg)
{
    struct blob_attr *tb[__MAP_MAX];
    struct blob_buf values = {};
    struct plan_data plan = {};
    struct airui_ubus_result action = {};
    const char *section;
    const char *network;
    bool dry_run;
    int ret;

    (void)obj;
    (void)method;

    blobmsg_parse(map_policy, __MAP_MAX, tb,
                  msg ? blob_data(msg) : NULL,
                  msg ? blob_len(msg) : 0);

    if (!tb[MAP_SECTION] || !tb[MAP_NETWORK]) {
        reply_iface_error(ctx, req, "VALIDATION_FAILED", NULL,
                          "SSID mapping requires section and network");
        return 0;
    }

    section = blobmsg_get_string(tb[MAP_SECTION]);
    network = blobmsg_get_string(tb[MAP_NETWORK]);
    if (!valid_iface_name(section) || !valid_iface_name(network)) {
        reply_iface_error(ctx, req, "VALIDATION_FAILED", NULL,
                          "section and network must use lowercase letters, numbers, and underscore only");
        return 0;
    }

    if (!uci_section_exists(ctx, "network", network)) {
        reply_iface_error(ctx, req, "VALIDATION_FAILED", "network",
                          "Target network does not exist");
        return 0;
    }

    dry_run = tb[MAP_DRY_RUN] && blobmsg_get_bool(tb[MAP_DRY_RUN]);
    plan.operation = "map_ssid";
    plan.type = "ssid_mapping";
    plan.name = section;
    plan.dry_run = dry_run;
    plan.changed = !dry_run;
    plan.risk = "network_reload";
    plan_add(&plan, "set wireless wifi-iface network");
    restart_add(&plan, "network");

    if (!dry_run) {
        blob_buf_init(&values, 0);
        blobmsg_add_string(&values, "network", network);
        ret = uci_set_values(ctx, "wireless", section, &values, &action);
        blob_buf_free(&values);
        if (ret) {
            reply_iface_error(ctx, req, "BACKEND_FAILED", "uci", ubus_strerror(ret));
            airui_ubus_result_free(&action);
            return 0;
        }
        plan.uci_json = action.json;
    }

    airui_reply_ok_schema(ctx, req, plan_builder, &plan,
                          AIRUI_IFACE_SOURCE, AIRUI_IFACE_SCHEMA);
    airui_ubus_result_free(&action);
    return 0;
}
