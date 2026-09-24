#include "airui_management.h"
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
#include <uci.h>

#include "airui_response.h"
#include "airui_ubus_client.h"

#define AIRUI_MGMT_SOURCE "airui.system"
#define AIRUI_MGMT_SCHEMA "airui.system.wan_management.v1"
#define AIRUI_MGMT_SECTION "lan"
#define AIRUI_MGMT_ROLLBACK_FILE "/tmp/airui-network.rollback"

enum {
    MGMT_PROTO,
    MGMT_IPADDR,
    MGMT_NETMASK,
    MGMT_GATEWAY,
    MGMT_DNS,
    MGMT_VLAN_ID,
    MGMT_DRY_RUN,
    __MGMT_MAX
};

static const struct blobmsg_policy mgmt_policy[__MGMT_MAX] = {
    [MGMT_PROTO] = { .name = "proto", .type = BLOBMSG_TYPE_STRING },
    [MGMT_IPADDR] = { .name = "ipaddr", .type = BLOBMSG_TYPE_STRING },
    [MGMT_NETMASK] = { .name = "netmask", .type = BLOBMSG_TYPE_STRING },
    [MGMT_GATEWAY] = { .name = "gateway", .type = BLOBMSG_TYPE_STRING },
    [MGMT_DNS] = { .name = "dns", .type = BLOBMSG_TYPE_STRING },
    [MGMT_VLAN_ID] = { .name = "vlan_id", .type = BLOBMSG_TYPE_INT32 },
    [MGMT_DRY_RUN] = { .name = "dry_run", .type = BLOBMSG_TYPE_BOOL },
};

struct mgmt_config {
    const char *network_json;
    const char *runtime_json;
};

struct mgmt_values {
    const char *section;
    const char *proto;
    const char *ipaddr;
    const char *netmask;
    const char *gateway;
    const char *dns;
    const char *device;
    char interface[32];
    int vlan_id;
    const char *uci_json;
    struct json_object *json_root;
    struct json_object *runtime_root;
    char runtime_netmask[16];
    char runtime_dns[256];
};

struct mgmt_set_result {
    const char *operation;
    const char *section;
    const char *proto;
    const char *interface;
    int vlan_id;
    bool dry_run;
    bool changed;
    bool connectivity_verified;
    bool rolled_back;
    const char *uci_set_json;
    const char *uci_commit_json;
    const char *network_reload_json;
};

static void reply_mgmt_error(struct ubus_context *ctx,
                             struct ubus_request_data *req,
                             const char *code,
                             const char *field,
                             const char *message)
{
    airui_reply_error_schema(ctx, req, code, field, message,
                             AIRUI_MGMT_SOURCE, AIRUI_MGMT_SCHEMA);
}

static bool valid_ipv4(const char *value)
{
    struct in_addr addr;

    return value && inet_pton(AF_INET, value, &addr) == 1;
}

static bool valid_netmask(const char *value, uint32_t *mask_out)
{
    struct in_addr addr;
    uint32_t mask;
    uint32_t inverse;

    if (!value || inet_pton(AF_INET, value, &addr) != 1)
        return false;

    mask = ntohl(addr.s_addr);
    inverse = ~mask;
    if (mask == 0 || mask >= UINT32_MAX - 1 ||
        (inverse & (inverse + 1)) != 0)
        return false;

    if (mask_out)
        *mask_out = mask;
    return true;
}

static bool same_subnet(const char *left, const char *right, uint32_t mask)
{
    struct in_addr left_addr;
    struct in_addr right_addr;

    if (!valid_ipv4(left) || !valid_ipv4(right))
        return false;
    inet_pton(AF_INET, left, &left_addr);
    inet_pton(AF_INET, right, &right_addr);
    return (ntohl(left_addr.s_addr) & mask) ==
           (ntohl(right_addr.s_addr) & mask);
}

static bool usable_host_address(const char *value, uint32_t mask)
{
    struct in_addr addr;
    uint32_t host;

    if (!valid_ipv4(value))
        return false;
    inet_pton(AF_INET, value, &addr);
    host = ntohl(addr.s_addr);
    return (host & ~mask) != 0 && (host & ~mask) != ~mask;
}

static bool valid_dns_list(const char *value)
{
    char copy[256];
    char *token;
    char *saveptr = NULL;

    if (!value || !value[0])
        return true;
    if (strlen(value) >= sizeof(copy))
        return false;

    snprintf(copy, sizeof(copy), "%s", value);
    token = strtok_r(copy, " ,", &saveptr);
    if (!token)
        return false;
    while (token) {
        if (!valid_ipv4(token))
            return false;
        token = strtok_r(NULL, " ,", &saveptr);
    }
    return true;
}

static bool command_ok(const char *command)
{
    int status = system(command);

    return status != -1 && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static bool verify_management_connectivity(const char *proto,
                                           const char *ipaddr,
                                           const char *gateway)
{
    char command[384];
    int attempt;

    for (attempt = 0; attempt < 10; attempt++) {
        if (!strcmp(proto, "dhcp")) {
            if (command_ok("ubus call network.interface.lan status 2>/dev/null | "
                           "jsonfilter -e '@.up' | grep -qx true && "
                           "ubus call network.interface.lan status 2>/dev/null | "
                           "jsonfilter -e '@.ipv4-address[0].address' | "
                           "grep -qE '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$'"))
                return true;
        } else {
            snprintf(command, sizeof(command),
                     "ip -4 addr show dev br-lan 2>/dev/null | grep -q 'inet %s/'",
                     ipaddr);
            if (command_ok(command)) {
                if (!gateway || !gateway[0])
                    return true;
                snprintf(command, sizeof(command),
                         "ping -c 1 -W 1 %s >/dev/null 2>&1", gateway);
                if (command_ok(command))
                    return true;
            }
        }
        sleep(2);
    }
    return false;
}

static bool backup_network_config(void)
{
    return command_ok("cp /etc/config/network " AIRUI_MGMT_ROLLBACK_FILE);
}

static void rollback_network_config(void)
{
    command_ok("cp " AIRUI_MGMT_ROLLBACK_FILE " /etc/config/network");
    command_ok("ubus call network reload >/dev/null 2>&1");
    unlink(AIRUI_MGMT_ROLLBACK_FILE);
}

static const char *json_string(struct json_object *obj,
                               const char *name,
                               const char *fallback)
{
    struct json_object *value = NULL;

    if (obj &&
        json_object_object_get_ex(obj, name, &value) &&
        json_object_is_type(value, json_type_string)) {
        return json_object_get_string(value);
    }

    return fallback;
}

static void prefix_to_netmask(int prefix, char *buffer, size_t size)
{
    struct in_addr addr;
    uint32_t mask;

    if (prefix < 0)
        prefix = 0;
    if (prefix > 32)
        prefix = 32;
    mask = prefix == 0 ? 0 : UINT32_MAX << (32 - prefix);

    addr.s_addr = htonl(mask);
    if (!inet_ntop(AF_INET, &addr, buffer, size))
        snprintf(buffer, size, "0.0.0.0");
}

static void add_json_object(struct blob_buf *b, const char *name, const char *json)
{
    struct json_object *obj;
    void *empty;

    if (!json) {
        empty = blobmsg_open_table(b, name);
        blobmsg_close_table(b, empty);
        return;
    }

    obj = json_tokener_parse(json);
    if (!obj || !blobmsg_add_json_element(b, name, obj)) {
        empty = blobmsg_open_table(b, name);
        blobmsg_close_table(b, empty);
    }

    if (obj) {
        json_object_put(obj);
    }
}

static int uci_get_network(struct ubus_context *ctx,
                           struct airui_ubus_result *result)
{
    struct blob_buf b = {};
    int ret;

    blob_buf_init(&b, 0);
    blobmsg_add_string(&b, "config", "network");
    ret = airui_ubus_call_json(ctx, "uci", "get", &b, result);
    blob_buf_free(&b);
    return ret;
}

static int __attribute__((unused)) uci_set_lan_values(struct ubus_context *ctx,
                              struct blob_buf *values,
                              struct airui_ubus_result *result)
{
    struct blob_buf b = {};
    int ret;

    blob_buf_init(&b, 0);
    blobmsg_add_string(&b, "config", "network");
    blobmsg_add_string(&b, "section", AIRUI_MGMT_SECTION);
    if (values && values->head) {
        blobmsg_add_field(&b, BLOBMSG_TYPE_TABLE, "values",
                          blobmsg_data(values->head),
                          blobmsg_data_len(values->head));
    }
    ret = airui_ubus_call_json(ctx, "uci", "set", &b, result);
    blob_buf_free(&b);
    return ret;
}

static int __attribute__((unused)) uci_set_section_values(struct ubus_context *ctx,
                                  const char *section,
                                  struct blob_buf *values,
                                  struct airui_ubus_result *result)
{
    struct blob_buf b = {};
    int ret;

    blob_buf_init(&b, 0);
    blobmsg_add_string(&b, "config", "network");
    blobmsg_add_string(&b, "section", section);
    blobmsg_add_field(&b, BLOBMSG_TYPE_TABLE, "values",
                      blobmsg_data(values->head), blobmsg_data_len(values->head));
    ret = airui_ubus_call_json(ctx, "uci", "set", &b, result);
    blob_buf_free(&b);
    return ret;
}

static int __attribute__((unused)) uci_add_vlan_device(struct ubus_context *ctx,
                               int vlan_id,
                               struct airui_ubus_result *result)
{
    struct blob_buf b = {};
    struct blob_buf values = {};
    char name[32];
    int ret;

    snprintf(name, sizeof(name), "wan.%d", vlan_id);
    blob_buf_init(&values, 0);
    blobmsg_add_string(&values, "name", name);
    blobmsg_add_string(&values, "type", "8021q");
    blobmsg_add_string(&values, "ifname", "wan");
    blobmsg_add_u32(&values, "vid", (uint32_t)vlan_id);
    blobmsg_add_string(&values, "airui_managed", "1");

    blob_buf_init(&b, 0);
    blobmsg_add_string(&b, "config", "network");
    blobmsg_add_string(&b, "type", "device");
    blobmsg_add_string(&b, "name", "airui_wan_vlan");
    blobmsg_add_field(&b, BLOBMSG_TYPE_TABLE, "values",
                      blobmsg_data(values.head), blobmsg_data_len(values.head));
    ret = airui_ubus_call_json(ctx, "uci", "add", &b, result);
    blob_buf_free(&b);
    blob_buf_free(&values);
    return ret;
}

static int __attribute__((unused)) uci_delete_section(struct ubus_context *ctx,
                                                      const char *section)
{
    struct airui_ubus_result result = {};
    struct blob_buf b = {};
    int ret;

    blob_buf_init(&b, 0);
    blobmsg_add_string(&b, "config", "network");
    blobmsg_add_string(&b, "section", section);
    ret = airui_ubus_call_json(ctx, "uci", "delete", &b, &result);
    blob_buf_free(&b);
    airui_ubus_result_free(&result);
    return ret;
}

static bool __attribute__((unused)) find_management_bridge(const char *network_json,
                                   char *section,
                                   size_t section_size,
                                   int *vlan_id)
{
    struct json_object *root = json_tokener_parse(network_json);
    struct json_object *values = NULL;
    struct json_object_iterator it;
    struct json_object_iterator end;
    bool found = false;

    *vlan_id = 0;
    if (!root || !json_object_object_get_ex(root, "values", &values))
        goto out;

    it = json_object_iter_begin(values);
    end = json_object_iter_end(values);
    while (!json_object_iter_equal(&it, &end)) {
        struct json_object *row = json_object_iter_peek_value(&it);
        const char *name = json_string(row, "name", "");

        if (!strcmp(name, "br-lan")) {
            struct json_object *ports = NULL;
            const char *port = "wan";

            snprintf(section, section_size, "%s", json_object_iter_peek_name(&it));
            if (json_object_object_get_ex(row, "ports", &ports)) {
                if (json_object_is_type(ports, json_type_array) && json_object_array_length(ports))
                    port = json_object_get_string(json_object_array_get_idx(ports, 0));
                else if (json_object_is_type(ports, json_type_string))
                    port = json_object_get_string(ports);
            }
            if (port && sscanf(port, "wan.%d", vlan_id) != 1)
                *vlan_id = 0;
            found = true;
            break;
        }
        json_object_iter_next(&it);
    }

out:
    if (root)
        json_object_put(root);
    return found;
}

static int __attribute__((unused)) uci_delete_lan_option(struct ubus_context *ctx,
                                                        const char *option)
{
    struct airui_ubus_result result = {};
    struct blob_buf b = {};
    int ret;

    blob_buf_init(&b, 0);
    blobmsg_add_string(&b, "config", "network");
    blobmsg_add_string(&b, "section", AIRUI_MGMT_SECTION);
    blobmsg_add_string(&b, "option", option);
    ret = airui_ubus_call_json(ctx, "uci", "delete", &b, &result);
    blob_buf_free(&b);
    airui_ubus_result_free(&result);
    return ret;
}

static int __attribute__((unused)) uci_commit_network(struct ubus_context *ctx,
                              struct airui_ubus_result *result)
{
    struct blob_buf b = {};
    int ret;

    blob_buf_init(&b, 0);
    blobmsg_add_string(&b, "config", "network");
    ret = airui_ubus_call_json(ctx, "uci", "commit", &b, result);
    blob_buf_free(&b);
    return ret;
}

static int direct_uci_set(struct uci_context *uci, const char *expression)
{
    struct uci_ptr ptr = {};
    char value[256];

    snprintf(value, sizeof(value), "%s", expression);
    if (uci_lookup_ptr(uci, &ptr, value, true) != UCI_OK)
        return -1;
    return uci_set(uci, &ptr) == UCI_OK ? 0 : -1;
}

static int direct_uci_delete(struct uci_context *uci, const char *expression)
{
    struct uci_ptr ptr = {};
    char value[256];

    snprintf(value, sizeof(value), "%s", expression);
    if (uci_lookup_ptr(uci, &ptr, value, true) != UCI_OK || !ptr.last)
        return 0;
    return uci_delete(uci, &ptr) == UCI_OK ? 0 : -1;
}

static int direct_uci_apply_management(const char *proto,
                                       const char *ipaddr,
                                       const char *netmask,
                                       const char *gateway,
                                       const char *dns,
                                       const char *uplink,
                                       int vlan_id)
{
    struct uci_context *uci = uci_alloc_context();
    struct uci_package *network = NULL;
    struct uci_element *element;
    struct uci_section *bridge = NULL;
    char expression[256];
    int ret = -1;

    if (!uci || uci_load(uci, "network", &network) != UCI_OK)
        goto out;

    uci_foreach_element(&network->sections, element) {
        struct uci_section *section = uci_to_section(element);
        const char *name;

        if (strcmp(section->type, "device") != 0)
            continue;
        name = uci_lookup_option_string(uci, section, "name");
        if (name && strcmp(name, "br-lan") == 0) {
            bridge = section;
            break;
        }
    }
    if (!bridge)
        goto out;

    direct_uci_delete(uci, "network.airui_wan_vlan");
    if (vlan_id) {
        if (direct_uci_set(uci, "network.airui_wan_vlan=device"))
            goto out;
        snprintf(expression, sizeof(expression),
                 "network.airui_wan_vlan.name=wan.%d", vlan_id);
        if (direct_uci_set(uci, expression) ||
            direct_uci_set(uci, "network.airui_wan_vlan.type=8021q") ||
            direct_uci_set(uci, "network.airui_wan_vlan.ifname=wan"))
            goto out;
        snprintf(expression, sizeof(expression),
                 "network.airui_wan_vlan.vid=%d", vlan_id);
        if (direct_uci_set(uci, expression) ||
            direct_uci_set(uci, "network.airui_wan_vlan.airui_managed=1"))
            goto out;
    }

    snprintf(expression, sizeof(expression), "network.%s.ports", bridge->e.name);
    direct_uci_delete(uci, expression);
    snprintf(expression, sizeof(expression), "network.%s.ports=%s",
             bridge->e.name, uplink);
    {
        struct uci_ptr ptr = {};
        if (uci_lookup_ptr(uci, &ptr, expression, true) != UCI_OK ||
            uci_add_list(uci, &ptr) != UCI_OK)
            goto out;
    }

    snprintf(expression, sizeof(expression), "network.%s.proto=%s",
             AIRUI_MGMT_SECTION, proto);
    if (direct_uci_set(uci, expression))
        goto out;

    if (strcmp(proto, "static") == 0) {
        snprintf(expression, sizeof(expression), "network.%s.ipaddr=%s",
                 AIRUI_MGMT_SECTION, ipaddr);
        if (direct_uci_set(uci, expression))
            goto out;
        snprintf(expression, sizeof(expression), "network.%s.netmask=%s",
                 AIRUI_MGMT_SECTION, netmask);
        if (direct_uci_set(uci, expression))
            goto out;
        if (gateway && gateway[0]) {
            snprintf(expression, sizeof(expression), "network.%s.gateway=%s",
                     AIRUI_MGMT_SECTION, gateway);
            if (direct_uci_set(uci, expression))
                goto out;
        }
        if (dns && dns[0]) {
            snprintf(expression, sizeof(expression), "network.%s.dns=%s",
                     AIRUI_MGMT_SECTION, dns);
            if (direct_uci_set(uci, expression))
                goto out;
        }
    } else {
        direct_uci_delete(uci, "network.lan.ipaddr");
        direct_uci_delete(uci, "network.lan.netmask");
        direct_uci_delete(uci, "network.lan.gateway");
        direct_uci_delete(uci, "network.lan.dns");
    }

    if (uci_commit(uci, &network, false) != UCI_OK)
        goto out;
    ret = 0;

out:
    if (network)
        uci_unload(uci, network);
    if (uci)
        uci_free_context(uci);
    return ret;
}

static void parse_management_values(const char *network_json,
                                    const char *runtime_json,
                                    struct mgmt_values *values)
{
    struct json_object *root = NULL;
    struct json_object *uci_values = NULL;
    struct json_object *lan = NULL;

    memset(values, 0, sizeof(*values));
    values->section = AIRUI_MGMT_SECTION;
    values->proto = "static";
    values->ipaddr = "192.168.1.2";
    values->netmask = "255.255.255.0";
    values->gateway = "192.168.1.1";
    values->dns = "192.168.1.1";
    values->device = "br-lan";
    snprintf(values->interface, sizeof(values->interface), "wan");
    values->vlan_id = 0;
    values->uci_json = network_json;

    if (!network_json) {
        return;
    }

    root = json_tokener_parse(network_json);
    if (!root) {
        return;
    }
    values->json_root = root;

    if (json_object_object_get_ex(root, "values", &uci_values) &&
        json_object_object_get_ex(uci_values, AIRUI_MGMT_SECTION, &lan)) {
        values->proto = json_string(lan, "proto", values->proto);
        values->ipaddr = json_string(lan, "ipaddr", values->ipaddr);
        values->netmask = json_string(lan, "netmask", values->netmask);
        values->gateway = json_string(lan, "gateway", values->gateway);
        values->dns = json_string(lan, "dns", values->dns);
        values->device = json_string(lan, "device", values->device);
    }

    if (uci_values) {
        struct json_object *vlan = NULL;

        if (json_object_object_get_ex(uci_values, "airui_wan_vlan", &vlan)) {
            struct json_object *vid = NULL;

            if (json_object_object_get_ex(vlan, "vid", &vid)) {
                values->vlan_id = json_object_get_int(vid);
                if (values->vlan_id > 0 && values->vlan_id <= 4094)
                    snprintf(values->interface, sizeof(values->interface),
                             "wan.%d", values->vlan_id);
                else
                    values->vlan_id = 0;
            }
        }
    }

    if (runtime_json) {
        struct json_object *addresses = NULL;
        struct json_object *routes = NULL;
        struct json_object *dns_servers = NULL;
        size_t i;

        values->runtime_root = json_tokener_parse(runtime_json);
        if (values->runtime_root &&
            json_object_object_get_ex(values->runtime_root, "ipv4-address", &addresses) &&
            json_object_is_type(addresses, json_type_array) &&
            json_object_array_length(addresses) > 0) {
            struct json_object *address = json_object_array_get_idx(addresses, 0);
            struct json_object *mask = NULL;

            values->ipaddr = json_string(address, "address", values->ipaddr);
            if (json_object_object_get_ex(address, "mask", &mask)) {
                prefix_to_netmask(json_object_get_int(mask),
                                  values->runtime_netmask,
                                  sizeof(values->runtime_netmask));
                values->netmask = values->runtime_netmask;
            }
        }

        if (values->runtime_root &&
            json_object_object_get_ex(values->runtime_root, "route", &routes) &&
            json_object_is_type(routes, json_type_array)) {
            for (i = 0; i < json_object_array_length(routes); i++) {
                struct json_object *route = json_object_array_get_idx(routes, i);
                struct json_object *mask_value = NULL;
                const char *target = json_string(route, "target", "");
                int route_mask = 0;

                if (json_object_object_get_ex(route, "mask", &mask_value))
                    route_mask = json_object_get_int(mask_value);

                if ((!strcmp(target, "0.0.0.0") || !target[0]) && route_mask == 0) {
                    values->gateway = json_string(route, "nexthop", values->gateway);
                    break;
                }
            }
        }

        if (values->runtime_root &&
            json_object_object_get_ex(values->runtime_root, "dns-server", &dns_servers) &&
            json_object_is_type(dns_servers, json_type_array)) {
            values->runtime_dns[0] = '\0';
            for (i = 0; i < json_object_array_length(dns_servers); i++) {
                const char *server = json_object_get_string(
                    json_object_array_get_idx(dns_servers, i));
                size_t used = strlen(values->runtime_dns);

                if (!server || !server[0] || used + strlen(server) + 2 >= sizeof(values->runtime_dns))
                    continue;
                snprintf(values->runtime_dns + used,
                         sizeof(values->runtime_dns) - used,
                         "%s%s", used ? " " : "", server);
            }
            if (values->runtime_dns[0])
                values->dns = values->runtime_dns;
        }
    }

}

static void mgmt_config_builder(struct blob_buf *b, void *user)
{
    struct mgmt_config *config = user;
    struct mgmt_values values;
    void *management;

    parse_management_values(config ? config->network_json : NULL,
                            config ? config->runtime_json : NULL,
                            &values);

    management = blobmsg_open_table(b, "management");
    blobmsg_add_string(b, "section", values.section);
    blobmsg_add_string(b, "proto", values.proto);
    blobmsg_add_string(b, "ipaddr", values.ipaddr);
    blobmsg_add_string(b, "netmask", values.netmask);
    blobmsg_add_string(b, "gateway", values.gateway);
    blobmsg_add_string(b, "dns", values.dns);
    blobmsg_add_string(b, "device", values.device);
    blobmsg_add_string(b, "interface", values.interface);
    blobmsg_add_u32(b, "vlan_id", (uint32_t)values.vlan_id);
    blobmsg_close_table(b, management);

    if (values.json_root)
        json_object_put(values.json_root);
    if (values.runtime_root)
        json_object_put(values.runtime_root);
}

static void mgmt_set_builder(struct blob_buf *b, void *user)
{
    struct mgmt_set_result *result = user;

    blobmsg_add_string(b, "operation", result ? result->operation : "set");
    blobmsg_add_string(b, "section", result ? result->section : AIRUI_MGMT_SECTION);
    blobmsg_add_string(b, "proto", result ? result->proto : "static");
    blobmsg_add_string(b, "interface", result ? result->interface : "wan");
    blobmsg_add_u32(b, "vlan_id", result ? (uint32_t)result->vlan_id : 0);
    blobmsg_add_u8(b, "dry_run", result ? result->dry_run : true);
    blobmsg_add_u8(b, "changed", result ? result->changed : false);
    blobmsg_add_u8(b, "connectivity_verified",
                   result ? result->connectivity_verified : false);
    blobmsg_add_u8(b, "rolled_back", result ? result->rolled_back : false);
    add_json_object(b, "uci_set", result ? result->uci_set_json : NULL);
    add_json_object(b, "uci_commit", result ? result->uci_commit_json : NULL);
    add_json_object(b, "network_reload", result ? result->network_reload_json : NULL);
}

int airui_system_wan_management_config(struct ubus_context *ctx,
                                       struct ubus_object *obj,
                                       struct ubus_request_data *req,
                                       const char *method,
                                       struct blob_attr *msg)
{
    struct airui_ubus_result network = {};
    struct airui_ubus_result runtime = {};
    struct mgmt_config config;
    int ret;

    (void)obj;
    (void)method;
    (void)msg;

    ret = uci_get_network(ctx, &network);
    if (ret) {
        reply_mgmt_error(ctx, req, "backend_unavailable", "uci",
                         ubus_strerror(ret));
        return 0;
    }

    config.network_json = network.json;
    ret = airui_ubus_call_json(ctx, "network.interface.lan", "status",
                               NULL, &runtime);
    config.runtime_json = ret ? NULL : runtime.json;
    airui_reply_ok_schema(ctx, req, mgmt_config_builder, &config,
                          AIRUI_MGMT_SOURCE, AIRUI_MGMT_SCHEMA);
    airui_ubus_result_free(&network);
    airui_ubus_result_free(&runtime);
    return 0;
}

int airui_system_wan_management_set(struct ubus_context *ctx,
                                    struct ubus_object *obj,
                                    struct ubus_request_data *req,
                                    const char *method,
                                    struct blob_attr *msg)
{
    struct blob_attr *tb[__MGMT_MAX];
    struct mgmt_set_result result = {};
    const char *proto = "static";
    const char *ipaddr = NULL;
    const char *netmask = NULL;
    const char *gateway = NULL;
    const char *dns = NULL;
    int vlan_id = 0;
    uint32_t mask = 0;
    char uplink[32] = "wan";
    bool dry_run = false;
    int ret;

    (void)obj;
    (void)method;

    blobmsg_parse(mgmt_policy,
                  __MGMT_MAX,
                  tb,
                  msg ? blob_data(msg) : NULL,
                  msg ? blob_len(msg) : 0);

    if (tb[MGMT_PROTO]) {
        proto = blobmsg_get_string(tb[MGMT_PROTO]);
    }
    if (tb[MGMT_IPADDR]) {
        ipaddr = blobmsg_get_string(tb[MGMT_IPADDR]);
    }
    if (tb[MGMT_NETMASK]) {
        netmask = blobmsg_get_string(tb[MGMT_NETMASK]);
    }
    if (tb[MGMT_GATEWAY]) {
        gateway = blobmsg_get_string(tb[MGMT_GATEWAY]);
    }
    if (tb[MGMT_DNS]) {
        dns = blobmsg_get_string(tb[MGMT_DNS]);
    }
    if (tb[MGMT_VLAN_ID]) {
        vlan_id = (int)blobmsg_get_u32(tb[MGMT_VLAN_ID]);
    }
    dry_run = tb[MGMT_DRY_RUN] && blobmsg_get_bool(tb[MGMT_DRY_RUN]);

    if (strcmp(proto, "static") != 0 && strcmp(proto, "dhcp") != 0) {
        reply_mgmt_error(ctx, req, "invalid_argument", "proto",
                         "Protocol must be static or dhcp");
        return 0;
    }
    if (vlan_id < 0 || vlan_id > 4094) {
        reply_mgmt_error(ctx, req, "invalid_argument", "vlan_id",
                         "VLAN ID must be between 0 and 4094");
        return 0;
    }

    if (vlan_id)
        snprintf(uplink, sizeof(uplink), "wan.%d", vlan_id);

    if (strcmp(proto, "static") == 0) {
        if (!valid_ipv4(ipaddr)) {
            reply_mgmt_error(ctx, req, "invalid_argument", "ipaddr",
                             "IPv4 address is required for static mode");
            return 0;
        }
        if (!valid_netmask(netmask, &mask)) {
            reply_mgmt_error(ctx, req, "invalid_argument", "netmask",
                             "Subnet mask must be contiguous and between /1 and /30");
            return 0;
        }
        if (!usable_host_address(ipaddr, mask)) {
            reply_mgmt_error(ctx, req, "invalid_argument", "ipaddr",
                             "IPv4 address must be a usable host address");
            return 0;
        }
        if (gateway && gateway[0] && !valid_ipv4(gateway)) {
            reply_mgmt_error(ctx, req, "invalid_argument", "gateway",
                             "Gateway must be a valid IPv4 address");
            return 0;
        }
        if (gateway && gateway[0] &&
            (!same_subnet(ipaddr, gateway, mask) || !usable_host_address(gateway, mask) ||
             !strcmp(ipaddr, gateway))) {
            reply_mgmt_error(ctx, req, "invalid_argument", "gateway",
                             "Gateway must be a different usable address in the management subnet");
            return 0;
        }
        if (!valid_dns_list(dns)) {
            reply_mgmt_error(ctx, req, "invalid_argument", "dns",
                             "DNS must contain valid IPv4 addresses separated by spaces or commas");
            return 0;
        }
    }

    result.operation = "set";
    result.section = AIRUI_MGMT_SECTION;
    result.proto = proto;
    result.interface = uplink;
    result.vlan_id = vlan_id;
    result.dry_run = dry_run;
    result.changed = !dry_run;
    result.connectivity_verified = dry_run;

    if (!dry_run) {
        airui_apply_begin("wan_management");
        if (!backup_network_config()) {
            airui_apply_failed("Unable to create network rollback snapshot");
            reply_mgmt_error(ctx, req, "backend_unavailable", "rollback",
                             "Unable to create network rollback snapshot");
            return 0;
        }
        ret = direct_uci_apply_management(proto, ipaddr, netmask, gateway,
                                          dns, uplink, vlan_id);
        if (ret) {
            airui_apply_failed("Unable to save WAN management configuration");
            reply_mgmt_error(ctx, req, "backend_unavailable", "uci",
                             "Unable to save WAN management configuration");
            return 0;
        }
        if (!command_ok("ubus call network reload >/dev/null 2>&1") ||
            !verify_management_connectivity(proto, ipaddr, gateway)) {
            rollback_network_config();
            result.rolled_back = true;
            airui_apply_rolled_back("Management connectivity failed; previous network configuration restored");
            reply_mgmt_error(ctx, req, "connectivity_failed", "management",
                             "Management connectivity failed and the previous configuration was restored");
            return 0;
        }
        result.connectivity_verified = true;
        unlink(AIRUI_MGMT_ROLLBACK_FILE);
        airui_apply_success("WAN management configuration applied");
    }

    airui_reply_ok_schema(ctx, req, mgmt_set_builder, &result,
                          AIRUI_MGMT_SOURCE, AIRUI_MGMT_SCHEMA);

    return 0;
}
