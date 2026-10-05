#include "airui_security.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>

#include "airui_apply_status.h"
#include "airui_response.h"
#include "airui_ubus_client.h"

enum {
    MAC_SECTION,
    MAC_ENABLED,
    MAC_MODE,
    MAC_MAC,
    MAC_LABEL,
    MAC_DRY_RUN,
    __MAC_MAX
};

enum {
    RULE_SECTION,
    RULE_NAME,
    RULE_ENABLED,
    RULE_FAMILY,
    RULE_PROTO,
    RULE_SRC,
    RULE_SRC_IP,
    RULE_SRC_PORT,
    RULE_DEST,
    RULE_DEST_IP,
    RULE_DEST_PORT,
    RULE_TARGET,
    RULE_DRY_RUN,
    __RULE_MAX
};

enum {
    ACCESS_HTTPS,
    ACCESS_HTTP,
    ACCESS_SSH,
    ACCESS_SNMP,
    ACCESS_REMOTE_WAN,
    ACCESS_LAN_SUBNET,
    __ACCESS_MAX
};

static const struct blobmsg_policy access_policy[__ACCESS_MAX] = {
    [ACCESS_HTTPS] = { .name = "https", .type = BLOBMSG_TYPE_BOOL },
    [ACCESS_HTTP] = { .name = "http", .type = BLOBMSG_TYPE_BOOL },
    [ACCESS_SSH] = { .name = "ssh", .type = BLOBMSG_TYPE_BOOL },
    [ACCESS_SNMP] = { .name = "snmp", .type = BLOBMSG_TYPE_BOOL },
    [ACCESS_REMOTE_WAN] = { .name = "remote_wan", .type = BLOBMSG_TYPE_BOOL },
    [ACCESS_LAN_SUBNET] = { .name = "lan_subnet", .type = BLOBMSG_TYPE_STRING },
};

struct access_control_data {
    bool https;
    bool http;
    bool ssh;
    bool snmp;
    bool remote_wan;
    bool snmp_available;
    bool changed;
    char lan_subnet[32];
};

static const struct blobmsg_policy rule_policy[__RULE_MAX] = {
    [RULE_SECTION] = { .name = "section", .type = BLOBMSG_TYPE_STRING },
    [RULE_NAME] = { .name = "name", .type = BLOBMSG_TYPE_STRING },
    [RULE_ENABLED] = { .name = "enabled", .type = BLOBMSG_TYPE_BOOL },
    [RULE_FAMILY] = { .name = "family", .type = BLOBMSG_TYPE_STRING },
    [RULE_PROTO] = { .name = "proto", .type = BLOBMSG_TYPE_STRING },
    [RULE_SRC] = { .name = "src", .type = BLOBMSG_TYPE_STRING },
    [RULE_SRC_IP] = { .name = "src_ip", .type = BLOBMSG_TYPE_STRING },
    [RULE_SRC_PORT] = { .name = "src_port", .type = BLOBMSG_TYPE_STRING },
    [RULE_DEST] = { .name = "dest", .type = BLOBMSG_TYPE_STRING },
    [RULE_DEST_IP] = { .name = "dest_ip", .type = BLOBMSG_TYPE_STRING },
    [RULE_DEST_PORT] = { .name = "dest_port", .type = BLOBMSG_TYPE_STRING },
    [RULE_TARGET] = { .name = "target", .type = BLOBMSG_TYPE_STRING },
    [RULE_DRY_RUN] = { .name = "dry_run", .type = BLOBMSG_TYPE_BOOL },
};

struct rule_action_data {
    const char *operation;
    const char *section;
    bool dry_run;
    bool changed;
    bool recovered;
    const char *uci_action_json;
    const char *uci_commit_json;
    const char *reload_json;
};

static const struct blobmsg_policy mac_policy[__MAC_MAX] = {
    [MAC_SECTION] = { .name = "section", .type = BLOBMSG_TYPE_STRING },
    [MAC_ENABLED] = { .name = "enabled", .type = BLOBMSG_TYPE_BOOL },
    [MAC_MODE] = { .name = "mode", .type = BLOBMSG_TYPE_STRING },
    [MAC_MAC] = { .name = "mac", .type = BLOBMSG_TYPE_STRING },
    [MAC_LABEL] = { .name = "label", .type = BLOBMSG_TYPE_STRING },
    [MAC_DRY_RUN] = { .name = "dry_run", .type = BLOBMSG_TYPE_BOOL },
};

struct mac_config_data {
    const char *uci_json;
};

struct mac_action_data {
    const char *operation;
    const char *section;
    const char *mac;
    bool dry_run;
    bool changed;
    const char *uci_action_json;
    const char *uci_commit_json;
    const char *reload_json;
};

static bool valid_section_name(const char *section)
{
    const char *p;

    if (!section || !section[0]) {
        return false;
    }

    for (p = section; *p; p++) {
        if (isalnum((unsigned char)*p) || *p == '_' || *p == '-') {
            continue;
        }
        return false;
    }

    return true;
}

static bool valid_mac(const char *mac)
{
    int i;

    if (!mac || strlen(mac) != 17) {
        return false;
    }

    for (i = 0; i < 17; i++) {
        if ((i + 1) % 3 == 0) {
            if (mac[i] != ':') {
                return false;
            }
        } else if (!isxdigit((unsigned char)mac[i])) {
            return false;
        }
    }

    return true;
}

static const char *json_get_string(struct json_object *obj, const char *name)
{
    struct json_object *value;

    if (!obj || !json_object_object_get_ex(obj, name, &value) ||
        !json_object_is_type(value, json_type_string)) {
        return "";
    }

    return json_object_get_string(value);
}

static bool json_string_equals(struct json_object *obj, const char *name, const char *match)
{
    return strcmp(json_get_string(obj, name), match) == 0;
}

static const char *mode_value(const char *mode)
{
    if (mode && (!strcmp(mode, "allow") || !strcmp(mode, "allow_list") ||
                 !strcmp(mode, "Allow list"))) {
        return "allow";
    }

    return "deny";
}

static const char *mode_label(const char *mode)
{
    return !strcmp(mode_value(mode), "allow") ? "Allow list" : "Deny list";
}

static const char *band_for_device(const char *device)
{
    if (!strcmp(device, "wifi1")) {
        return "2.4 GHz";
    }

    if (!strcmp(device, "wifi0")) {
        return "5 GHz";
    }

    return device && device[0] ? device : "-";
}

static void add_json_or_null(struct blob_buf *b, const char *name, const char *json)
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
        if (obj) {
            json_object_put(obj);
        }
        empty = blobmsg_open_table(b, name);
        blobmsg_close_table(b, empty);
        return;
    }

    json_object_put(obj);
}

static struct json_object *wireless_values_from_json(const char *uci_json)
{
    struct json_object *root = NULL;
    struct json_object *values = NULL;

    if (!uci_json) {
        return NULL;
    }

    root = json_tokener_parse(uci_json);
    if (!root) {
        return NULL;
    }

    if (!json_object_object_get_ex(root, "values", &values)) {
        json_object_put(root);
        return NULL;
    }

    json_object_get(values);
    json_object_put(root);
    return values;
}

static int maclist_count(struct json_object *section)
{
    struct json_object *list;

    if (!section || !json_object_object_get_ex(section, "maclist", &list)) {
        return 0;
    }

    if (json_object_is_type(list, json_type_array)) {
        return json_object_array_length(list);
    }

    if (json_object_is_type(list, json_type_string) &&
        json_object_get_string(list)[0]) {
        return 1;
    }

    return 0;
}

static bool maclist_contains(struct json_object *section, const char *mac)
{
    struct json_object *list;
    int i, len;

    if (!section || !mac ||
        !json_object_object_get_ex(section, "maclist", &list)) {
        return false;
    }

    if (json_object_is_type(list, json_type_string)) {
        return strcasecmp(json_object_get_string(list), mac) == 0;
    }

    if (!json_object_is_type(list, json_type_array)) {
        return false;
    }

    len = json_object_array_length(list);
    for (i = 0; i < len; i++) {
        struct json_object *item = json_object_array_get_idx(list, i);
        if (item && json_object_is_type(item, json_type_string) &&
            strcasecmp(json_object_get_string(item), mac) == 0) {
            return true;
        }
    }

    return false;
}

static void add_maclist_array(struct blob_buf *b,
                              struct json_object *section,
                              const char *add_mac,
                              const char *remove_mac)
{
    struct json_object *list;
    void *arr;
    int i, len;
    bool added = false;

    arr = blobmsg_open_array(b, "maclist");

    if (section && json_object_object_get_ex(section, "maclist", &list)) {
        if (json_object_is_type(list, json_type_array)) {
            len = json_object_array_length(list);
            for (i = 0; i < len; i++) {
                struct json_object *item = json_object_array_get_idx(list, i);
                const char *value;

                if (!item || !json_object_is_type(item, json_type_string)) {
                    continue;
                }

                value = json_object_get_string(item);
                if (remove_mac && strcasecmp(value, remove_mac) == 0) {
                    continue;
                }

                blobmsg_add_string(b, NULL, value);
                if (add_mac && strcasecmp(value, add_mac) == 0) {
                    added = true;
                }
            }
        } else if (json_object_is_type(list, json_type_string)) {
            const char *value = json_object_get_string(list);
            if ((!remove_mac || strcasecmp(value, remove_mac) != 0) && value[0]) {
                blobmsg_add_string(b, NULL, value);
                if (add_mac && strcasecmp(value, add_mac) == 0) {
                    added = true;
                }
            }
        }
    }

    if (add_mac && !added) {
        blobmsg_add_string(b, NULL, add_mac);
    }

    blobmsg_close_array(b, arr);
}

static void add_policy_entry(struct blob_buf *b, const char *mac, const char *mode)
{
    void *entry = blobmsg_open_table(b, NULL);

    blobmsg_add_string(b, "mac", mac ? mac : "");
    blobmsg_add_string(b, "label", "-");
    blobmsg_add_string(b, "policy", mode_label(mode));
    blobmsg_add_string(b, "last_seen", "-");
    blobmsg_add_string(b, "state", !strcmp(mode_value(mode), "deny") ? "Blocked" : "Allowed");
    blobmsg_close_table(b, entry);
}

static void add_policy_entries(struct blob_buf *b, struct json_object *section, const char *mode)
{
    struct json_object *list;
    void *entries = blobmsg_open_array(b, "entries");

    if (section && json_object_object_get_ex(section, "maclist", &list)) {
        if (json_object_is_type(list, json_type_array)) {
            int i, len = json_object_array_length(list);
            for (i = 0; i < len; i++) {
                struct json_object *item = json_object_array_get_idx(list, i);
                if (item && json_object_is_type(item, json_type_string)) {
                    add_policy_entry(b, json_object_get_string(item), mode);
                }
            }
        } else if (json_object_is_type(list, json_type_string) &&
                   json_object_get_string(list)[0]) {
            add_policy_entry(b, json_object_get_string(list), mode);
        }
    }

    blobmsg_close_array(b, entries);
}

static void mac_config_builder(struct blob_buf *b, void *user)
{
    struct mac_config_data *data = user;
    struct json_object *values;
    void *global;
    void *policies;
    int active_ssids = 0;
    int total_entries = 0;
    int policy_count = 0;
    bool any_enabled = false;

    values = wireless_values_from_json(data ? data->uci_json : NULL);

    if (values && json_object_is_type(values, json_type_object)) {
        json_object_object_foreach(values, name, section) {
            const char *macfilter;
            (void)name;

            if (!section || !json_object_is_type(section, json_type_object) ||
                !json_string_equals(section, ".type", "wifi-iface")) {
                continue;
            }

            policy_count++;
            total_entries += maclist_count(section);
            macfilter = json_get_string(section, "macfilter");
            if (macfilter[0] && strcmp(macfilter, "disable") != 0) {
                any_enabled = true;
                active_ssids++;
            }
        }
    }

    global = blobmsg_open_table(b, "global");
    blobmsg_add_u8(b, "enabled", any_enabled);
    blobmsg_add_string(b, "default_mode", "deny");
    blobmsg_add_u32(b, "active_ssids", active_ssids);
    blobmsg_add_u32(b, "total_entries", total_entries);
    blobmsg_add_u32(b, "policy_count", policy_count);
    blobmsg_close_table(b, global);

    policies = blobmsg_open_array(b, "policies");
    if (values && json_object_is_type(values, json_type_object)) {
        json_object_object_foreach(values, name, section) {
            const char *ssid;
            const char *device;
            const char *disabled;
            const char *macfilter;
            const char *mode;
            const char *network;
            int entries_count;
            void *policy;

            if (!section || !json_object_is_type(section, json_type_object) ||
                !json_string_equals(section, ".type", "wifi-iface")) {
                continue;
            }

            ssid = json_get_string(section, "ssid");
            device = json_get_string(section, "device");
            disabled = json_get_string(section, "disabled");
            macfilter = json_get_string(section, "macfilter");
            mode = mode_value(macfilter);
            network = json_get_string(section, "network");
            entries_count = maclist_count(section);

            policy = blobmsg_open_table(b, NULL);
            blobmsg_add_string(b, "section", name ? name : "");
            blobmsg_add_string(b, "ssid", ssid[0] ? ssid : (name ? name : "SSID"));
            blobmsg_add_string(b, "device", device);
            blobmsg_add_string(b, "band", band_for_device(device));
            blobmsg_add_string(b, "network", network[0] ? network : "lan");
            blobmsg_add_u8(b, "ssid_enabled", strcmp(disabled, "1") != 0);
            blobmsg_add_u8(b, "filter_enabled", macfilter[0] && strcmp(macfilter, "disable") != 0);
            blobmsg_add_string(b, "mode", mode);
            blobmsg_add_string(b, "mode_label", mode_label(mode));
            blobmsg_add_u32(b, "entries_count", entries_count);
            add_policy_entries(b, section, mode);
            blobmsg_close_table(b, policy);
        }
    }
    blobmsg_close_array(b, policies);

    if (values) {
        json_object_put(values);
    }
}

static void mac_action_builder(struct blob_buf *b, void *user)
{
    struct mac_action_data *data = user;

    if (!data) {
        return;
    }

    blobmsg_add_string(b, "operation", data->operation);
    blobmsg_add_string(b, "section", data->section ? data->section : "");
    blobmsg_add_string(b, "mac", data->mac ? data->mac : "");
    blobmsg_add_u8(b, "dry_run", data->dry_run);
    blobmsg_add_u8(b, "changed", data->changed);
    add_json_or_null(b, "uci_action", data->uci_action_json);
    add_json_or_null(b, "uci_commit", data->uci_commit_json);
    add_json_or_null(b, "network_reload", data->reload_json);
}

static int commit_and_reload(struct ubus_context *ctx,
                             struct airui_ubus_result *commit,
                             struct airui_ubus_result *reload)
{
    struct blob_buf uci_commit = {};
    int ret;

    blob_buf_init(&uci_commit, 0);
    blobmsg_add_string(&uci_commit, "config", "wireless");
    ret = airui_ubus_call_json(ctx, "uci", "commit", &uci_commit, commit);
    blob_buf_free(&uci_commit);
    if (ret) {
        return ret;
    }

    {
        bool recovered = false;
        return airui_network_reload_with_recovery(ctx, reload, 15, &recovered);
    }
}

static int call_uci_get_wireless(struct ubus_context *ctx, struct airui_ubus_result *uci)
{
    struct blob_buf query = {};
    int ret;

    blob_buf_init(&query, 0);
    blobmsg_add_string(&query, "config", "wireless");
    ret = airui_ubus_call_json(ctx, "uci", "get", &query, uci);
    blob_buf_free(&query);
    return ret;
}

static struct json_object *find_section(struct json_object *values, const char *section_name)
{
    struct json_object *section;

    if (!values || !json_object_object_get_ex(values, section_name, &section) ||
        !json_string_equals(section, ".type", "wifi-iface")) {
        return NULL;
    }

    return section;
}

int airui_security_mac_filter_config(struct ubus_context *ctx,
                                     struct ubus_object *obj,
                                     struct ubus_request_data *req,
                                     const char *method,
                                     struct blob_attr *msg)
{
    struct airui_ubus_result uci = {};
    struct mac_config_data data;

    (void)obj;
    (void)method;
    (void)msg;

    if (call_uci_get_wireless(ctx, &uci)) {
        airui_reply_error(ctx, req, "backend_unavailable", "uci",
                          "Unable to read wireless configuration");
        return 0;
    }

    data.uci_json = uci.json;
    airui_reply_ok_schema(ctx, req, mac_config_builder, &data, "live",
                          "airui.security.mac_filter.v1");
    airui_ubus_result_free(&uci);
    return 0;
}

int airui_security_mac_filter_set(struct ubus_context *ctx,
                                  struct ubus_object *obj,
                                  struct ubus_request_data *req,
                                  const char *method,
                                  struct blob_attr *msg)
{
    struct blob_attr *tb[__MAC_MAX];
    struct airui_ubus_result set = {};
    struct airui_ubus_result commit = {};
    struct airui_ubus_result reload = {};
    struct mac_action_data data = {};
    struct blob_buf uci_set = {};
    const char *section;
    const char *mode;
    bool dry_run;
    bool enabled;
    int ret;

    (void)obj;
    (void)method;

    blobmsg_parse(mac_policy, __MAC_MAX, tb,
                  msg ? blob_data(msg) : NULL,
                  msg ? blob_len(msg) : 0);

    if (!tb[MAC_SECTION]) {
        airui_reply_error(ctx, req, "invalid_argument", "section",
                          "SSID section is required");
        return 0;
    }

    section = blobmsg_get_string(tb[MAC_SECTION]);
    if (!valid_section_name(section)) {
        airui_reply_error(ctx, req, "invalid_argument", "section",
                          "SSID section contains unsupported characters");
        return 0;
    }

    enabled = !tb[MAC_ENABLED] || blobmsg_get_bool(tb[MAC_ENABLED]);
    mode = tb[MAC_MODE] ? mode_value(blobmsg_get_string(tb[MAC_MODE])) : "deny";
    dry_run = tb[MAC_DRY_RUN] && blobmsg_get_bool(tb[MAC_DRY_RUN]);
    data.operation = "set";
    data.section = section;
    data.dry_run = dry_run;
    data.changed = !dry_run;

    if (!dry_run) {
        void *values;

        airui_apply_begin("mac_filter");
        blob_buf_init(&uci_set, 0);
        blobmsg_add_string(&uci_set, "config", "wireless");
        blobmsg_add_string(&uci_set, "section", section);
        values = blobmsg_open_table(&uci_set, "values");
        blobmsg_add_string(&uci_set, "macfilter", enabled ? mode : "disable");
        blobmsg_close_table(&uci_set, values);

        ret = airui_ubus_call_json(ctx, "uci", "set", &uci_set, &set);
        blob_buf_free(&uci_set);
        if (ret) {
            airui_apply_failed("Unable to update MAC filter policy");
            airui_reply_error(ctx, req, "backend_unavailable", "uci",
                              ubus_strerror(ret));
            return 0;
        }

        ret = commit_and_reload(ctx, &commit, &reload);
        if (ret) {
            airui_apply_failed("Unable to reload MAC filter policy");
            airui_ubus_result_free(&set);
            airui_reply_error(ctx, req, "backend_unavailable", NULL,
                              ubus_strerror(ret));
            return 0;
        }
    }

    data.uci_action_json = set.json;
    data.uci_commit_json = commit.json;
    data.reload_json = reload.json;
    airui_reply_ok_schema(ctx, req, mac_action_builder, &data, "uci",
                          "airui.security.mac_filter.v1");
    if (!dry_run)
        airui_apply_success("MAC filter policy applied");
    airui_ubus_result_free(&set);
    airui_ubus_result_free(&commit);
    airui_ubus_result_free(&reload);
    return 0;
}

static int update_mac_entry(struct ubus_context *ctx,
                            struct ubus_request_data *req,
                            struct blob_attr *msg,
                            bool add)
{
    struct blob_attr *tb[__MAC_MAX];
    struct airui_ubus_result uci = {};
    struct airui_ubus_result set = {};
    struct airui_ubus_result commit = {};
    struct airui_ubus_result reload = {};
    struct mac_action_data data = {};
    struct json_object *values = NULL;
    struct json_object *section_json;
    struct blob_buf uci_set = {};
    const char *section;
    const char *mac;
    bool dry_run;
    int ret;

    blobmsg_parse(mac_policy, __MAC_MAX, tb,
                  msg ? blob_data(msg) : NULL,
                  msg ? blob_len(msg) : 0);

    if (!tb[MAC_SECTION] || !tb[MAC_MAC]) {
        airui_reply_error(ctx, req, "invalid_argument", NULL,
                          "SSID section and MAC address are required");
        return 0;
    }

    section = blobmsg_get_string(tb[MAC_SECTION]);
    mac = blobmsg_get_string(tb[MAC_MAC]);

    if (!valid_section_name(section)) {
        airui_reply_error(ctx, req, "invalid_argument", "section",
                          "SSID section contains unsupported characters");
        return 0;
    }

    if (!valid_mac(mac)) {
        airui_reply_error(ctx, req, "invalid_argument", "mac",
                          "MAC address must use xx:xx:xx:xx:xx:xx format");
        return 0;
    }

    ret = call_uci_get_wireless(ctx, &uci);
    if (ret) {
        airui_reply_error(ctx, req, "backend_unavailable", "uci",
                          ubus_strerror(ret));
        return 0;
    }

    values = wireless_values_from_json(uci.json);
    section_json = find_section(values, section);
    if (!section_json) {
        airui_ubus_result_free(&uci);
        if (values) {
            json_object_put(values);
        }
        airui_reply_error(ctx, req, "not_found", "section",
                          "SSID policy was not found");
        return 0;
    }

    if (add && maclist_contains(section_json, mac)) {
        airui_ubus_result_free(&uci);
        json_object_put(values);
        airui_reply_error(ctx, req, "already_exists", "mac",
                          "MAC address already exists for this SSID");
        return 0;
    }

    if (!add && !maclist_contains(section_json, mac)) {
        airui_ubus_result_free(&uci);
        json_object_put(values);
        airui_reply_error(ctx, req, "not_found", "mac",
                          "MAC address was not found for this SSID");
        return 0;
    }

    dry_run = tb[MAC_DRY_RUN] && blobmsg_get_bool(tb[MAC_DRY_RUN]);
    data.operation = add ? "entry_add" : "entry_delete";
    data.section = section;
    data.mac = mac;
    data.dry_run = dry_run;
    data.changed = !dry_run;

    if (!dry_run) {
        void *uci_values;

        airui_apply_begin("mac_filter");
        blob_buf_init(&uci_set, 0);
        blobmsg_add_string(&uci_set, "config", "wireless");
        blobmsg_add_string(&uci_set, "section", section);
        uci_values = blobmsg_open_table(&uci_set, "values");
        add_maclist_array(&uci_set, section_json, add ? mac : NULL, add ? NULL : mac);
        blobmsg_close_table(&uci_set, uci_values);

        ret = airui_ubus_call_json(ctx, "uci", "set", &uci_set, &set);
        blob_buf_free(&uci_set);
        if (ret) {
            airui_apply_failed("Unable to update MAC filter entry");
            airui_ubus_result_free(&uci);
            json_object_put(values);
            airui_reply_error(ctx, req, "backend_unavailable", "uci",
                              ubus_strerror(ret));
            return 0;
        }

        ret = commit_and_reload(ctx, &commit, &reload);
        if (ret) {
            airui_apply_failed("Unable to reload MAC filter entry");
            airui_ubus_result_free(&uci);
            airui_ubus_result_free(&set);
            json_object_put(values);
            airui_reply_error(ctx, req, "backend_unavailable", NULL,
                              ubus_strerror(ret));
            return 0;
        }
    }

    data.uci_action_json = set.json;
    data.uci_commit_json = commit.json;
    data.reload_json = reload.json;
    airui_reply_ok_schema(ctx, req, mac_action_builder, &data, "uci",
                          "airui.security.mac_filter.v1");
    if (!dry_run)
        airui_apply_success(add ? "MAC filter entry added" :
                                  "MAC filter entry deleted");

    airui_ubus_result_free(&uci);
    airui_ubus_result_free(&set);
    airui_ubus_result_free(&commit);
    airui_ubus_result_free(&reload);
    json_object_put(values);
    return 0;
}

int airui_security_mac_filter_entry_add(struct ubus_context *ctx,
                                        struct ubus_object *obj,
                                        struct ubus_request_data *req,
                                        const char *method,
                                        struct blob_attr *msg)
{
    (void)obj;
    (void)method;
    return update_mac_entry(ctx, req, msg, true);
}

int airui_security_mac_filter_entry_delete(struct ubus_context *ctx,
                                           struct ubus_object *obj,
                                           struct ubus_request_data *req,
                                           const char *method,
                                           struct blob_attr *msg)
{
    (void)obj;
    (void)method;
    return update_mac_entry(ctx, req, msg, false);
}

static bool valid_rule_choice(const char *value, const char *const *choices,
                              size_t count)
{
    size_t i;

    if (!value)
        return false;
    for (i = 0; i < count; i++) {
        if (strcmp(value, choices[i]) == 0)
            return true;
    }
    return false;
}

static bool valid_rule_text(const char *value)
{
    const unsigned char *p = (const unsigned char *)value;

    if (!value || strlen(value) > 128)
        return false;
    for (; *p; p++) {
        if (*p < 32 || *p == 127)
            return false;
    }
    return true;
}

static int get_firewall_config(struct ubus_context *ctx,
                               struct airui_ubus_result *result)
{
    struct blob_buf query = {};
    int ret;

    blob_buf_init(&query, 0);
    blobmsg_add_string(&query, "config", "firewall");
    ret = airui_ubus_call_json(ctx, "uci", "get", &query, result);
    blob_buf_free(&query);
    return ret;
}

static struct json_object *config_values_from_json(const char *json)
{
    struct json_object *root;
    struct json_object *values;

    if (!json || !(root = json_tokener_parse(json)))
        return NULL;
    if (!json_object_object_get_ex(root, "values", &values) ||
        !json_object_is_type(values, json_type_object)) {
        json_object_put(root);
        return NULL;
    }
    json_object_get(values);
    json_object_put(root);
    return values;
}

static void rules_builder(struct blob_buf *b, void *user)
{
    const char *json = user;
    struct json_object *values = config_values_from_json(json);
    void *rules = blobmsg_open_array(b, "rules");
    unsigned int count = 0;

    if (values) {
        json_object_object_foreach(values, section_name, section) {
            void *rule;
            const char *disabled;
            const char *enabled;
            bool is_enabled = true;

            if (!section || !json_object_is_type(section, json_type_object) ||
                !json_string_equals(section, ".type", "rule"))
                continue;

            enabled = json_get_string(section, "enabled");
            disabled = json_get_string(section, "disabled");
            if (enabled[0])
                is_enabled = strcmp(enabled, "0") != 0;
            else if (disabled[0])
                is_enabled = strcmp(disabled, "1") != 0;
            rule = blobmsg_open_table(b, NULL);
            blobmsg_add_string(b, "section", section_name);
            blobmsg_add_string(b, "name", json_get_string(section, "name"));
            blobmsg_add_u8(b, "enabled", is_enabled);
            blobmsg_add_string(b, "family", json_get_string(section, "family"));
            blobmsg_add_string(b, "proto", json_get_string(section, "proto"));
            blobmsg_add_string(b, "src", json_get_string(section, "src"));
            blobmsg_add_string(b, "src_ip", json_get_string(section, "src_ip"));
            blobmsg_add_string(b, "src_port", json_get_string(section, "src_port"));
            blobmsg_add_string(b, "dest", json_get_string(section, "dest"));
            blobmsg_add_string(b, "dest_ip", json_get_string(section, "dest_ip"));
            blobmsg_add_string(b, "dest_port", json_get_string(section, "dest_port"));
            blobmsg_add_string(b, "target", json_get_string(section, "target"));
            blobmsg_close_table(b, rule);
            count++;
        }
    }
    blobmsg_close_array(b, rules);
    blobmsg_add_u32(b, "count", count);
    if (values)
        json_object_put(values);
}

static void rule_action_builder(struct blob_buf *b, void *user)
{
    struct rule_action_data *data = user;

    blobmsg_add_string(b, "operation", data->operation);
    blobmsg_add_string(b, "section", data->section);
    blobmsg_add_u8(b, "dry_run", data->dry_run);
    blobmsg_add_u8(b, "changed", data->changed);
    blobmsg_add_u8(b, "recovered", data->recovered);
    add_json_or_null(b, "uci_action", data->uci_action_json);
    add_json_or_null(b, "uci_commit", data->uci_commit_json);
    add_json_or_null(b, "reload", data->reload_json);
}

static bool firewall_rule_exists(struct ubus_context *ctx, const char *section)
{
    struct airui_ubus_result config = {};
    struct json_object *values;
    struct json_object *entry = NULL;
    bool exists = false;

    if (get_firewall_config(ctx, &config) == 0) {
        values = config_values_from_json(config.json);
        if (values && json_object_object_get_ex(values, section, &entry) &&
            json_string_equals(entry, ".type", "rule"))
            exists = true;
        if (values)
            json_object_put(values);
    }
    airui_ubus_result_free(&config);
    return exists;
}

static int commit_firewall(struct ubus_context *ctx,
                           struct airui_ubus_result *commit)
{
    struct blob_buf request = {};
    int ret;

    blob_buf_init(&request, 0);
    blobmsg_add_string(&request, "config", "firewall");
    ret = airui_ubus_call_json(ctx, "uci", "commit", &request, commit);
    blob_buf_free(&request);
    return ret;
}

static bool shell_ok(int status)
{
    return status != -1 && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static bool command_has_output(const char *command)
{
    FILE *fp;
    int ch;

    fp = popen(command, "r");
    if (!fp)
        return false;
    ch = fgetc(fp);
    pclose(fp);
    return ch != EOF;
}

static bool read_command_line(const char *command, char *value, size_t size)
{
    FILE *fp;
    size_t len;

    if (!value || size == 0)
        return false;
    value[0] = '\0';
    fp = popen(command, "r");
    if (!fp)
        return false;
    if (!fgets(value, size, fp)) {
        pclose(fp);
        return false;
    }
    pclose(fp);
    len = strlen(value);
    while (len && (value[len - 1] == '\n' || value[len - 1] == '\r'))
        value[--len] = '\0';
    return len > 0;
}

static bool valid_ipv4_cidr(const char *value)
{
    struct in_addr address;
    char copy[32];
    char *slash;
    char *end;
    long prefix;

    if (!value || strlen(value) >= sizeof(copy))
        return false;
    snprintf(copy, sizeof(copy), "%s", value);
    slash = strchr(copy, '/');
    if (!slash || strchr(slash + 1, '/'))
        return false;
    *slash++ = '\0';
    if (inet_pton(AF_INET, copy, &address) != 1)
        return false;
    prefix = strtol(slash, &end, 10);
    return *slash && !*end && prefix >= 0 && prefix <= 32;
}

static bool service_running(const char *service)
{
    char command[128];

    snprintf(command, sizeof(command),
             "/etc/init.d/%s running >/dev/null 2>&1", service);
    return shell_ok(system(command));
}

static bool dropbear_enabled_uci(void)
{
    char enable[8];

    if (!read_command_line("uci -q get dropbear.@dropbear[0].enable 2>/dev/null",
                           enable, sizeof(enable)))
        return true;

    return strcmp(enable, "0") != 0;
}

static bool stop_dropbear_service(void)
{
    system("/etc/init.d/dropbear disable >/dev/null 2>&1");
    system("/etc/init.d/dropbear stop >/dev/null 2>&1");
    if (service_running("dropbear"))
        system("killall dropbear >/dev/null 2>&1");
    usleep(200000);
    return !service_running("dropbear");
}

static bool start_dropbear_service(void)
{
    if (!shell_ok(system("/etc/init.d/dropbear enable >/dev/null 2>&1")))
        return false;
    if (service_running("dropbear"))
        return true;
    return shell_ok(system("/etc/init.d/dropbear start >/dev/null 2>&1")) &&
           service_running("dropbear");
}

static void access_control_read(struct access_control_data *data)
{
    memset(data, 0, sizeof(*data));
    data->https = command_has_output("uci -q get uhttpd.main.listen_https 2>/dev/null");
    data->http = command_has_output("uci -q get uhttpd.main.listen_http 2>/dev/null");
    data->ssh = dropbear_enabled_uci() && service_running("dropbear");
    data->snmp_available = access("/etc/init.d/snmpd", X_OK) == 0;
    data->snmp = data->snmp_available && service_running("snmpd");
    data->remote_wan = command_has_output(
        "uci -q get airui_access.main.remote_wan 2>/dev/null | grep -x 1");
    if (!read_command_line("uci -q get airui_access.main.lan_subnet 2>/dev/null",
                           data->lan_subnet, sizeof(data->lan_subnet)))
        snprintf(data->lan_subnet, sizeof(data->lan_subnet), "192.168.1.0/24");
}

static void access_control_builder(struct blob_buf *b, void *user)
{
    struct access_control_data *data = user;

    blobmsg_add_u8(b, "https", data->https);
    blobmsg_add_u8(b, "http", data->http);
    blobmsg_add_u8(b, "ssh", data->ssh);
    blobmsg_add_u8(b, "snmp", data->snmp);
    blobmsg_add_u8(b, "remote_wan", data->remote_wan);
    blobmsg_add_u8(b, "snmp_available", data->snmp_available);
    blobmsg_add_string(b, "lan_subnet", data->lan_subnet);
    blobmsg_add_u8(b, "changed", data->changed);
}

static void restore_access_control(void)
{
    system("cp -f /tmp/uhttpd.airui.access.bak /etc/config/uhttpd 2>/dev/null");
    system("cp -f /tmp/dropbear.airui.access.bak /etc/config/dropbear 2>/dev/null");
    system("cp -f /tmp/firewall.airui.access.bak /etc/config/firewall 2>/dev/null");
    system("if test -f /tmp/airui_access.airui.access.bak; then cp -f /tmp/airui_access.airui.access.bak /etc/config/airui_access; else rm -f /etc/config/airui_access; fi");
    system("uci commit uhttpd; uci commit dropbear; uci commit firewall; uci commit airui_access 2>/dev/null");
    system("/etc/init.d/uhttpd restart >/dev/null 2>&1");
    system("/etc/init.d/firewall restart >/dev/null 2>&1");
    if (dropbear_enabled_uci())
        start_dropbear_service();
    else
        stop_dropbear_service();
}

static int configure_access_firewall(bool https, bool http, bool ssh, bool snmp,
                                     bool remote_wan, const char *subnet)
{
    static const struct {
        const char *key;
        const char *label;
        const char *proto;
        const char *port;
    } services[] = {
        { "https", "HTTPS", "tcp", "443" },
        { "http", "HTTP", "tcp", "80" },
        { "ssh", "SSH", "tcp", "3041" },
        { "snmp", "SNMP", "udp", "161" },
    };
    const bool enabled[] = { https, http, ssh, snmp };
    char command[4096];
    size_t used = 0;
    size_t i;

    command[0] = '\0';
    for (i = 0; i < sizeof(services) / sizeof(services[0]); i++)
        used += snprintf(command + used, sizeof(command) - used,
                         "uci -q delete firewall.airui_access_%s;", services[i].key);
    for (i = 0; i < sizeof(services) / sizeof(services[0]); i++) {
        if (!enabled[i])
            continue;
        used += snprintf(command + used, sizeof(command) - used,
                         "uci set firewall.airui_access_%s=rule;"
                         "uci set firewall.airui_access_%s.name='AirUI-%s';"
                         "uci set firewall.airui_access_%s.family='ipv4';"
                         "uci set firewall.airui_access_%s.proto='%s';"
                         "uci set firewall.airui_access_%s.src='%s';"
                         "uci set firewall.airui_access_%s.dest_port='%s';"
                         "uci set firewall.airui_access_%s.target='ACCEPT';",
                         services[i].key, services[i].key, services[i].label,
                         services[i].key, services[i].key, services[i].proto,
                         services[i].key, remote_wan ? "wan" : "lan",
                         services[i].key, services[i].port, services[i].key);
        if (!remote_wan)
            used += snprintf(command + used, sizeof(command) - used,
                             "uci set firewall.airui_access_%s.src_ip='%s';",
                             services[i].key, subnet);
    }
    snprintf(command + used, sizeof(command) - used, "uci commit firewall");
    return shell_ok(system(command)) ? 0 : -1;
}

static int apply_firewall_with_rollback(void)
{
    int ret = system("/etc/init.d/firewall restart >/dev/null 2>&1");

    if (shell_ok(ret))
        return 0;

    system("cp -f /etc/config/firewall.airui.rules.bak /etc/config/firewall");
    return shell_ok(system("/etc/init.d/firewall restart >/dev/null 2>&1")) ?
           UBUS_STATUS_UNKNOWN_ERROR : UBUS_STATUS_TIMEOUT;
}

static int mutate_rule(struct ubus_context *ctx,
                       struct ubus_request_data *req,
                       struct blob_attr *msg,
                       const char *operation)
{
    static const char *const targets[] = { "ACCEPT", "REJECT", "DROP" };
    static const char *const protocols[] = {
        "any", "all", "tcp", "udp", "icmp", "tcp udp"
    };
    static const char *const families[] = { "any", "ipv4", "ipv6" };
    struct blob_attr *tb[__RULE_MAX];
    struct airui_ubus_result action = {};
    struct airui_ubus_result commit = {};
    struct airui_ubus_result reload = {};
    struct rule_action_data data = {};
    struct blob_buf request = {};
    char generated[48];
    const char *section;
    bool adding = strcmp(operation, "add") == 0;
    bool deleting = strcmp(operation, "delete") == 0;
    bool dry_run;
    int ret;

    blobmsg_parse(rule_policy, __RULE_MAX, tb,
                  msg ? blob_data(msg) : NULL,
                  msg ? blob_len(msg) : 0);

    if (adding && !tb[RULE_SECTION]) {
        snprintf(generated, sizeof(generated), "airui_rule_%ld", (long)time(NULL));
        section = generated;
    } else if (tb[RULE_SECTION]) {
        section = blobmsg_get_string(tb[RULE_SECTION]);
    } else {
        airui_reply_error(ctx, req, "invalid_argument", "section",
                          "Rule section is required");
        return 0;
    }

    if (!valid_section_name(section)) {
        airui_reply_error(ctx, req, "invalid_argument", "section",
                          "Rule section contains unsupported characters");
        return 0;
    }
    if (adding == firewall_rule_exists(ctx, section)) {
        airui_reply_error(ctx, req, adding ? "already_exists" : "not_found",
                          "section", adding ? "Rule already exists" :
                          "Rule was not found");
        return 0;
    }
    if (!deleting) {
        if ((adding && !tb[RULE_NAME]) ||
            (tb[RULE_NAME] && !valid_rule_text(blobmsg_get_string(tb[RULE_NAME])))) {
            airui_reply_error(ctx, req, "invalid_argument", "name",
                              "A valid rule name is required");
            return 0;
        }
        if (tb[RULE_TARGET] &&
            !valid_rule_choice(blobmsg_get_string(tb[RULE_TARGET]), targets, 3)) {
            airui_reply_error(ctx, req, "invalid_argument", "target",
                              "Target must be ACCEPT, REJECT, or DROP");
            return 0;
        }
        if (tb[RULE_PROTO] &&
            !valid_rule_choice(blobmsg_get_string(tb[RULE_PROTO]), protocols, 6)) {
            airui_reply_error(ctx, req, "invalid_argument", "proto",
                              "Unsupported rule protocol");
            return 0;
        }
        if (tb[RULE_FAMILY] &&
            !valid_rule_choice(blobmsg_get_string(tb[RULE_FAMILY]), families, 3)) {
            airui_reply_error(ctx, req, "invalid_argument", "family",
                              "Family must be any, ipv4, or ipv6");
            return 0;
        }
    }

    dry_run = tb[RULE_DRY_RUN] && blobmsg_get_bool(tb[RULE_DRY_RUN]);
    data.operation = operation;
    data.section = section;
    data.dry_run = dry_run;
    data.changed = !dry_run;

    if (!dry_run) {
        if (!shell_ok(system("cp -f /etc/config/firewall /etc/config/firewall.airui.rules.bak"))) {
            airui_reply_error(ctx, req, "backup_failed", NULL,
                              "Unable to back up firewall configuration");
            return 0;
        }

        blob_buf_init(&request, 0);
        blobmsg_add_string(&request, "config", "firewall");
        if (deleting) {
            blobmsg_add_string(&request, "section", section);
            ret = airui_ubus_call_json(ctx, "uci", "delete", &request, &action);
        } else {
            void *values;

            if (adding) {
                blobmsg_add_string(&request, "type", "rule");
                blobmsg_add_string(&request, "name", section);
            } else
                blobmsg_add_string(&request, "section", section);
            values = blobmsg_open_table(&request, "values");
#define ADD_RULE_STRING(index, key) \
            do { if (tb[index]) blobmsg_add_string(&request, key, \
                    blobmsg_get_string(tb[index])); } while (0)
            ADD_RULE_STRING(RULE_NAME, "name");
            ADD_RULE_STRING(RULE_FAMILY, "family");
            ADD_RULE_STRING(RULE_PROTO, "proto");
            ADD_RULE_STRING(RULE_SRC, "src");
            ADD_RULE_STRING(RULE_SRC_IP, "src_ip");
            ADD_RULE_STRING(RULE_SRC_PORT, "src_port");
            ADD_RULE_STRING(RULE_DEST, "dest");
            ADD_RULE_STRING(RULE_DEST_IP, "dest_ip");
            ADD_RULE_STRING(RULE_DEST_PORT, "dest_port");
            ADD_RULE_STRING(RULE_TARGET, "target");
#undef ADD_RULE_STRING
            if (tb[RULE_ENABLED])
                blobmsg_add_string(&request, "enabled",
                                   blobmsg_get_bool(tb[RULE_ENABLED]) ? "1" : "0");
            blobmsg_add_string(&request, "airui_managed", "1");
            blobmsg_close_table(&request, values);
            ret = airui_ubus_call_json(ctx, "uci", adding ? "add" : "set",
                                       &request, &action);
        }
        blob_buf_free(&request);

        if (!ret)
            ret = commit_firewall(ctx, &commit);
        if (!ret)
            ret = apply_firewall_with_rollback();
        if (ret) {
            system("cp -f /etc/config/firewall.airui.rules.bak /etc/config/firewall");
            data.recovered = shell_ok(system(
                "/etc/init.d/firewall restart >/dev/null 2>&1"));
            airui_reply_error(ctx, req,
                              data.recovered ? "apply_rolled_back" : "recovery_failed",
                              NULL, data.recovered ?
                              "Firewall rule apply failed; previous configuration restored" :
                              "Firewall rule apply failed and firewall recovery failed");
            goto out;
        }
    }

    data.uci_action_json = action.json;
    data.uci_commit_json = commit.json;
    data.reload_json = reload.json;
    airui_reply_ok_schema(ctx, req, rule_action_builder, &data, "uci",
                          "airui.security.rules.v1");

out:
    airui_ubus_result_free(&action);
    airui_ubus_result_free(&commit);
    airui_ubus_result_free(&reload);
    return 0;
}

int airui_security_rules(struct ubus_context *ctx,
                         struct ubus_object *obj,
                         struct ubus_request_data *req,
                         const char *method,
                         struct blob_attr *msg)
{
    struct airui_ubus_result config = {};

    (void)obj;
    (void)method;
    (void)msg;
    if (get_firewall_config(ctx, &config)) {
        airui_reply_error(ctx, req, "backend_unavailable", "firewall",
                          "Unable to read firewall rules");
        return 0;
    }
    airui_reply_ok_schema(ctx, req, rules_builder, config.json, "uci",
                          "airui.security.rules.v1");
    airui_ubus_result_free(&config);
    return 0;
}

int airui_security_rule_add(struct ubus_context *ctx,
                            struct ubus_object *obj,
                            struct ubus_request_data *req,
                            const char *method,
                            struct blob_attr *msg)
{
    (void)obj;
    (void)method;
    return mutate_rule(ctx, req, msg, "add");
}

int airui_security_rule_set(struct ubus_context *ctx,
                            struct ubus_object *obj,
                            struct ubus_request_data *req,
                            const char *method,
                            struct blob_attr *msg)
{
    (void)obj;
    (void)method;
    return mutate_rule(ctx, req, msg, "set");
}

int airui_security_rule_delete(struct ubus_context *ctx,
                               struct ubus_object *obj,
                               struct ubus_request_data *req,
                               const char *method,
                               struct blob_attr *msg)
{
    (void)obj;
    (void)method;
    return mutate_rule(ctx, req, msg, "delete");
}

int airui_security_access_control_get(struct ubus_context *ctx,
                                      struct ubus_object *obj,
                                      struct ubus_request_data *req,
                                      const char *method,
                                      struct blob_attr *msg)
{
    struct access_control_data data;

    (void)obj;
    (void)method;
    (void)msg;
    access_control_read(&data);
    airui_reply_ok_schema(ctx, req, access_control_builder, &data, "system",
                          "airui.security.access_control.v1");
    return 0;
}

int airui_security_access_control_set(struct ubus_context *ctx,
                                      struct ubus_object *obj,
                                      struct ubus_request_data *req,
                                      const char *method,
                                      struct blob_attr *msg)
{
    struct blob_attr *tb[__ACCESS_MAX];
    struct access_control_data data;
    char command[2048];
    const char *subnet;
    bool https;
    bool http;
    bool ssh;
    bool snmp;
    bool remote_wan;
    int ret = 0;

    (void)obj;
    (void)method;
    blobmsg_parse(access_policy, __ACCESS_MAX, tb,
                  msg ? blob_data(msg) : NULL,
                  msg ? blob_len(msg) : 0);
    if (!tb[ACCESS_HTTPS] || !tb[ACCESS_HTTP] || !tb[ACCESS_SSH] ||
        !tb[ACCESS_SNMP] || !tb[ACCESS_REMOTE_WAN] || !tb[ACCESS_LAN_SUBNET]) {
        airui_reply_error(ctx, req, "invalid_argument", NULL,
                          "All access control fields are required");
        return 0;
    }

    https = blobmsg_get_bool(tb[ACCESS_HTTPS]);
    http = blobmsg_get_bool(tb[ACCESS_HTTP]);
    ssh = blobmsg_get_bool(tb[ACCESS_SSH]);
    snmp = blobmsg_get_bool(tb[ACCESS_SNMP]);
    remote_wan = blobmsg_get_bool(tb[ACCESS_REMOTE_WAN]);
    subnet = blobmsg_get_string(tb[ACCESS_LAN_SUBNET]);
    if (!https && !http) {
        airui_reply_error(ctx, req, "invalid_argument", "https",
                          "Keep HTTP or HTTPS enabled to preserve web management access");
        return 0;
    }
    if (!valid_ipv4_cidr(subnet)) {
        airui_reply_error(ctx, req, "invalid_argument", "lan_subnet",
                          "LAN subnet must be a valid IPv4 CIDR");
        return 0;
    }
    if (snmp && access("/etc/init.d/snmpd", X_OK) != 0) {
        airui_reply_error(ctx, req, "unsupported", "snmp",
                          "SNMP service is not installed on this device");
        return 0;
    }

    if (!shell_ok(system(
            "cp -f /etc/config/uhttpd /tmp/uhttpd.airui.access.bak && "
            "cp -f /etc/config/dropbear /tmp/dropbear.airui.access.bak && "
            "cp -f /etc/config/firewall /tmp/firewall.airui.access.bak"))) {
        airui_reply_error(ctx, req, "backup_failed", NULL,
                          "Unable to back up access control configuration");
        return 0;
    }
    system("rm -f /tmp/airui_access.airui.access.bak");
    if (access("/etc/config/airui_access", F_OK) == 0 &&
        !shell_ok(system("cp -f /etc/config/airui_access /tmp/airui_access.airui.access.bak"))) {
        airui_reply_error(ctx, req, "backup_failed", NULL,
                          "Unable to back up access control configuration");
        return 0;
    }

    if (!shell_ok(system("touch /etc/config/airui_access"))) {
        airui_reply_error(ctx, req, "apply_failed", NULL,
                          "Unable to initialize access control configuration");
        return 0;
    }

    airui_apply_begin("access_control");
    snprintf(command, sizeof(command),
             "uci -q delete uhttpd.main.listen_http;"
             "uci -q delete uhttpd.main.listen_https;"
             "%s%s"
             "uci set dropbear.@dropbear[0].enable='%u';"
             "uci set airui_access.main=access;"
             "uci set airui_access.main.remote_wan='%u';"
             "uci set airui_access.main.lan_subnet='%s';"
             "uci commit uhttpd;uci commit dropbear;uci commit airui_access",
             http ? "uci add_list uhttpd.main.listen_http='0.0.0.0:80';uci add_list uhttpd.main.listen_http='[::]:80';" : "",
             https ? "uci add_list uhttpd.main.listen_https='0.0.0.0:443';uci add_list uhttpd.main.listen_https='[::]:443';" : "",
             ssh ? 1U : 0U, remote_wan ? 1U : 0U, subnet);
    if (!shell_ok(system(command)) ||
        configure_access_firewall(https, http, ssh, snmp, remote_wan, subnet) ||
        !shell_ok(system("/etc/init.d/firewall restart >/dev/null 2>&1")) ||
        !shell_ok(system("/etc/init.d/uhttpd reload >/dev/null 2>&1")))
        ret = -1;

    if (!ret && ssh) {
        if (!start_dropbear_service())
            ret = -1;
    } else if (!ret) {
        if (!stop_dropbear_service())
            ret = -1;
    }
    if (!ret && snmp) {
        if (!shell_ok(system("/etc/init.d/snmpd enable >/dev/null 2>&1")) ||
            !shell_ok(system("/etc/init.d/snmpd restart >/dev/null 2>&1")))
            ret = -1;
    } else if (!ret && access("/etc/init.d/snmpd", X_OK) == 0) {
        system("/etc/init.d/snmpd disable >/dev/null 2>&1");
        system("/etc/init.d/snmpd stop >/dev/null 2>&1");
    }

    if (ret) {
        restore_access_control();
        airui_apply_rolled_back("Access control apply failed; previous configuration restored");
        airui_reply_error(ctx, req, "apply_rolled_back", NULL,
                          "Access control apply failed; previous configuration restored");
        return 0;
    }

    access_control_read(&data);
    data.changed = true;
    airui_reply_ok_schema(ctx, req, access_control_builder, &data, "system",
                          "airui.security.access_control.v1");
    airui_apply_success("Access control configuration applied");
    return 0;
}
