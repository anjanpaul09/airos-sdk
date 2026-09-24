#include "airui_maintenance.h"

#include <stdbool.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>

#include "airui_response.h"
#include "airui_ubus_client.h"

#define AIRUI_MAINT_SOURCE "airui.maintenance"
#define AIRUI_MAINT_SCHEMA "airui.maintenance.v1"
#define AIRUI_LOG_LIMIT 120
#define AIRUI_FIRMWARE_PATH "/tmp/airui-firmware.bin"

enum {
    MAINT_DRY_RUN,
    MAINT_CONFIRM,
    MAINT_HOSTNAME,
    MAINT_ZONENAME,
    MAINT_TIMEZONE,
    MAINT_PATH,
    MAINT_KEEP_SETTINGS,
    MAINT_FORCE,
    MAINT_SYSLOG_ENABLED,
    MAINT_SYSLOG_SERVER,
    MAINT_SYSLOG_PORT,
    MAINT_SYSLOG_PROTOCOL,
    __MAINT_MAX
};

static const struct blobmsg_policy maint_policy[__MAINT_MAX] = {
    [MAINT_DRY_RUN] = { .name = "dry_run", .type = BLOBMSG_TYPE_BOOL },
    [MAINT_CONFIRM] = { .name = "confirm", .type = BLOBMSG_TYPE_STRING },
    [MAINT_HOSTNAME] = { .name = "hostname", .type = BLOBMSG_TYPE_STRING },
    [MAINT_ZONENAME] = { .name = "zonename", .type = BLOBMSG_TYPE_STRING },
    [MAINT_TIMEZONE] = { .name = "timezone", .type = BLOBMSG_TYPE_STRING },
    [MAINT_PATH] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
    [MAINT_KEEP_SETTINGS] = { .name = "keep_settings", .type = BLOBMSG_TYPE_BOOL },
    [MAINT_FORCE] = { .name = "force", .type = BLOBMSG_TYPE_BOOL },
    [MAINT_SYSLOG_ENABLED] = { .name = "enabled", .type = BLOBMSG_TYPE_BOOL },
    [MAINT_SYSLOG_SERVER] = { .name = "server", .type = BLOBMSG_TYPE_STRING },
    [MAINT_SYSLOG_PORT] = { .name = "port", .type = BLOBMSG_TYPE_INT32 },
    [MAINT_SYSLOG_PROTOCOL] = { .name = "protocol", .type = BLOBMSG_TYPE_STRING },
};

struct release_info {
    char distribution[64];
    char version[96];
    char revision[96];
    char target[96];
    char description[160];
};

struct maintenance_config {
    const char *board_json;
    const char *info_json;
    const char *system_json;
    struct release_info release;
};

struct maintenance_action {
    const char *operation;
    bool dry_run;
    bool accepted;
};

struct maintenance_logs {
    char lines[AIRUI_LOG_LIMIT][256];
    int count;
};

struct syslog_config {
    bool enabled;
    bool dry_run;
    char server[254];
    uint32_t port;
    char protocol[4];
};

struct firmware_result {
    const char *operation;
    const char *path;
    const char *validation_json;
    bool dry_run;
    bool force;
    bool keep_settings;
};

static bool valid_hostname(const char *value)
{
    size_t i;
    size_t len;

    if (!value) {
        return false;
    }

    len = strlen(value);
    if (len < 1 || len > 63) {
        return false;
    }

    for (i = 0; i < len; i++) {
        char c = value[i];

        if (!((c >= 'a' && c <= 'z') ||
              (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') ||
              c == '-')) {
            return false;
        }
    }

    return value[0] != '-' && value[len - 1] != '-';
}

static bool valid_syslog_server(const char *value)
{
    size_t i;
    size_t len;

    if (!value) {
        return false;
    }

    len = strlen(value);
    if (len < 1 || len > 253) {
        return false;
    }

    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)value[i];

        if (!(isalnum(c) || c == '.' || c == '-' || c == ':' ||
              c == '[' || c == ']')) {
            return false;
        }
    }

    return true;
}

static void reply_maint_error(struct ubus_context *ctx,
                              struct ubus_request_data *req,
                              const char *code,
                              const char *field,
                              const char *message)
{
    airui_reply_error_schema(ctx, req, code, field, message,
                             AIRUI_MAINT_SOURCE, AIRUI_MAINT_SCHEMA);
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

static uint64_t json_uint64(struct json_object *obj,
                            const char *name,
                            uint64_t fallback)
{
    struct json_object *value = NULL;

    if (obj &&
        json_object_object_get_ex(obj, name, &value) &&
        (json_object_is_type(value, json_type_int) ||
         json_object_is_type(value, json_type_double))) {
        return (uint64_t)json_object_get_int64(value);
    }

    return fallback;
}

static const char *find_system_section(struct json_object *root,
                                       char *section,
                                       size_t section_len)
{
    struct json_object *values = NULL;
    struct json_object_iter it;

    if (!section || section_len == 0) {
        return NULL;
    }

    section[0] = '\0';

    if (!root ||
        !json_object_object_get_ex(root, "values", &values) ||
        !json_object_is_type(values, json_type_object)) {
        return NULL;
    }

    json_object_object_foreachC(values, it) {
        struct json_object *entry = it.val;
        const char *type = json_string(entry, ".type", NULL);

        if (type && strcmp(type, "system") == 0) {
            snprintf(section, section_len, "%s", it.key);
            return section;
        }
    }

    return NULL;
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

static bool valid_firmware_path(const char *path)
{
    return path && strcmp(path, AIRUI_FIRMWARE_PATH) == 0;
}

static bool firmware_validation_bool(const char *json,
                                     const char *name,
                                     bool fallback)
{
    struct json_object *root = NULL;
    struct json_object *value = NULL;
    bool result = fallback;

    if (!json) {
        return fallback;
    }

    root = json_tokener_parse(json);
    if (root &&
        json_object_object_get_ex(root, name, &value) &&
        json_object_is_type(value, json_type_boolean)) {
        result = json_object_get_boolean(value);
    }

    if (root) {
        json_object_put(root);
    }

    return result;
}

static void trim_line(char *line)
{
    size_t len;

    if (!line) {
        return;
    }

    len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
        line[len - 1] = '\0';
        len--;
    }
}

static void release_set_value(struct release_info *release,
                              const char *key,
                              const char *value)
{
    char *target = NULL;
    size_t target_len = 0;

    if (strcmp(key, "DISTRIB_ID") == 0) {
        target = release->distribution;
        target_len = sizeof(release->distribution);
    } else if (strcmp(key, "DISTRIB_RELEASE") == 0) {
        target = release->version;
        target_len = sizeof(release->version);
    } else if (strcmp(key, "DISTRIB_REVISION") == 0) {
        target = release->revision;
        target_len = sizeof(release->revision);
    } else if (strcmp(key, "DISTRIB_TARGET") == 0) {
        target = release->target;
        target_len = sizeof(release->target);
    } else if (strcmp(key, "DISTRIB_DESCRIPTION") == 0) {
        target = release->description;
        target_len = sizeof(release->description);
    }

    if (target && target_len > 0) {
        snprintf(target, target_len, "%s", value);
    }
}

static void parse_release(struct release_info *release)
{
    FILE *fp;
    char line[256];

    memset(release, 0, sizeof(*release));
    snprintf(release->distribution, sizeof(release->distribution), "%s", "OpenWrt");
    snprintf(release->version, sizeof(release->version), "%s", "-");
    snprintf(release->revision, sizeof(release->revision), "%s", "-");
    snprintf(release->target, sizeof(release->target), "%s", "-");
    snprintf(release->description, sizeof(release->description), "%s", "OpenWrt");

    fp = fopen("/etc/openwrt_release", "r");
    if (!fp) {
        return;
    }

    while (fgets(line, sizeof(line), fp)) {
        char *eq;
        char *value;
        char *end;

        trim_line(line);
        eq = strchr(line, '=');
        if (!eq) {
            continue;
        }

        *eq = '\0';
        value = eq + 1;
        if (*value == '\'' || *value == '"') {
            value++;
            end = value + strlen(value);
            if (end > value && (end[-1] == '\'' || end[-1] == '"')) {
                end[-1] = '\0';
            }
        }

        release_set_value(release, line, value);
    }

    fclose(fp);
}

static void maintenance_config_builder(struct blob_buf *b, void *user)
{
    struct maintenance_config *config = user;
    struct json_object *board = NULL;
    struct json_object *info = NULL;
    struct json_object *system_root = NULL;
    struct json_object *system_values = NULL;
    struct json_object *system_section = NULL;
    char section_name[64];
    const char *hostname = "-";
    const char *model = "-";
    const char *board_name = "-";
    const char *system = "-";
    const char *kernel = "-";
    const char *zonename = "UTC";
    const char *timezone = "UTC0";
    uint64_t uptime = 0;
    uint64_t localtime = 0;
    void *device;
    void *firmware;
    void *actions;

    if (config && config->board_json) {
        board = json_tokener_parse(config->board_json);
    }
    if (config && config->info_json) {
        info = json_tokener_parse(config->info_json);
    }
    if (config && config->system_json) {
        system_root = json_tokener_parse(config->system_json);
    }

    hostname = json_string(board, "hostname", hostname);
    model = json_string(board, "model", model);
    board_name = json_string(board, "board_name", board_name);
    system = json_string(board, "system", system);
    kernel = json_string(board, "kernel", kernel);
    uptime = json_uint64(info, "uptime", uptime);
    localtime = json_uint64(info, "localtime", localtime);

    if (system_root &&
        find_system_section(system_root, section_name, sizeof(section_name)) &&
        json_object_object_get_ex(system_root, "values", &system_values) &&
        json_object_object_get_ex(system_values, section_name, &system_section)) {
        zonename = json_string(system_section, "zonename", json_string(system_section, "timezone", zonename));
        timezone = json_string(system_section, "timezone", timezone);
    }

    device = blobmsg_open_table(b, "device");
    blobmsg_add_string(b, "hostname", hostname);
    blobmsg_add_string(b, "model", model);
    blobmsg_add_string(b, "board_name", board_name);
    blobmsg_add_string(b, "system", system);
    blobmsg_add_string(b, "kernel", kernel);
    blobmsg_add_u64(b, "uptime", uptime);
    blobmsg_add_u64(b, "localtime", localtime);
    blobmsg_add_string(b, "zonename", zonename);
    blobmsg_add_string(b, "timezone", timezone);
    blobmsg_close_table(b, device);

    firmware = blobmsg_open_table(b, "firmware");
    blobmsg_add_string(b, "distribution", config ? config->release.distribution : "OpenWrt");
    blobmsg_add_string(b, "version", config ? config->release.version : "-");
    blobmsg_add_string(b, "revision", config ? config->release.revision : "-");
    blobmsg_add_string(b, "target", config ? config->release.target : "-");
    blobmsg_add_string(b, "description", config ? config->release.description : "OpenWrt");
    blobmsg_close_table(b, firmware);

    actions = blobmsg_open_table(b, "actions");
    blobmsg_add_u8(b, "reboot", true);
    blobmsg_add_u8(b, "factory_reset", true);
    blobmsg_add_u8(b, "backup", true);
    blobmsg_add_u8(b, "restore", false);
    blobmsg_add_u8(b, "firmware_upgrade", true);
    blobmsg_add_u8(b, "logs", true);
    blobmsg_add_string(b, "firmware_path", AIRUI_FIRMWARE_PATH);
    blobmsg_close_table(b, actions);

    if (board) {
        json_object_put(board);
    }
    if (info) {
        json_object_put(info);
    }
    if (system_root) {
        json_object_put(system_root);
    }
}

static void maintenance_action_builder(struct blob_buf *b, void *user)
{
    struct maintenance_action *action = user;

    blobmsg_add_string(b, "operation", action ? action->operation : "maintenance");
    blobmsg_add_u8(b, "dry_run", action ? action->dry_run : true);
    blobmsg_add_u8(b, "accepted", action ? action->accepted : false);
}

static void maintenance_logs_builder(struct blob_buf *b, void *user)
{
    struct maintenance_logs *logs = user;
    void *entries;
    int i;

    blobmsg_add_u32(b, "count", logs ? logs->count : 0);
    entries = blobmsg_open_array(b, "entries");
    if (logs) {
        for (i = 0; i < logs->count; i++) {
            blobmsg_add_string(b, NULL, logs->lines[i]);
        }
    }
    blobmsg_close_array(b, entries);
}

static void syslog_config_builder(struct blob_buf *b, void *user)
{
    struct syslog_config *config = user;

    blobmsg_add_u8(b, "enabled", config ? config->enabled : false);
    blobmsg_add_string(b, "server", config ? config->server : "");
    blobmsg_add_u32(b, "port", config ? config->port : 514);
    blobmsg_add_string(b, "protocol", config ? config->protocol : "udp");
    blobmsg_add_u8(b, "dry_run", config ? config->dry_run : false);
}

static int load_syslog_config(struct ubus_context *ctx,
                              struct syslog_config *config,
                              char *section_name,
                              size_t section_len)
{
    struct blob_buf request = {};
    struct airui_ubus_result result = {};
    struct json_object *root = NULL;
    struct json_object *values = NULL;
    struct json_object *section = NULL;
    const char *enabled;
    const char *server;
    const char *port;
    const char *protocol;
    int ret;

    memset(config, 0, sizeof(*config));
    config->port = 514;
    snprintf(config->protocol, sizeof(config->protocol), "%s", "udp");

    blob_buf_init(&request, 0);
    blobmsg_add_string(&request, "config", "system");
    ret = airui_ubus_call_json(ctx, "uci", "get", &request, &result);
    blob_buf_free(&request);
    if (ret) {
        return ret;
    }

    root = json_tokener_parse(result.json);
    if (!root ||
        !find_system_section(root, section_name, section_len) ||
        !json_object_object_get_ex(root, "values", &values) ||
        !json_object_object_get_ex(values, section_name, &section)) {
        if (root) {
            json_object_put(root);
        }
        airui_ubus_result_free(&result);
        return UBUS_STATUS_NOT_FOUND;
    }

    server = json_string(section, "log_ip", "");
    port = json_string(section, "log_port", "514");
    protocol = json_string(section, "log_proto", "udp");
    enabled = json_string(section, "log_remote", server[0] ? "1" : "0");

    snprintf(config->server, sizeof(config->server), "%s", server);
    config->port = (uint32_t)strtoul(port, NULL, 10);
    if (config->port < 1 || config->port > 65535) {
        config->port = 514;
    }
    snprintf(config->protocol, sizeof(config->protocol), "%s",
             strcmp(protocol, "tcp") == 0 ? "tcp" : "udp");
    config->enabled = strcmp(enabled, "0") != 0 && config->server[0] != '\0';

    json_object_put(root);
    airui_ubus_result_free(&result);
    return 0;
}

static void firmware_result_builder(struct blob_buf *b, void *user)
{
    struct firmware_result *result = user;

    blobmsg_add_string(b, "operation", result ? result->operation : "firmware");
    blobmsg_add_string(b, "path", result ? result->path : AIRUI_FIRMWARE_PATH);
    blobmsg_add_u8(b, "dry_run", result ? result->dry_run : true);
    blobmsg_add_u8(b, "force", result ? result->force : false);
    blobmsg_add_u8(b, "keep_settings", result ? result->keep_settings : true);
    add_json_object(b, "validation", result ? result->validation_json : NULL);
}

int airui_maintenance_config(struct ubus_context *ctx,
                             struct ubus_object *obj,
                             struct ubus_request_data *req,
                             const char *method,
                             struct blob_attr *msg)
{
    struct airui_ubus_result board = {};
    struct airui_ubus_result info = {};
    struct airui_ubus_result system_config = {};
    struct blob_buf uci = {};
    struct maintenance_config config;
    int ret;

    (void)obj;
    (void)method;
    (void)msg;

    memset(&config, 0, sizeof(config));
    parse_release(&config.release);

    ret = airui_ubus_call_json(ctx, "system", "board", NULL, &board);
    if (ret) {
        reply_maint_error(ctx, req, "backend_unavailable", "system.board",
                          ubus_strerror(ret));
        return 0;
    }

    ret = airui_ubus_call_json(ctx, "system", "info", NULL, &info);
    if (ret) {
        airui_ubus_result_free(&board);
        reply_maint_error(ctx, req, "backend_unavailable", "system.info",
                          ubus_strerror(ret));
        return 0;
    }

    blob_buf_init(&uci, 0);
    blobmsg_add_string(&uci, "config", "system");
    ret = airui_ubus_call_json(ctx, "uci", "get", &uci, &system_config);
    blob_buf_free(&uci);
    if (ret) {
        airui_ubus_result_free(&board);
        airui_ubus_result_free(&info);
        reply_maint_error(ctx, req, "backend_unavailable", "uci.system",
                          ubus_strerror(ret));
        return 0;
    }

    config.board_json = board.json;
    config.info_json = info.json;
    config.system_json = system_config.json;
    airui_reply_ok_schema(ctx, req, maintenance_config_builder, &config,
                          AIRUI_MAINT_SOURCE, AIRUI_MAINT_SCHEMA);

    airui_ubus_result_free(&board);
    airui_ubus_result_free(&info);
    airui_ubus_result_free(&system_config);
    return 0;
}

int airui_maintenance_device_management_set(struct ubus_context *ctx,
                                            struct ubus_object *obj,
                                            struct ubus_request_data *req,
                                            const char *method,
                                            struct blob_attr *msg)
{
    struct blob_attr *tb[__MAINT_MAX];
    struct blob_buf request = {};
    struct blob_buf values = {};
    struct airui_ubus_result get = {};
    struct airui_ubus_result result = {};
    struct maintenance_action action = {
        .operation = "device_management_set",
        .dry_run = false,
        .accepted = true,
    };
    const char *hostname = NULL;
    const char *zonename = NULL;
    const char *timezone = NULL;
    struct json_object *system_root = NULL;
    char section_name[64];
    int ret;

    (void)obj;
    (void)method;

    blobmsg_parse(maint_policy, __MAINT_MAX, tb,
                  msg ? blob_data(msg) : NULL,
                  msg ? blob_len(msg) : 0);

    action.dry_run = tb[MAINT_DRY_RUN] && blobmsg_get_bool(tb[MAINT_DRY_RUN]);
    if (tb[MAINT_HOSTNAME]) {
        hostname = blobmsg_get_string(tb[MAINT_HOSTNAME]);
    }
    if (tb[MAINT_ZONENAME]) {
        zonename = blobmsg_get_string(tb[MAINT_ZONENAME]);
    }
    if (tb[MAINT_TIMEZONE]) {
        timezone = blobmsg_get_string(tb[MAINT_TIMEZONE]);
    }

    if (!valid_hostname(hostname)) {
        reply_maint_error(ctx, req, "invalid_argument", "hostname",
                          "Hostname must be 1-63 letters, numbers or dashes.");
        return 0;
    }

    if (!zonename || !zonename[0] || !timezone || !timezone[0]) {
        reply_maint_error(ctx, req, "invalid_argument", "timezone",
                          "Timezone and zone name are required.");
        return 0;
    }

    if (!action.dry_run) {
        blob_buf_init(&request, 0);
        blobmsg_add_string(&request, "config", "system");
        ret = airui_ubus_call_json(ctx, "uci", "get", &request, &get);
        blob_buf_free(&request);
        if (ret) {
            reply_maint_error(ctx, req, "backend_unavailable", "uci.system",
                              ubus_strerror(ret));
            return 0;
        }

        system_root = json_tokener_parse(get.json);
        if (!find_system_section(system_root, section_name, sizeof(section_name))) {
            if (system_root) {
                json_object_put(system_root);
            }
            airui_ubus_result_free(&get);
            reply_maint_error(ctx, req, "backend_unavailable", "uci.system",
                              "System section was not found.");
            return 0;
        }

        blob_buf_init(&values, 0);
        blobmsg_add_string(&values, "hostname", hostname);
        blobmsg_add_string(&values, "zonename", zonename);
        blobmsg_add_string(&values, "timezone", timezone);

        blob_buf_init(&request, 0);
        blobmsg_add_string(&request, "config", "system");
        blobmsg_add_string(&request, "section", section_name);
        blobmsg_add_field(&request, BLOBMSG_TYPE_TABLE, "values",
                          blobmsg_data(values.head),
                          blobmsg_data_len(values.head));
        ret = airui_ubus_call_json(ctx, "uci", "set", &request, &result);
        blob_buf_free(&request);
        blob_buf_free(&values);
        if (system_root) {
            json_object_put(system_root);
        }
        airui_ubus_result_free(&get);
        airui_ubus_result_free(&result);
        if (ret) {
            reply_maint_error(ctx, req, "backend_unavailable", "uci.system",
                              ubus_strerror(ret));
            return 0;
        }

        blob_buf_init(&request, 0);
        blobmsg_add_string(&request, "config", "system");
        ret = airui_ubus_call_json(ctx, "uci", "commit", &request, &result);
        blob_buf_free(&request);
        airui_ubus_result_free(&result);
        if (ret) {
            reply_maint_error(ctx, req, "backend_unavailable", "uci.system",
                              ubus_strerror(ret));
            return 0;
        }

        ret = airui_ubus_call_json(ctx, "system", "reload", NULL, &result);
        airui_ubus_result_free(&result);
        if (ret) {
            int cmd_ret = system("/etc/init.d/system reload >/dev/null 2>&1");
            (void)cmd_ret;
        }
    }

    airui_reply_ok_schema(ctx, req, maintenance_action_builder, &action,
                          AIRUI_MAINT_SOURCE, AIRUI_MAINT_SCHEMA);
    return 0;
}

int airui_maintenance_logs(struct ubus_context *ctx,
                           struct ubus_object *obj,
                           struct ubus_request_data *req,
                           const char *method,
                           struct blob_attr *msg)
{
    struct maintenance_logs logs = {};
    FILE *fp;
    int status;

    (void)obj;
    (void)method;
    (void)msg;

    fp = popen("logread -l 120 2>/dev/null", "r");
    if (!fp) {
        reply_maint_error(ctx, req, "backend_unavailable", "logread",
                          "Unable to open the system log stream.");
        return 0;
    }

    while (logs.count < AIRUI_LOG_LIMIT &&
           fgets(logs.lines[logs.count], sizeof(logs.lines[logs.count]), fp)) {
        trim_line(logs.lines[logs.count]);
        if (logs.lines[logs.count][0]) {
            logs.count++;
        }
    }

    status = pclose(fp);
    if (status != 0) {
        reply_maint_error(ctx, req, "backend_unavailable", "logread",
                          "The system log command failed.");
        return 0;
    }

    airui_reply_ok_schema(ctx, req, maintenance_logs_builder, &logs,
                          AIRUI_MAINT_SOURCE, AIRUI_MAINT_SCHEMA);
    return 0;
}

int airui_maintenance_syslog_get(struct ubus_context *ctx,
                                 struct ubus_object *obj,
                                 struct ubus_request_data *req,
                                 const char *method,
                                 struct blob_attr *msg)
{
    struct syslog_config config;
    char section_name[64];
    int ret;

    (void)obj;
    (void)method;
    (void)msg;

    ret = load_syslog_config(ctx, &config, section_name, sizeof(section_name));
    if (ret) {
        reply_maint_error(ctx, req, "backend_unavailable", "uci.system",
                          ubus_strerror(ret));
        return 0;
    }

    airui_reply_ok_schema(ctx, req, syslog_config_builder, &config,
                          AIRUI_MAINT_SOURCE, AIRUI_MAINT_SCHEMA);
    return 0;
}

int airui_maintenance_syslog_set(struct ubus_context *ctx,
                                 struct ubus_object *obj,
                                 struct ubus_request_data *req,
                                 const char *method,
                                 struct blob_attr *msg)
{
    struct blob_attr *tb[__MAINT_MAX];
    struct blob_buf request = {};
    struct blob_buf values = {};
    struct airui_ubus_result result = {};
    struct syslog_config config;
    struct syslog_config current;
    char section_name[64];
    char port[8];
    char backup[96];
    char command[256];
    const char *server = "";
    const char *protocol = "udp";
    uint32_t log_port = 514;
    bool enabled = false;
    bool dry_run = false;
    bool backup_ready = false;
    int ret;

    (void)obj;
    (void)method;

    blobmsg_parse(maint_policy, __MAINT_MAX, tb,
                  msg ? blob_data(msg) : NULL,
                  msg ? blob_len(msg) : 0);

    enabled = tb[MAINT_SYSLOG_ENABLED] &&
              blobmsg_get_bool(tb[MAINT_SYSLOG_ENABLED]);
    dry_run = tb[MAINT_DRY_RUN] && blobmsg_get_bool(tb[MAINT_DRY_RUN]);
    if (tb[MAINT_SYSLOG_SERVER]) {
        server = blobmsg_get_string(tb[MAINT_SYSLOG_SERVER]);
    }
    if (tb[MAINT_SYSLOG_PORT]) {
        log_port = blobmsg_get_u32(tb[MAINT_SYSLOG_PORT]);
    }
    if (tb[MAINT_SYSLOG_PROTOCOL]) {
        protocol = blobmsg_get_string(tb[MAINT_SYSLOG_PROTOCOL]);
    }

    if (enabled && !valid_syslog_server(server)) {
        reply_maint_error(ctx, req, "invalid_argument", "server",
                          "Enter a valid IPv4, IPv6 or host name.");
        return 0;
    }
    if (log_port < 1 || log_port > 65535) {
        reply_maint_error(ctx, req, "invalid_argument", "port",
                          "Port must be between 1 and 65535.");
        return 0;
    }
    if (strcmp(protocol, "udp") != 0 && strcmp(protocol, "tcp") != 0) {
        reply_maint_error(ctx, req, "invalid_argument", "protocol",
                          "Protocol must be UDP or TCP.");
        return 0;
    }

    memset(&config, 0, sizeof(config));
    config.enabled = enabled;
    config.dry_run = dry_run;
    config.port = log_port;
    snprintf(config.server, sizeof(config.server), "%s", server);
    snprintf(config.protocol, sizeof(config.protocol), "%s", protocol);

    ret = load_syslog_config(ctx, &current,
                             section_name, sizeof(section_name));
    if (ret) {
        reply_maint_error(ctx, req, "backend_unavailable", "uci.system",
                          ubus_strerror(ret));
        return 0;
    }

    if (!dry_run) {
        snprintf(backup, sizeof(backup), "/tmp/airui-system-syslog.%ld",
                 (long)getpid());
        snprintf(command, sizeof(command), "cp /etc/config/system %s", backup);
        if (system(command) != 0) {
            reply_maint_error(ctx, req, "backend_unavailable", "uci.system",
                              "Unable to create a rollback copy.");
            return 0;
        }
        backup_ready = true;

        snprintf(port, sizeof(port), "%u", log_port);
        blob_buf_init(&values, 0);
        blobmsg_add_string(&values, "log_remote", enabled ? "1" : "0");
        blobmsg_add_string(&values, "log_ip", server);
        blobmsg_add_string(&values, "log_port", port);
        blobmsg_add_string(&values, "log_proto", protocol);

        blob_buf_init(&request, 0);
        blobmsg_add_string(&request, "config", "system");
        blobmsg_add_string(&request, "section", section_name);
        blobmsg_add_field(&request, BLOBMSG_TYPE_TABLE, "values",
                          blobmsg_data(values.head),
                          blobmsg_data_len(values.head));
        ret = airui_ubus_call_json(ctx, "uci", "set", &request, &result);
        blob_buf_free(&request);
        blob_buf_free(&values);
        airui_ubus_result_free(&result);

        if (!ret) {
            blob_buf_init(&request, 0);
            blobmsg_add_string(&request, "config", "system");
            ret = airui_ubus_call_json(ctx, "uci", "commit", &request, &result);
            blob_buf_free(&request);
            airui_ubus_result_free(&result);
        }

        if (!ret && system("/etc/init.d/log restart >/dev/null 2>&1") != 0) {
            ret = UBUS_STATUS_UNKNOWN_ERROR;
        }

        if (ret && backup_ready) {
            snprintf(command, sizeof(command), "cp %s /etc/config/system", backup);
            system(command);
            system("/etc/init.d/log restart >/dev/null 2>&1");
        }

        if (backup_ready) {
            unlink(backup);
        }

        if (ret) {
            reply_maint_error(ctx, req, "apply_failed", "syslog",
                              "Remote syslog was not applied; the previous configuration was restored.");
            return 0;
        }
    }

    airui_reply_ok_schema(ctx, req, syslog_config_builder, &config,
                          AIRUI_MAINT_SOURCE, AIRUI_MAINT_SCHEMA);
    return 0;
}

int airui_maintenance_reboot(struct ubus_context *ctx,
                             struct ubus_object *obj,
                             struct ubus_request_data *req,
                             const char *method,
                             struct blob_attr *msg)
{
    struct blob_attr *tb[__MAINT_MAX];
    struct maintenance_action action = {
        .operation = "reboot",
        .dry_run = false,
        .accepted = true,
    };

    (void)obj;
    (void)method;

    blobmsg_parse(maint_policy, __MAINT_MAX, tb,
                  msg ? blob_data(msg) : NULL,
                  msg ? blob_len(msg) : 0);

    action.dry_run = tb[MAINT_DRY_RUN] && blobmsg_get_bool(tb[MAINT_DRY_RUN]);

    if (!action.dry_run) {
        int cmd_ret = system("(sleep 1; /sbin/reboot) >/dev/null 2>&1 &");
        (void)cmd_ret;
    }

    airui_reply_ok_schema(ctx, req, maintenance_action_builder, &action,
                          AIRUI_MAINT_SOURCE, AIRUI_MAINT_SCHEMA);
    return 0;
}

int airui_maintenance_factory_reset(struct ubus_context *ctx,
                                    struct ubus_object *obj,
                                    struct ubus_request_data *req,
                                    const char *method,
                                    struct blob_attr *msg)
{
    struct blob_attr *tb[__MAINT_MAX];
    struct maintenance_action action = {
        .operation = "factory_reset",
        .dry_run = false,
        .accepted = true,
    };
    const char *confirm = NULL;

    (void)obj;
    (void)method;

    blobmsg_parse(maint_policy, __MAINT_MAX, tb,
                  msg ? blob_data(msg) : NULL,
                  msg ? blob_len(msg) : 0);

    action.dry_run = tb[MAINT_DRY_RUN] && blobmsg_get_bool(tb[MAINT_DRY_RUN]);
    if (tb[MAINT_CONFIRM]) {
        confirm = blobmsg_get_string(tb[MAINT_CONFIRM]);
    }

    if (!confirm || strcmp(confirm, "RESET") != 0) {
        reply_maint_error(ctx, req, "confirmation_required", "confirm",
                          "Type RESET to confirm factory default.");
        return 0;
    }

    if (!action.dry_run) {
        int cmd_ret = system("(sleep 1; /sbin/firstboot -y; /sbin/reboot) >/dev/null 2>&1 &");
        (void)cmd_ret;
    }

    airui_reply_ok_schema(ctx, req, maintenance_action_builder, &action,
                          AIRUI_MAINT_SOURCE, AIRUI_MAINT_SCHEMA);
    return 0;
}

int airui_maintenance_firmware_validate(struct ubus_context *ctx,
                                        struct ubus_object *obj,
                                        struct ubus_request_data *req,
                                        const char *method,
                                        struct blob_attr *msg)
{
    struct blob_attr *tb[__MAINT_MAX];
    struct blob_buf request = {};
    struct airui_ubus_result validation = {};
    struct firmware_result result = {
        .operation = "firmware_validate",
        .path = AIRUI_FIRMWARE_PATH,
        .dry_run = true,
        .force = false,
        .keep_settings = true,
    };
    const char *path = AIRUI_FIRMWARE_PATH;
    int ret;

    (void)obj;
    (void)method;

    blobmsg_parse(maint_policy, __MAINT_MAX, tb,
                  msg ? blob_data(msg) : NULL,
                  msg ? blob_len(msg) : 0);

    if (tb[MAINT_PATH]) {
        path = blobmsg_get_string(tb[MAINT_PATH]);
    }

    if (!valid_firmware_path(path)) {
        reply_maint_error(ctx, req, "invalid_argument", "path",
                          "Firmware image must be uploaded to /tmp/airui-firmware.bin.");
        return 0;
    }

    blob_buf_init(&request, 0);
    blobmsg_add_string(&request, "path", path);
    ret = airui_ubus_call_json(ctx, "system", "validate_firmware_image", &request, &validation);
    blob_buf_free(&request);
    if (ret) {
        reply_maint_error(ctx, req, "backend_unavailable", "system.validate_firmware_image",
                          ubus_strerror(ret));
        return 0;
    }

    result.path = path;
    result.validation_json = validation.json;
    airui_reply_ok_schema(ctx, req, firmware_result_builder, &result,
                          AIRUI_MAINT_SOURCE, AIRUI_MAINT_SCHEMA);
    airui_ubus_result_free(&validation);
    return 0;
}

int airui_maintenance_firmware_upgrade(struct ubus_context *ctx,
                                       struct ubus_object *obj,
                                       struct ubus_request_data *req,
                                       const char *method,
                                       struct blob_attr *msg)
{
    struct blob_attr *tb[__MAINT_MAX];
    struct blob_buf request = {};
    struct airui_ubus_result validation = {};
    struct firmware_result result = {
        .operation = "firmware_upgrade",
        .path = AIRUI_FIRMWARE_PATH,
        .dry_run = false,
        .force = false,
        .keep_settings = true,
    };
    const char *path = AIRUI_FIRMWARE_PATH;
    const char *confirm = NULL;
    bool keep_settings = true;
    bool force = false;
    bool dry_run = false;
    int ret;

    (void)obj;
    (void)method;

    blobmsg_parse(maint_policy, __MAINT_MAX, tb,
                  msg ? blob_data(msg) : NULL,
                  msg ? blob_len(msg) : 0);

    if (tb[MAINT_PATH]) {
        path = blobmsg_get_string(tb[MAINT_PATH]);
    }
    if (tb[MAINT_CONFIRM]) {
        confirm = blobmsg_get_string(tb[MAINT_CONFIRM]);
    }
    if (tb[MAINT_KEEP_SETTINGS]) {
        keep_settings = blobmsg_get_bool(tb[MAINT_KEEP_SETTINGS]);
    }
    if (tb[MAINT_FORCE]) {
        force = blobmsg_get_bool(tb[MAINT_FORCE]);
    }
    dry_run = tb[MAINT_DRY_RUN] && blobmsg_get_bool(tb[MAINT_DRY_RUN]);

    if (!valid_firmware_path(path)) {
        reply_maint_error(ctx, req, "invalid_argument", "path",
                          "Firmware image must be uploaded to /tmp/airui-firmware.bin.");
        return 0;
    }

    if (!confirm || strcmp(confirm, "UPGRADE") != 0) {
        reply_maint_error(ctx, req, "confirmation_required", "confirm",
                          "Type UPGRADE to confirm firmware upgrade.");
        return 0;
    }

    blob_buf_init(&request, 0);
    blobmsg_add_string(&request, "path", path);
    ret = airui_ubus_call_json(ctx, "system", "validate_firmware_image", &request, &validation);
    blob_buf_free(&request);
    if (ret) {
        reply_maint_error(ctx, req, "backend_unavailable", "system.validate_firmware_image",
                          ubus_strerror(ret));
        return 0;
    }

    result.path = path;
    result.validation_json = validation.json;
    result.dry_run = dry_run;
    result.force = force;
    result.keep_settings = keep_settings;

    if (!firmware_validation_bool(validation.json, "valid", false) && !force) {
        airui_ubus_result_free(&validation);
        reply_maint_error(ctx, req, "validation_failed", "firmware",
                          "Firmware image did not pass validation.");
        return 0;
    }

    if (!firmware_validation_bool(validation.json, "valid", false) &&
        force &&
        !firmware_validation_bool(validation.json, "forceable", false)) {
        airui_ubus_result_free(&validation);
        reply_maint_error(ctx, req, "validation_failed", "firmware",
                          "Firmware image cannot be forced.");
        return 0;
    }

    if (!dry_run) {
        char command[192];
        int cmd_ret;

        snprintf(command, sizeof(command),
                 "(sleep 1; /sbin/sysupgrade %s %s %s) >/dev/null 2>&1 &",
                 force ? "-F" : "",
                 keep_settings ? "" : "-n",
                 AIRUI_FIRMWARE_PATH);
        cmd_ret = system(command);
        (void)cmd_ret;
    }

    airui_reply_ok_schema(ctx, req, firmware_result_builder, &result,
                          AIRUI_MAINT_SOURCE, AIRUI_MAINT_SCHEMA);
    airui_ubus_result_free(&validation);
    return 0;
}
