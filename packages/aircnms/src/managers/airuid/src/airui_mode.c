#include "airui_mode.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <json-c/json.h>
#include <uci.h>

#include "airui_response.h"
#include "airui_ubus_client.h"

#define MODE_SCHEMA "airui.mode.v1"

enum {
    MODE_SET_MODE,
    MODE_SET_CLOUD_URL,
    MODE_SET_BROKER_HOST,
    MODE_SET_BROKER_PORT,
    MODE_SET_INTERVAL,
    MODE_SET_DRY_RUN,
    __MODE_SET_MAX
};

static const struct blobmsg_policy mode_set_policy[__MODE_SET_MAX] = {
    [MODE_SET_MODE] = { .name = "mode", .type = BLOBMSG_TYPE_STRING },
    [MODE_SET_CLOUD_URL] = { .name = "cloud_url", .type = BLOBMSG_TYPE_STRING },
    [MODE_SET_BROKER_HOST] = { .name = "broker_host", .type = BLOBMSG_TYPE_STRING },
    [MODE_SET_BROKER_PORT] = { .name = "broker_port", .type = BLOBMSG_TYPE_INT32 },
    [MODE_SET_INTERVAL] = { .name = "interval", .type = BLOBMSG_TYPE_INT32 },
    [MODE_SET_DRY_RUN] = { .name = "dry_run", .type = BLOBMSG_TYPE_BOOL },
};

struct mode_state {
    bool config_available;
    bool service_running;
    bool online;
    bool registered;
    bool applied;
    bool dry_run;
    char mode[16];
    char state[32];
    char cloud_url[128];
    char broker_host[128];
    char broker_port[16];
    char interval[16];
    char device_id[64];
    char serial_num[64];
    char org_id[128];
    char network_id[128];
};

struct saved_option {
    const char *name;
    char *value;
};

static const char *option_value(struct uci_context *uci,
                                struct uci_section *section,
                                const char *name)
{
    const char *value = uci_lookup_option_string(uci, section, name);
    return value ? value : "";
}

static struct uci_section *aircnms_section(struct uci_package *package)
{
    struct uci_element *element;

    if (!package)
        return NULL;

    uci_foreach_element(&package->sections, element) {
        struct uci_section *section = uci_to_section(element);
        if (section->type && strcmp(section->type, "aircnms") == 0)
            return section;
    }
    return NULL;
}

static void copy_option(char *dest, size_t size, const char *value)
{
    if (size)
        snprintf(dest, size, "%s", value ? value : "");
}

static bool command_ok(const char *command)
{
    int status = system(command);
    return status != -1 && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static void read_cgwd_state(struct mode_state *state, struct ubus_context *ctx)
{
    struct airui_ubus_result result = {};
    struct json_object *root = NULL;
    struct json_object *value = NULL;

    state->service_running = airui_ubus_object_exists(ctx, "cgwd");
    if (!state->service_running) {
        copy_option(state->state, sizeof(state->state),
                    strcmp(state->mode, "cloud") == 0 ? "service_stopped" : "standalone");
        return;
    }

    if (airui_ubus_call_json(ctx, "cgwd", "get.cgwd.state", NULL, &result) ||
        !result.json)
        goto out;

    root = json_tokener_parse(result.json);
    if (root && json_object_object_get_ex(root, "state", &value))
        copy_option(state->state, sizeof(state->state), json_object_get_string(value));

out:
    if (root)
        json_object_put(root);
    airui_ubus_result_free(&result);
    if (!state->state[0])
        copy_option(state->state, sizeof(state->state), "unknown");
    state->registered = strcmp(state->state, "registered") == 0;
}

static bool load_mode_state(struct mode_state *state, struct ubus_context *ctx)
{
    struct uci_context *uci = NULL;
    struct uci_package *package = NULL;
    struct uci_section *section;
    const char *configured_mode;

    memset(state, 0, sizeof(*state));
    copy_option(state->mode, sizeof(state->mode), "standalone");
    copy_option(state->state, sizeof(state->state), "standalone");

    uci = uci_alloc_context();
    if (!uci || uci_load(uci, "aircnms", &package) != UCI_OK)
        goto out;

    section = aircnms_section(package);
    if (!section)
        goto out;

    state->config_available = true;
    configured_mode = option_value(uci, section, "mode");
    if (strcmp(configured_mode, "cloud") == 0)
        copy_option(state->mode, sizeof(state->mode), "cloud");
    copy_option(state->cloud_url, sizeof(state->cloud_url), option_value(uci, section, "cloud_url"));
    copy_option(state->broker_host, sizeof(state->broker_host), option_value(uci, section, "ipaddr"));
    copy_option(state->broker_port, sizeof(state->broker_port), option_value(uci, section, "port"));
    copy_option(state->interval, sizeof(state->interval), option_value(uci, section, "interval"));
    copy_option(state->device_id, sizeof(state->device_id), option_value(uci, section, "device_id"));
    copy_option(state->serial_num, sizeof(state->serial_num), option_value(uci, section, "serial_num"));
    copy_option(state->org_id, sizeof(state->org_id), option_value(uci, section, "org_id"));
    copy_option(state->network_id, sizeof(state->network_id), option_value(uci, section, "network_id"));
    state->online = strcmp(option_value(uci, section, "online"), "1") == 0;

out:
    if (package)
        uci_unload(uci, package);
    if (uci)
        uci_free_context(uci);
    read_cgwd_state(state, ctx);
    return state->config_available;
}

static void mode_state_builder(struct blob_buf *b, void *user)
{
    struct mode_state *state = user;

    blobmsg_add_string(b, "mode", state->mode);
    blobmsg_add_string(b, "controller_type", "cloud");
    blobmsg_add_string(b, "state", state->state);
    blobmsg_add_u8(b, "config_available", state->config_available);
    blobmsg_add_u8(b, "service_running", state->service_running);
    blobmsg_add_u8(b, "registered", state->registered);
    blobmsg_add_u8(b, "online", state->online);
    blobmsg_add_string(b, "cloud_url", state->cloud_url);
    blobmsg_add_string(b, "broker_host", state->broker_host);
    blobmsg_add_string(b, "broker_port", state->broker_port);
    blobmsg_add_string(b, "interval", state->interval);
    blobmsg_add_string(b, "device_id", state->device_id);
    blobmsg_add_string(b, "serial_num", state->serial_num);
    blobmsg_add_string(b, "org_id", state->org_id);
    blobmsg_add_string(b, "network_id", state->network_id);
    if (state->applied)
        blobmsg_add_u8(b, "applied", true);
    if (state->dry_run)
        blobmsg_add_u8(b, "dry_run", true);
}

void airui_mode_add_snapshot(struct blob_buf *b, struct ubus_context *ctx)
{
    struct mode_state state;
    void *mode;

    load_mode_state(&state, ctx);
    mode = blobmsg_open_table(b, "mode");
    blobmsg_add_string(b, "current",
                       strcmp(state.mode, "cloud") == 0 ? "Cloud Controller" : "Standalone");
    blobmsg_add_string(b, "management",
                       strcmp(state.mode, "cloud") == 0 ? "Cloud management" : "Local management");
    blobmsg_add_string(b, "controller_state", state.state);
    blobmsg_add_u8(b, "online", state.online);
    blobmsg_close_table(b, mode);
}

int airui_mode_controller_status(struct ubus_context *ctx,
                                 struct ubus_object *obj,
                                 struct ubus_request_data *req,
                                 const char *method,
                                 struct blob_attr *msg)
{
    struct mode_state state;

    (void)obj;
    (void)method;
    (void)msg;

    load_mode_state(&state, ctx);
    airui_reply_ok_schema(ctx, req, mode_state_builder, &state,
                          "aircnms/cgwd", MODE_SCHEMA);
    return 0;
}

static bool valid_https_url(const char *value)
{
    const unsigned char *p;

    if (!value || strncmp(value, "https://", 8) != 0 ||
        value[8] == '\0' || strlen(value) >= 128)
        return false;
    for (p = (const unsigned char *)value; *p; p++) {
        if (isspace(*p) || iscntrl(*p))
            return false;
    }
    return true;
}

static bool valid_host(const char *value)
{
    const unsigned char *p;

    if (!value || !value[0] || strlen(value) >= 128)
        return false;
    for (p = (const unsigned char *)value; *p; p++) {
        if (!isalnum(*p) && *p != '.' && *p != '-' && *p != ':')
            return false;
    }
    return true;
}

static int set_uci_option(struct uci_context *uci, struct uci_package *package,
                          struct uci_section *section, const char *name,
                          const char *value)
{
    struct uci_ptr ptr = {};

    ptr.p = package;
    ptr.s = section;
    ptr.option = name;
    ptr.value = value;
    return uci_set(uci, &ptr);
}

static int restore_option(struct uci_context *uci, struct uci_package *package,
                          struct uci_section *section, struct saved_option *saved)
{
    struct uci_ptr ptr = {};

    if (saved->value)
        return set_uci_option(uci, package, section, saved->name, saved->value);

    ptr.p = package;
    ptr.s = section;
    ptr.option = saved->name;
    return uci_delete(uci, &ptr);
}

static bool apply_service_mode(const char *mode)
{
    bool ok;
    if (strcmp(mode, "cloud") == 0) {
        ok = command_ok("/etc/init.d/aircgwd enable >/dev/null 2>&1") &&
             command_ok("/etc/init.d/aircgwd restart >/dev/null 2>&1") &&
             command_ok("/etc/init.d/aironbd enable >/dev/null 2>&1") &&
             command_ok("/etc/init.d/aironbd restart >/dev/null 2>&1");
    } else {
        ok = command_ok("/etc/init.d/aircgwd stop >/dev/null 2>&1") &&
             command_ok("/etc/init.d/aircgwd disable >/dev/null 2>&1") &&
             command_ok("/etc/init.d/aironbd stop >/dev/null 2>&1") &&
             command_ok("/etc/init.d/aironbd disable >/dev/null 2>&1");
    }
    command_ok("/sbin/reload_config >/dev/null 2>&1");
    return ok;
}

int airui_mode_controller_set(struct ubus_context *ctx,
                              struct ubus_object *obj,
                              struct ubus_request_data *req,
                              const char *method,
                              struct blob_attr *msg)
{
    struct blob_attr *tb[__MODE_SET_MAX] = {};
    struct uci_context *uci = NULL;
    struct uci_package *package = NULL;
    struct uci_section *section;
    struct mode_state current;
    struct mode_state response;
    struct saved_option saved[] = {
        { "mode", NULL }, { "cloud_url", NULL }, { "ipaddr", NULL },
        { "port", NULL }, { "interval", NULL }, { "online", NULL },
    };
    const char *mode;
    const char *cloud_url;
    const char *broker_host;
    uint32_t broker_port;
    uint32_t interval;
    char port_text[16];
    char interval_text[16];
    bool dry_run;
    bool previous_cloud;
    size_t i;
    int ret = UCI_OK;

    (void)obj;
    (void)method;

    if (!msg) {
        airui_reply_error_schema(ctx, req, "VALIDATION_FAILED", "mode",
                                 "Mode is required", "aircnms", MODE_SCHEMA);
        return 0;
    }
    blobmsg_parse(mode_set_policy, __MODE_SET_MAX, tb,
                  blob_data(msg), blob_len(msg));
    if (!tb[MODE_SET_MODE]) {
        airui_reply_error_schema(ctx, req, "VALIDATION_FAILED", "mode",
                                 "Mode is required", "aircnms", MODE_SCHEMA);
        return 0;
    }

    mode = blobmsg_get_string(tb[MODE_SET_MODE]);
    if (strcmp(mode, "standalone") != 0 && strcmp(mode, "cloud") != 0) {
        airui_reply_error_schema(ctx, req, "VALIDATION_FAILED", "mode",
                                 "Mode must be standalone or cloud", "aircnms", MODE_SCHEMA);
        return 0;
    }

    load_mode_state(&current, ctx);
    cloud_url = tb[MODE_SET_CLOUD_URL] ? blobmsg_get_string(tb[MODE_SET_CLOUD_URL]) : current.cloud_url;
    broker_host = tb[MODE_SET_BROKER_HOST] ? blobmsg_get_string(tb[MODE_SET_BROKER_HOST]) : current.broker_host;
    broker_port = tb[MODE_SET_BROKER_PORT] ? blobmsg_get_u32(tb[MODE_SET_BROKER_PORT]) : (uint32_t)strtoul(current.broker_port, NULL, 10);
    interval = tb[MODE_SET_INTERVAL] ? blobmsg_get_u32(tb[MODE_SET_INTERVAL]) : (uint32_t)strtoul(current.interval, NULL, 10);
    dry_run = tb[MODE_SET_DRY_RUN] && blobmsg_get_bool(tb[MODE_SET_DRY_RUN]);

    if (strcmp(mode, "cloud") == 0) {
        if (!valid_https_url(cloud_url)) {
            airui_reply_error_schema(ctx, req, "VALIDATION_FAILED", "cloud_url",
                                     "Cloud URL must be a valid HTTPS URL", "aircnms", MODE_SCHEMA);
            return 0;
        }
        if (!valid_host(broker_host)) {
            airui_reply_error_schema(ctx, req, "VALIDATION_FAILED", "broker_host",
                                     "Broker host is invalid", "aircnms", MODE_SCHEMA);
            return 0;
        }
        if (broker_port == 0 || broker_port > 65535) {
            airui_reply_error_schema(ctx, req, "VALIDATION_FAILED", "broker_port",
                                     "Broker port must be between 1 and 65535", "aircnms", MODE_SCHEMA);
            return 0;
        }
        if (interval < 5 || interval > 3600) {
            airui_reply_error_schema(ctx, req, "VALIDATION_FAILED", "interval",
                                     "Reporting interval must be between 5 and 3600 seconds", "aircnms", MODE_SCHEMA);
            return 0;
        }
    }

    response = current;
    copy_option(response.mode, sizeof(response.mode), mode);
    copy_option(response.cloud_url, sizeof(response.cloud_url), cloud_url);
    copy_option(response.broker_host, sizeof(response.broker_host), broker_host);
    snprintf(port_text, sizeof(port_text), "%u", broker_port);
    snprintf(interval_text, sizeof(interval_text), "%u", interval);
    copy_option(response.broker_port, sizeof(response.broker_port), port_text);
    copy_option(response.interval, sizeof(response.interval), interval_text);
    response.dry_run = dry_run;
    if (dry_run) {
        airui_reply_ok_schema(ctx, req, mode_state_builder, &response,
                              "aircnms", MODE_SCHEMA);
        return 0;
    }

    uci = uci_alloc_context();
    if (!uci || uci_load(uci, "aircnms", &package) != UCI_OK ||
        !(section = aircnms_section(package))) {
        airui_reply_error_schema(ctx, req, "CONFIG_UNAVAILABLE", "aircnms",
                                 "The aircnms configuration is unavailable", "aircnms", MODE_SCHEMA);
        goto out;
    }

    for (i = 0; i < sizeof(saved) / sizeof(saved[0]); i++) {
        const char *value = uci_lookup_option_string(uci, section, saved[i].name);
        saved[i].value = value ? strdup(value) : NULL;
    }
    previous_cloud = saved[0].value && strcmp(saved[0].value, "cloud") == 0;

    ret |= set_uci_option(uci, package, section, "mode", mode);
    ret |= set_uci_option(uci, package, section, "online", "0");
    if (strcmp(mode, "cloud") == 0) {
        ret |= set_uci_option(uci, package, section, "cloud_url", cloud_url);
        ret |= set_uci_option(uci, package, section, "ipaddr", broker_host);
        ret |= set_uci_option(uci, package, section, "port", port_text);
        ret |= set_uci_option(uci, package, section, "interval", interval_text);
    }
    if (ret != UCI_OK || uci_commit(uci, &package, false) != UCI_OK) {
        airui_reply_error_schema(ctx, req, "COMMIT_FAILED", "aircnms",
                                 "Unable to save controller configuration", "aircnms", MODE_SCHEMA);
        goto out;
    }

    if (!apply_service_mode(mode)) {
        section = aircnms_section(package);
        for (i = 0; section && i < sizeof(saved) / sizeof(saved[0]); i++)
            restore_option(uci, package, section, &saved[i]);
        if (section)
            uci_commit(uci, &package, false);
        apply_service_mode(previous_cloud ? "cloud" : "standalone");
        airui_reply_error_schema(ctx, req, "SERVICE_FAILED", "aircgwd",
                                 "Cloud service failed to apply; previous mode was restored",
                                 "aircnms/cgwd", MODE_SCHEMA);
        goto out;
    }

    load_mode_state(&response, ctx);
    response.applied = true;
    airui_reply_ok_schema(ctx, req, mode_state_builder, &response,
                          "aircnms/cgwd", MODE_SCHEMA);

out:
    for (i = 0; i < sizeof(saved) / sizeof(saved[0]); i++)
        free(saved[i].value);
    if (package)
        uci_unload(uci, package);
    if (uci)
        uci_free_context(uci);
    return 0;
}
