#include "airuid.h"

#include <ev.h>
#include <stdio.h>
#include <string.h>
#include <libubus.h>
#include <libubox/blobmsg.h>

#include "airui_interface.h"
#include "airui_apply_status.h"
#include "airui_management.h"
#include "airui_mode.h"
#include "airui_maintenance.h"
#include "airui_network.h"
#include "airui_response.h"
#include "airui_security.h"
#include "airui_status.h"
#include "airui_ubus_client.h"
#include "log.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

static struct ubus_context *g_ctx;
static struct ev_loop *g_loop;
static ev_io g_ubus_watcher;

static void ubus_io_cb(EV_P_ struct ev_io *w, int revents)
{
    (void)loop;
    (void)w;
    (void)revents;

    if (g_ctx) {
        ubus_handle_event(g_ctx);
    }
}

static void health_builder(struct blob_buf *b, void *user)
{
    struct ubus_context *ctx = user;

    blobmsg_add_string(b, "state", "running");
    blobmsg_add_u8(b, "uci_available", airui_ubus_object_exists(ctx, "uci"));
    blobmsg_add_u8(b, "network_wireless_available",
                   airui_ubus_object_exists(ctx, "network.wireless"));
}

static void capabilities_builder(struct blob_buf *b, void *user)
{
    struct ubus_context *ctx = user;
    void *objects;

    objects = blobmsg_open_table(b, "objects");
    blobmsg_add_u8(b, "airui.system", true);
    blobmsg_add_u8(b, "airui.network", true);
    blobmsg_add_u8(b, "airui.status", true);
    blobmsg_add_u8(b, "airui.mode", true);
    blobmsg_add_u8(b, "airui.security", true);
    blobmsg_add_u8(b, "airui.maintenance", true);
    blobmsg_add_u8(b, "openwrt.uci", airui_ubus_object_exists(ctx, "uci"));
    blobmsg_add_u8(b, "openwrt.network.wireless",
                   airui_ubus_object_exists(ctx, "network.wireless"));
    blobmsg_close_table(b, objects);

    blobmsg_add_u32(b, "schema", 1);
}

static int airui_system_health(struct ubus_context *ctx,
                               struct ubus_object *obj,
                               struct ubus_request_data *req,
                               const char *method,
                               struct blob_attr *msg)
{
    (void)obj;
    (void)method;
    (void)msg;

    airui_reply_ok(ctx, req, health_builder, ctx);
    return 0;
}

static int airui_system_capabilities(struct ubus_context *ctx,
                                     struct ubus_object *obj,
                                     struct ubus_request_data *req,
                                     const char *method,
                                     struct blob_attr *msg)
{
    (void)obj;
    (void)method;
    (void)msg;

    airui_reply_ok(ctx, req, capabilities_builder, ctx);
    return 0;
}

static int airui_unsupported_handler(struct ubus_context *ctx,
                                     struct ubus_object *obj,
                                     struct ubus_request_data *req,
                                     const char *method,
                                     struct blob_attr *msg)
{
    (void)obj;
    (void)msg;

    airui_reply_unsupported(ctx, req, method);
    return 0;
}

static const struct ubus_method airui_system_methods[] = {
    UBUS_METHOD_NOARG("health", airui_system_health),
    UBUS_METHOD_NOARG("capabilities", airui_system_capabilities),
    UBUS_METHOD_NOARG("wan_management_config", airui_system_wan_management_config),
    {
        .name = "wan_management_set",
        .handler = airui_system_wan_management_set,
    },
    UBUS_METHOD_NOARG("apply_status", airui_system_apply_status),
};

static const struct ubus_method airui_network_methods[] = {
    UBUS_METHOD_NOARG("interface_config", airui_network_interface_config),
    {
        .name = "interface_add",
        .handler = airui_network_interface_add,
    },
    {
        .name = "interface_set",
        .handler = airui_network_interface_set,
    },
    {
        .name = "interface_delete",
        .handler = airui_network_interface_delete,
    },
    {
        .name = "interface_apply",
        .handler = airui_network_interface_apply,
    },
    {
        .name = "interface_validate",
        .handler = airui_network_interface_validate,
    },
    {
        .name = "interface_map_ssid",
        .handler = airui_network_interface_map_ssid,
    },
    UBUS_METHOD_NOARG("wireless_config", airui_network_wireless_config),
    {
        .name = "wireless_set",
        .handler = airui_network_wireless_set,
    },
    {
        .name = "wireless_add",
        .handler = airui_network_wireless_add,
    },
    {
        .name = "wireless_delete",
        .handler = airui_network_wireless_delete,
    },
    UBUS_METHOD_NOARG("lanwan_config", airui_unsupported_handler),
    {
        .name = "lanwan_set",
        .handler = airui_unsupported_handler,
    },
};

static const struct ubus_method airui_status_methods[] = {
    UBUS_METHOD_NOARG("snapshot", airui_status_summary),
    UBUS_METHOD_NOARG("summary", airui_status_summary),
    UBUS_METHOD_NOARG("overview", airui_status_summary),
    UBUS_METHOD_NOARG("device_status", airui_status_device_status),
    UBUS_METHOD_NOARG("clients", airui_status_clients),
    {
        .name = "client_disconnect",
        .handler = airui_status_client_disconnect,
    },
    UBUS_METHOD_NOARG("statistics", airui_status_statistics),
};

static const struct ubus_method airui_mode_methods[] = {
    UBUS_METHOD_NOARG("controller_status", airui_mode_controller_status),
    {
        .name = "controller_set",
        .handler = airui_mode_controller_set,
    },
};

static const struct ubus_method airui_security_methods[] = {
    UBUS_METHOD_NOARG("access_control_get", airui_security_access_control_get),
    {
        .name = "access_control_set",
        .handler = airui_security_access_control_set,
    },
    UBUS_METHOD_NOARG("rules", airui_security_rules),
    {
        .name = "rule_add",
        .handler = airui_security_rule_add,
    },
    {
        .name = "rule_set",
        .handler = airui_security_rule_set,
    },
    {
        .name = "rule_delete",
        .handler = airui_security_rule_delete,
    },
    UBUS_METHOD_NOARG("mac_filter_config", airui_security_mac_filter_config),
    {
        .name = "mac_filter_set",
        .handler = airui_security_mac_filter_set,
    },
    {
        .name = "mac_filter_entry_add",
        .handler = airui_security_mac_filter_entry_add,
    },
    {
        .name = "mac_filter_entry_delete",
        .handler = airui_security_mac_filter_entry_delete,
    },
};

static const struct ubus_method airui_maintenance_methods[] = {
    UBUS_METHOD_NOARG("config", airui_maintenance_config),
    UBUS_METHOD_NOARG("device_management_get", airui_maintenance_config),
    UBUS_METHOD_NOARG("logs", airui_maintenance_logs),
    UBUS_METHOD_NOARG("syslog_get", airui_maintenance_syslog_get),
    {
        .name = "syslog_set",
        .handler = airui_maintenance_syslog_set,
    },
    {
        .name = "device_management_set",
        .handler = airui_maintenance_device_management_set,
    },
    {
        .name = "reboot",
        .handler = airui_maintenance_reboot,
    },
    {
        .name = "factory_reset",
        .handler = airui_maintenance_factory_reset,
    },
    {
        .name = "firmware_validate",
        .handler = airui_maintenance_firmware_validate,
    },
    {
        .name = "firmware_upgrade",
        .handler = airui_maintenance_firmware_upgrade,
    },
};

static struct ubus_object_type airui_system_type =
    UBUS_OBJECT_TYPE("airui.system", airui_system_methods);
static struct ubus_object_type airui_network_type =
    UBUS_OBJECT_TYPE("airui.network", airui_network_methods);
static struct ubus_object_type airui_status_type =
    UBUS_OBJECT_TYPE("airui.status", airui_status_methods);
static struct ubus_object_type airui_mode_type =
    UBUS_OBJECT_TYPE("airui.mode", airui_mode_methods);
static struct ubus_object_type airui_security_type =
    UBUS_OBJECT_TYPE("airui.security", airui_security_methods);
static struct ubus_object_type airui_maintenance_type =
    UBUS_OBJECT_TYPE("airui.maintenance", airui_maintenance_methods);

static struct ubus_object airui_objects[] = {
    {
        .name = "airui.system",
        .type = &airui_system_type,
        .methods = airui_system_methods,
        .n_methods = ARRAY_SIZE(airui_system_methods),
    },
    {
        .name = "airui.network",
        .type = &airui_network_type,
        .methods = airui_network_methods,
        .n_methods = ARRAY_SIZE(airui_network_methods),
    },
    {
        .name = "airui.status",
        .type = &airui_status_type,
        .methods = airui_status_methods,
        .n_methods = ARRAY_SIZE(airui_status_methods),
    },
    {
        .name = "airui.mode",
        .type = &airui_mode_type,
        .methods = airui_mode_methods,
        .n_methods = ARRAY_SIZE(airui_mode_methods),
    },
    {
        .name = "airui.security",
        .type = &airui_security_type,
        .methods = airui_security_methods,
        .n_methods = ARRAY_SIZE(airui_security_methods),
    },
    {
        .name = "airui.maintenance",
        .type = &airui_maintenance_type,
        .methods = airui_maintenance_methods,
        .n_methods = ARRAY_SIZE(airui_maintenance_methods),
    },
};

bool airui_ubus_service_init(void)
{
    size_t i;

    g_loop = EV_DEFAULT;
    g_ctx = ubus_connect(NULL);
    if (!g_ctx) {
        LOG(ERR, "AIRUID: failed to connect to ubus");
        return false;
    }

    for (i = 0; i < ARRAY_SIZE(airui_objects); i++) {
        if (ubus_add_object(g_ctx, &airui_objects[i])) {
            LOG(ERR, "AIRUID: failed to add ubus object %s",
                airui_objects[i].name);
            airui_ubus_service_cleanup();
            return false;
        }
    }

    if (g_ctx->sock.fd < 0) {
        LOG(ERR, "AIRUID: invalid ubus fd");
        airui_ubus_service_cleanup();
        return false;
    }

    ev_io_init(&g_ubus_watcher, ubus_io_cb, g_ctx->sock.fd, EV_READ);
    ev_io_start(g_loop, &g_ubus_watcher);
    LOG(INFO, "AIRUID: ubus service ready");
    return true;
}

void airui_ubus_service_cleanup(void)
{
    if (g_loop) {
        ev_io_stop(g_loop, &g_ubus_watcher);
    }

    if (g_ctx) {
        ubus_free(g_ctx);
        g_ctx = NULL;
    }
}
