#include "onbd.h"

#include <libubus.h>

#include <ev.h>
#include <libubox/blobmsg.h>
#include <string.h>
#include "log.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

static struct ubus_context *g_ctx;
static struct ev_loop *g_loop;
static ev_io g_watcher;
static struct ubus_event_handler g_mqtt_events;
static struct ubus_event_handler g_registration_events;
static struct ubus_event_handler g_netconf_events;
static struct ubus_event_handler g_network_events;

static const char *attr_string(struct blob_attr *msg, const char *name)
{
    struct blob_attr *cur;
    int remaining;
    blobmsg_for_each_attr(cur, msg, remaining)
        if (!strcmp(blobmsg_name(cur), name) && blobmsg_type(cur) == BLOBMSG_TYPE_STRING)
            return blobmsg_get_string(cur);
    return NULL;
}

static bool attr_bool(struct blob_attr *msg, const char *name, bool fallback)
{
    struct blob_attr *cur;
    int remaining;
    blobmsg_for_each_attr(cur, msg, remaining)
        if (!strcmp(blobmsg_name(cur), name) && blobmsg_type(cur) == BLOBMSG_TYPE_BOOL)
            return blobmsg_get_bool(cur);
    return fallback;
}

static uint64_t attr_u64(struct blob_attr *msg, const char *name, uint64_t fallback)
{
    struct blob_attr *cur;
    int remaining;
    blobmsg_for_each_attr(cur, msg, remaining)
        if (!strcmp(blobmsg_name(cur), name)) {
            if (blobmsg_type(cur) == BLOBMSG_TYPE_INT64) return blobmsg_get_u64(cur);
            if (blobmsg_type(cur) == BLOBMSG_TYPE_INT32) return blobmsg_get_u32(cur);
        }
    return fallback;
}

static void network_event_cb(struct ubus_context *ctx, struct ubus_event_handler *ev,
                             const char *type, struct blob_attr *msg)
{
    (void)ev; (void)type; (void)msg;
    onbd_observe(ctx, &g_onbd_state);
}

static void mqtt_event_cb(struct ubus_context *ctx, struct ubus_event_handler *ev,
                          const char *type, struct blob_attr *msg)
{
    const char *reason;
    bool connected;
    (void)ctx; (void)ev; (void)type;
    if (!msg) return;
    connected = attr_bool(msg, "connected", false);
    g_onbd_state.connectivity = connected ?
        ONBD_CONN_ONLINE : ONBD_CONN_MQTT_DISCONNECTED;
    reason = attr_string(msg, "reason_code");
    onbd_set_reason(&g_onbd_state, reason ? reason : "MQTT_EVENT");
    LOG(INFO, "UBUS_EVENT_MQTT: connected=%d reason='%s'", connected, reason ? reason : "none");
}

static void registration_event_cb(struct ubus_context *ctx, struct ubus_event_handler *ev,
                                  const char *type, struct blob_attr *msg)
{
    const char *result, *attempt;
    (void)ctx; (void)ev; (void)type;
    if (!msg) return;
    result = attr_string(msg, "result");
    attempt = attr_string(msg, "attempt_id");
    if (attempt) snprintf(g_onbd_state.attempt_id, sizeof(g_onbd_state.attempt_id), "%s", attempt);
    if (!result || !strcmp(result, "NONE")) return;
    if (!strcmp(result, "SUCCESS") || !strcmp(result, "ENROLLED"))
        g_onbd_state.lifecycle = ONBD_LIFECYCLE_ENROLLED;
    else
        g_onbd_state.lifecycle = ONBD_LIFECYCLE_ENROLLING;
    onbd_set_reason(&g_onbd_state, result);
    LOG(INFO, "UBUS_EVENT_REGISTRATION: result='%s' attempt_id='%s'",
        result ? result : "none", attempt ? attempt : "none");
}

static void netconf_event_cb(struct ubus_context *ctx, struct ubus_event_handler *ev,
                             const char *type, struct blob_attr *msg)
{
    const char *status, *job, *reason;
    (void)ctx; (void)ev; (void)type;
    if (!msg) return;
    status = attr_string(msg, "status");
    job = attr_string(msg, "job_id");
    reason = attr_string(msg, "reason_code");
    if (job) snprintf(g_onbd_state.config_job_id, sizeof(g_onbd_state.config_job_id), "%s", job);
    g_onbd_state.desired_revision = attr_u64(msg, "cloud_revision",
                                             attr_u64(msg, "revision", g_onbd_state.desired_revision));
    if (!status) return;
    if (!strcmp(status, "QUEUED")) g_onbd_state.configuration = ONBD_CONFIG_QUEUED;
    else if (!strcmp(status, "APPLYING")) g_onbd_state.configuration = ONBD_CONFIG_APPLYING;
    else if (!strcmp(status, "APPLIED")) {
        g_onbd_state.configuration = ONBD_CONFIG_APPLIED;
        g_onbd_state.applied_revision = g_onbd_state.desired_revision;
    } else if (!strcmp(status, "FAILED")) g_onbd_state.configuration = ONBD_CONFIG_FAILED;
    else if (!strcmp(status, "SUPERSEDED")) g_onbd_state.configuration = ONBD_CONFIG_SUPERSEDED;
    onbd_set_reason(&g_onbd_state, reason ? reason : status);
    LOG(INFO, "UBUS_EVENT_NETCONF: status='%s' job_id='%s' rev=%llu reason='%s'",
        status, job ? job : "none", (unsigned long long)g_onbd_state.desired_revision, reason ? reason : "none");
}

static void add_common(struct blob_buf *b, const onbd_state_t *s)
{
    blobmsg_add_string(b, "schema", ONBD_SCHEMA);
    blobmsg_add_string(b, "lifecycle", onbd_lifecycle_name(s->lifecycle));
    blobmsg_add_string(b, "connectivity", onbd_connectivity_name(s->connectivity));
    blobmsg_add_string(b, "configuration", onbd_config_name(s->configuration));
    blobmsg_add_string(b, "visible_state", onbd_visible_state(s));
    blobmsg_add_string(b, "reason_code", s->reason_code);
    blobmsg_add_u8(b, "enabled", s->enabled);
    blobmsg_add_u8(b, "shadow_mode", s->shadow_mode);
    blobmsg_add_u8(b, "recovery_apply_enabled", s->recovery_apply_enabled);
    blobmsg_add_u8(b, "operational_once", s->operational_once);
    blobmsg_add_u8(b, "recovery_ssid_enabled", s->recovery_ssid_enabled);
    blobmsg_add_u8(b, "fallback_active", s->fallback_active);
    blobmsg_add_u8(b, "wifi_suppressed", s->wifi_suppressed);
    blobmsg_add_u32(b, "cloud_down_ticks", s->cloud_down_ticks);
    blobmsg_add_string(b, "attempt_id", s->attempt_id);
    blobmsg_add_string(b, "config_job_id", s->config_job_id);
    blobmsg_add_u64(b, "desired_revision", s->desired_revision);
    blobmsg_add_u64(b, "applied_revision", s->applied_revision);
    blobmsg_add_u64(b, "updated_at_monotonic_ms", s->updated_monotonic_ms);
}

static int status_handler(struct ubus_context *ctx, struct ubus_object *obj,
                          struct ubus_request_data *req, const char *method,
                          struct blob_attr *msg)
{
    struct blob_buf b = {0};
    (void)obj; (void)method; (void)msg;
    blob_buf_init(&b, 0);
    add_common(&b, &g_onbd_state);
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
    return UBUS_STATUS_OK;
}

static int diagnostics_handler(struct ubus_context *ctx, struct ubus_object *obj,
                               struct ubus_request_data *req, const char *method,
                               struct blob_attr *msg)
{
    struct blob_buf b = {0};
    void *deps;
    (void)obj; (void)method; (void)msg;
    blob_buf_init(&b, 0);
    add_common(&b, &g_onbd_state);
    deps = blobmsg_open_table(&b, "dependencies");
    blobmsg_add_u8(&b, "ubus", g_onbd_state.ubus_available);
    blobmsg_add_u8(&b, "network.interface", g_onbd_state.network_available);
    blobmsg_add_u8(&b, "cgwd", g_onbd_state.cgwd_available);
    blobmsg_add_u8(&b, "netconfd", g_onbd_state.netconfd_available);
    blobmsg_close_table(&b, deps);
    blobmsg_add_u8(&b, "stored_identity_valid", g_onbd_state.stored_identity_valid);
    blobmsg_add_u8(&b, "legacy_online", g_onbd_state.legacy_online);
    blobmsg_add_u8(&b, "carrier", g_onbd_state.carrier_available);
    blobmsg_add_u8(&b, "management_ip", g_onbd_state.management_ip_available);
    blobmsg_add_u8(&b, "default_route", g_onbd_state.default_route_available);
    blobmsg_add_u8(&b, "dns_configured", g_onbd_state.dns_available);
    blobmsg_add_u8(&b, "dns_resolved", g_onbd_state.dns_resolved);
    blobmsg_add_u8(&b, "gateway_reachable", g_onbd_state.gateway_reachable);
    blobmsg_add_u8(&b, "internet_reachable", g_onbd_state.internet_available);
    blobmsg_add_u8(&b, "cloud_reachable", g_onbd_state.cloud_available);
    blobmsg_add_u8(&b, "fallback_active", g_onbd_state.fallback_active);
    blobmsg_add_u32(&b, "dhcp_wait_ticks", g_onbd_state.dhcp_wait_ticks);
    blobmsg_add_u32(&b, "dhcp_retry_count", g_onbd_state.dhcp_retry_count);
    blobmsg_add_string(&b, "default_gateway", g_onbd_state.default_gateway);
    blobmsg_add_string(&b, "cloud_host", g_onbd_state.cloud_host);
    blobmsg_add_string(&b, "probe_scope", "measured-network-v3-gateway-dns-https");
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
    return UBUS_STATUS_OK;
}

static const struct ubus_method methods[] = {
    UBUS_METHOD_NOARG("status", status_handler),
    UBUS_METHOD_NOARG("diagnostics", diagnostics_handler),
};
static struct ubus_object_type object_type = UBUS_OBJECT_TYPE("air.onboarding", methods);
static struct ubus_object object = {
    .name = "air.onboarding", .type = &object_type,
    .methods = methods, .n_methods = ARRAY_SIZE(methods),
};

static void ubus_io_cb(EV_P_ ev_io *watcher, int revents)
{
    (void)loop; (void)watcher; (void)revents;
    if (g_ctx) ubus_handle_event(g_ctx);
}

bool onbd_ubus_init(struct ev_loop *loop)
{
    g_loop = loop;
    g_ctx = ubus_connect(NULL);
    if (!g_ctx || ubus_add_object(g_ctx, &object) != 0 || g_ctx->sock.fd < 0) {
        onbd_ubus_cleanup();
        return false;
    }
    memset(&g_mqtt_events, 0, sizeof(g_mqtt_events));
    memset(&g_registration_events, 0, sizeof(g_registration_events));
    memset(&g_netconf_events, 0, sizeof(g_netconf_events));
    memset(&g_network_events, 0, sizeof(g_network_events));
    g_mqtt_events.cb = mqtt_event_cb;
    g_registration_events.cb = registration_event_cb;
    g_netconf_events.cb = netconf_event_cb;
    g_network_events.cb = network_event_cb;
    if (ubus_register_event_handler(g_ctx, &g_mqtt_events, "air.cgwd.mqtt") != 0 ||
        ubus_register_event_handler(g_ctx, &g_registration_events, "air.cgwd.registration") != 0 ||
        ubus_register_event_handler(g_ctx, &g_netconf_events, "air.netconfd.job") != 0 ||
        ubus_register_event_handler(g_ctx, &g_network_events, "network.interface") != 0) {
        onbd_ubus_cleanup();
        return false;
    }
    ev_io_init(&g_watcher, ubus_io_cb, g_ctx->sock.fd, EV_READ);
    ev_io_start(g_loop, &g_watcher);
    return true;
}

void onbd_ubus_cleanup(void)
{
    if (g_loop && g_ctx) ev_io_stop(g_loop, &g_watcher);
    if (g_ctx) ubus_free(g_ctx);
    g_ctx = NULL;
}

struct ubus_context *onbd_ubus_context(void) { return g_ctx; }
