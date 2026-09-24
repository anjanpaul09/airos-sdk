#include "airui_ubus_client.h"

#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <json-c/json.h>
#include <libubox/blobmsg_json.h>

struct airui_call_state {
    struct airui_ubus_result *result;
};

static void airui_ubus_call_cb(struct ubus_request *req,
                               int type,
                               struct blob_attr *msg)
{
    struct airui_call_state *state = req->priv;
    char *json;

    (void)type;

    if (!state || !state->result || !msg) {
        return;
    }

    json = blobmsg_format_json(msg, true);
    if (!json) {
        state->result->status = UBUS_STATUS_UNKNOWN_ERROR;
        return;
    }

    free(state->result->json);
    state->result->json = json;
    state->result->status = 0;
}

void airui_ubus_result_free(struct airui_ubus_result *result)
{
    if (!result) {
        return;
    }

    free(result->json);
    result->json = NULL;
    result->status = 0;
}

int airui_ubus_call_json(struct ubus_context *ctx,
                         const char *object,
                         const char *method,
                         struct blob_buf *request,
                         struct airui_ubus_result *result)
{
    struct airui_call_state state;
    struct ubus_context *call_ctx;
    uint32_t id;
    int ret;

    if (!ctx || !object || !method || !result) {
        return UBUS_STATUS_INVALID_ARGUMENT;
    }

    memset(result, 0, sizeof(*result));
    state.result = result;

    /*
     * Handlers call this helper while the daemon's primary context is already
     * dispatching a request. A synchronous invoke on that same context can
     * block its dispatcher until the nested call times out. Keep internal RPC
     * traffic on a short-lived context so apply and recovery remain responsive.
     */
    call_ctx = ubus_connect(NULL);
    if (!call_ctx) {
        result->status = UBUS_STATUS_CONNECTION_FAILED;
        return result->status;
    }

    ret = ubus_lookup_id(call_ctx, object, &id);
    if (ret) {
        result->status = ret;
        ubus_free(call_ctx);
        return ret;
    }

    ret = ubus_invoke(call_ctx,
                      id,
                      method,
                      request ? request->head : NULL,
                      airui_ubus_call_cb,
                      &state,
                      AIRUI_UBUS_TIMEOUT_MS);
    if (ret) {
        result->status = ret;
        ubus_free(call_ctx);
        return ret;
    }

    ubus_free(call_ctx);
    return result->status;
}

int airui_ubus_object_exists(struct ubus_context *ctx, const char *object)
{
    uint32_t id;

    if (!ctx || !object) {
        return 0;
    }

    return ubus_lookup_id(ctx, object, &id) == 0;
}

static bool command_succeeded(int status)
{
    return status != -1 && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static bool network_is_healthy(struct ubus_context *ctx)
{
    struct airui_ubus_result dump = {};
    struct json_object *root = NULL;
    struct json_object *interfaces = NULL;
    bool healthy = false;
    size_t i;

    if (airui_ubus_call_json(ctx, "network.interface", "dump", NULL, &dump) ||
        !dump.json)
        goto out;

    root = json_tokener_parse(dump.json);
    if (!root || !json_object_object_get_ex(root, "interface", &interfaces) ||
        !json_object_is_type(interfaces, json_type_array))
        goto out;

    for (i = 0; i < json_object_array_length(interfaces); i++) {
        struct json_object *entry = json_object_array_get_idx(interfaces, i);
        struct json_object *name = NULL;
        struct json_object *up = NULL;

        if (entry &&
            json_object_object_get_ex(entry, "interface", &name) &&
            json_object_object_get_ex(entry, "up", &up) &&
            strcmp(json_object_get_string(name), "loopback") != 0 &&
            json_object_get_boolean(up)) {
            healthy = true;
            break;
        }
    }

out:
    if (root)
        json_object_put(root);
    airui_ubus_result_free(&dump);
    return healthy;
}

static bool wait_for_network(struct ubus_context *ctx, unsigned int timeout)
{
    unsigned int elapsed;

    for (elapsed = 0; elapsed <= timeout; elapsed++) {
        if (network_is_healthy(ctx))
            return true;
        if (elapsed < timeout)
            sleep(1);
    }
    return false;
}

int airui_network_reload_with_recovery(struct ubus_context *ctx,
                                       struct airui_ubus_result *result,
                                       unsigned int timeout_seconds,
                                       bool *recovered)
{
    int ret;

    if (!ctx || !result || timeout_seconds == 0)
        return UBUS_STATUS_INVALID_ARGUMENT;
    if (recovered)
        *recovered = false;

    ret = airui_ubus_call_json(ctx, "network", "reload", NULL, result);

    /*
     * netifd may finish applying the configuration but delay the reload reply
     * while a DHCP client is still probing. Runtime health is authoritative;
     * avoid a disruptive restart when the network is already operational.
     */
    if (wait_for_network(ctx, timeout_seconds)) {
        free(result->json);
        result->json = strdup(ret == 0 ?
            "{\"healthy\":true,\"recovered\":false,\"timed_out\":false}" :
            "{\"healthy\":true,\"recovered\":false,\"timed_out\":true}");
        result->status = 0;
        return 0;
    }

    if (!command_succeeded(system("/etc/init.d/network restart >/dev/null 2>&1")) ||
        !wait_for_network(ctx, timeout_seconds)) {
        free(result->json);
        result->json = strdup("{\"healthy\":false,\"recovered\":false,\"timed_out\":true}");
        result->status = UBUS_STATUS_TIMEOUT;
        return UBUS_STATUS_TIMEOUT;
    }

    if (recovered)
        *recovered = true;
    free(result->json);
    result->json = strdup("{\"healthy\":true,\"recovered\":true,\"timed_out\":false}");
    result->status = 0;
    return 0;
}
