#include "airui_apply_status.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <libubox/blobmsg.h>

#include "airui_response.h"

#define APPLY_SOURCE "airui.system"
#define APPLY_SCHEMA "airui.apply-status.v1"

struct apply_state {
    char state[24];
    char operation[64];
    char message[160];
    uint64_t sequence;
    uint64_t updated_at;
};

static struct apply_state current = {
    .state = "idle",
    .operation = "",
    .message = "No configuration operation is active",
};

static void set_state(const char *state, const char *message)
{
    snprintf(current.state, sizeof(current.state), "%s", state);
    snprintf(current.message, sizeof(current.message), "%s",
             message ? message : "");
    current.sequence++;
    current.updated_at = (uint64_t)time(NULL);
}

void airui_apply_begin(const char *operation)
{
    snprintf(current.operation, sizeof(current.operation), "%s",
             operation ? operation : "configuration");
    set_state("applying", "Applying configuration");
}

void airui_apply_success(const char *message)
{
    set_state("success", message ? message : "Configuration applied");
}

void airui_apply_failed(const char *message)
{
    set_state("failed", message ? message : "Configuration apply failed");
}

void airui_apply_rolled_back(const char *message)
{
    set_state("rolled_back", message ? message : "Configuration rolled back");
}

static void status_builder(struct blob_buf *b, void *user)
{
    struct apply_state *status = user;

    blobmsg_add_string(b, "state", status->state);
    blobmsg_add_string(b, "operation", status->operation);
    blobmsg_add_string(b, "message", status->message);
    blobmsg_add_u64(b, "sequence", status->sequence);
    blobmsg_add_u64(b, "updated_at", status->updated_at);
    blobmsg_add_u8(b, "terminal", strcmp(status->state, "applying") != 0);
}

int airui_system_apply_status(struct ubus_context *ctx,
                              struct ubus_object *obj,
                              struct ubus_request_data *req,
                              const char *method,
                              struct blob_attr *msg)
{
    (void)obj;
    (void)method;
    (void)msg;

    airui_reply_ok_schema(ctx, req, status_builder, &current,
                          APPLY_SOURCE, APPLY_SCHEMA);
    return 0;
}
