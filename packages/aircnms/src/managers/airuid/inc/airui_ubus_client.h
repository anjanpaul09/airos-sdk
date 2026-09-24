#ifndef AIRUI_UBUS_CLIENT_H
#define AIRUI_UBUS_CLIENT_H

#include <stdbool.h>
#include <libubus.h>
#include <libubox/blobmsg.h>

#define AIRUI_UBUS_TIMEOUT_MS 5000

struct airui_ubus_result {
    int status;
    char *json;
};

void airui_ubus_result_free(struct airui_ubus_result *result);
int airui_ubus_call_json(struct ubus_context *ctx,
                         const char *object,
                         const char *method,
                         struct blob_buf *request,
                         struct airui_ubus_result *result);
int airui_ubus_object_exists(struct ubus_context *ctx, const char *object);
int airui_network_reload_with_recovery(struct ubus_context *ctx,
                                       struct airui_ubus_result *result,
                                       unsigned int timeout_seconds,
                                       bool *recovered);

#endif /* AIRUI_UBUS_CLIENT_H */
