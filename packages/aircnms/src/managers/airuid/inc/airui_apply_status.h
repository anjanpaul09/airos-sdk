#ifndef AIRUI_APPLY_STATUS_H
#define AIRUI_APPLY_STATUS_H

#include <libubus.h>

void airui_apply_begin(const char *operation);
void airui_apply_success(const char *message);
void airui_apply_failed(const char *message);
void airui_apply_rolled_back(const char *message);

int airui_system_apply_status(struct ubus_context *ctx,
                              struct ubus_object *obj,
                              struct ubus_request_data *req,
                              const char *method,
                              struct blob_attr *msg);

#endif
