#ifndef AIRUI_MODE_H
#define AIRUI_MODE_H

#include <libubus.h>
#include <libubox/blobmsg.h>

int airui_mode_controller_status(struct ubus_context *ctx,
                                 struct ubus_object *obj,
                                 struct ubus_request_data *req,
                                 const char *method,
                                 struct blob_attr *msg);
int airui_mode_controller_set(struct ubus_context *ctx,
                              struct ubus_object *obj,
                              struct ubus_request_data *req,
                              const char *method,
                              struct blob_attr *msg);
void airui_mode_add_snapshot(struct blob_buf *b, struct ubus_context *ctx);

#endif /* AIRUI_MODE_H */
