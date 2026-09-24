#ifndef AIRUI_NETWORK_H
#define AIRUI_NETWORK_H

#include <libubus.h>

int airui_network_wireless_config(struct ubus_context *ctx,
                                  struct ubus_object *obj,
                                  struct ubus_request_data *req,
                                  const char *method,
                                  struct blob_attr *msg);
int airui_network_wireless_set(struct ubus_context *ctx,
                               struct ubus_object *obj,
                               struct ubus_request_data *req,
                               const char *method,
                               struct blob_attr *msg);
int airui_network_wireless_add(struct ubus_context *ctx,
                               struct ubus_object *obj,
                               struct ubus_request_data *req,
                               const char *method,
                               struct blob_attr *msg);
int airui_network_wireless_delete(struct ubus_context *ctx,
                                  struct ubus_object *obj,
                                  struct ubus_request_data *req,
                                  const char *method,
                                  struct blob_attr *msg);

#endif /* AIRUI_NETWORK_H */
