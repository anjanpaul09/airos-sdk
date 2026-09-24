#ifndef AIRUI_STATUS_H
#define AIRUI_STATUS_H

#include <libubus.h>

int airui_status_summary(struct ubus_context *ctx,
                         struct ubus_object *obj,
                         struct ubus_request_data *req,
                         const char *method,
                         struct blob_attr *msg);
int airui_status_device_status(struct ubus_context *ctx,
                               struct ubus_object *obj,
                               struct ubus_request_data *req,
                               const char *method,
                               struct blob_attr *msg);
int airui_status_clients(struct ubus_context *ctx,
                         struct ubus_object *obj,
                         struct ubus_request_data *req,
                         const char *method,
                         struct blob_attr *msg);
int airui_status_client_disconnect(struct ubus_context *ctx,
                                   struct ubus_object *obj,
                                   struct ubus_request_data *req,
                                   const char *method,
                                   struct blob_attr *msg);
int airui_status_statistics(struct ubus_context *ctx,
                            struct ubus_object *obj,
                            struct ubus_request_data *req,
                            const char *method,
                            struct blob_attr *msg);

#endif /* AIRUI_STATUS_H */
