#ifndef AIRUI_MANAGEMENT_H
#define AIRUI_MANAGEMENT_H

#include <libubus.h>

int airui_system_wan_management_config(struct ubus_context *ctx,
                                       struct ubus_object *obj,
                                       struct ubus_request_data *req,
                                       const char *method,
                                       struct blob_attr *msg);

int airui_system_wan_management_set(struct ubus_context *ctx,
                                    struct ubus_object *obj,
                                    struct ubus_request_data *req,
                                    const char *method,
                                    struct blob_attr *msg);

#endif /* AIRUI_MANAGEMENT_H */
