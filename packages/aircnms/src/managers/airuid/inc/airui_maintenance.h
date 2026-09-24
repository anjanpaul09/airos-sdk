#ifndef AIRUI_MAINTENANCE_H
#define AIRUI_MAINTENANCE_H

#include <libubus.h>

int airui_maintenance_config(struct ubus_context *ctx,
                             struct ubus_object *obj,
                             struct ubus_request_data *req,
                             const char *method,
                             struct blob_attr *msg);

int airui_maintenance_logs(struct ubus_context *ctx,
                           struct ubus_object *obj,
                           struct ubus_request_data *req,
                           const char *method,
                           struct blob_attr *msg);

int airui_maintenance_syslog_get(struct ubus_context *ctx,
                                 struct ubus_object *obj,
                                 struct ubus_request_data *req,
                                 const char *method,
                                 struct blob_attr *msg);

int airui_maintenance_syslog_set(struct ubus_context *ctx,
                                 struct ubus_object *obj,
                                 struct ubus_request_data *req,
                                 const char *method,
                                 struct blob_attr *msg);

int airui_maintenance_device_management_set(struct ubus_context *ctx,
                                            struct ubus_object *obj,
                                            struct ubus_request_data *req,
                                            const char *method,
                                            struct blob_attr *msg);

int airui_maintenance_reboot(struct ubus_context *ctx,
                             struct ubus_object *obj,
                             struct ubus_request_data *req,
                             const char *method,
                             struct blob_attr *msg);

int airui_maintenance_factory_reset(struct ubus_context *ctx,
                                    struct ubus_object *obj,
                                    struct ubus_request_data *req,
                                    const char *method,
                                    struct blob_attr *msg);

int airui_maintenance_firmware_validate(struct ubus_context *ctx,
                                        struct ubus_object *obj,
                                        struct ubus_request_data *req,
                                        const char *method,
                                        struct blob_attr *msg);

int airui_maintenance_firmware_upgrade(struct ubus_context *ctx,
                                       struct ubus_object *obj,
                                       struct ubus_request_data *req,
                                       const char *method,
                                       struct blob_attr *msg);

#endif /* AIRUI_MAINTENANCE_H */
