#ifndef AIRUI_SECURITY_H
#define AIRUI_SECURITY_H

#include <libubus.h>

int airui_security_rules(struct ubus_context *ctx,
                         struct ubus_object *obj,
                         struct ubus_request_data *req,
                         const char *method,
                         struct blob_attr *msg);
int airui_security_rule_add(struct ubus_context *ctx,
                            struct ubus_object *obj,
                            struct ubus_request_data *req,
                            const char *method,
                            struct blob_attr *msg);
int airui_security_rule_set(struct ubus_context *ctx,
                            struct ubus_object *obj,
                            struct ubus_request_data *req,
                            const char *method,
                            struct blob_attr *msg);
int airui_security_rule_delete(struct ubus_context *ctx,
                               struct ubus_object *obj,
                               struct ubus_request_data *req,
                               const char *method,
                               struct blob_attr *msg);
int airui_security_access_control_get(struct ubus_context *ctx,
                                      struct ubus_object *obj,
                                      struct ubus_request_data *req,
                                      const char *method,
                                      struct blob_attr *msg);
int airui_security_access_control_set(struct ubus_context *ctx,
                                      struct ubus_object *obj,
                                      struct ubus_request_data *req,
                                      const char *method,
                                      struct blob_attr *msg);

int airui_security_mac_filter_config(struct ubus_context *ctx,
                                     struct ubus_object *obj,
                                     struct ubus_request_data *req,
                                     const char *method,
                                     struct blob_attr *msg);
int airui_security_mac_filter_set(struct ubus_context *ctx,
                                  struct ubus_object *obj,
                                  struct ubus_request_data *req,
                                  const char *method,
                                  struct blob_attr *msg);
int airui_security_mac_filter_entry_add(struct ubus_context *ctx,
                                        struct ubus_object *obj,
                                        struct ubus_request_data *req,
                                        const char *method,
                                        struct blob_attr *msg);
int airui_security_mac_filter_entry_delete(struct ubus_context *ctx,
                                           struct ubus_object *obj,
                                           struct ubus_request_data *req,
                                           const char *method,
                                           struct blob_attr *msg);

#endif /* AIRUI_SECURITY_H */
