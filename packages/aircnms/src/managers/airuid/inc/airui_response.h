#ifndef AIRUI_RESPONSE_H
#define AIRUI_RESPONSE_H

#include <libubus.h>
#include <libubox/blobmsg.h>

typedef void (*airui_data_builder_t)(struct blob_buf *b, void *user);

void airui_reply_ok(struct ubus_context *ctx,
                    struct ubus_request_data *req,
                    airui_data_builder_t data_builder,
                    void *user);
void airui_reply_ok_schema(struct ubus_context *ctx,
                           struct ubus_request_data *req,
                           airui_data_builder_t data_builder,
                           void *user,
                           const char *source,
                           const char *schema);
void airui_reply_error(struct ubus_context *ctx,
                       struct ubus_request_data *req,
                       const char *code,
                       const char *field,
                       const char *message);
void airui_reply_error_schema(struct ubus_context *ctx,
                              struct ubus_request_data *req,
                              const char *code,
                              const char *field,
                              const char *message,
                              const char *source,
                              const char *schema);
void airui_reply_unsupported(struct ubus_context *ctx,
                             struct ubus_request_data *req,
                             const char *method);

#endif /* AIRUI_RESPONSE_H */
