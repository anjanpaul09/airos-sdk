#include "airui_response.h"

#include <time.h>

static void add_empty_array(struct blob_buf *b, const char *name)
{
    void *array = blobmsg_open_array(b, name);
    blobmsg_close_array(b, array);
}

static void add_meta_schema(struct blob_buf *b, const char *source, const char *schema)
{
    void *meta = blobmsg_open_table(b, "meta");
    blobmsg_add_u64(b, "timestamp", (uint64_t)time(NULL));
    blobmsg_add_string(b, "source", source ? source : "live");
    if (schema) {
        blobmsg_add_string(b, "schema", schema);
    } else {
        blobmsg_add_u32(b, "schema", 1);
    }
    blobmsg_close_table(b, meta);
}

void airui_reply_ok_schema(struct ubus_context *ctx,
                           struct ubus_request_data *req,
                           airui_data_builder_t data_builder,
                           void *user,
                           const char *source,
                           const char *schema)
{
    struct blob_buf b = {};
    void *data;

    blob_buf_init(&b, 0);
    blobmsg_add_u8(&b, "ok", true);
    data = blobmsg_open_table(&b, "data");
    if (data_builder) {
        data_builder(&b, user);
    }
    blobmsg_close_table(&b, data);
    add_empty_array(&b, "warnings");
    add_empty_array(&b, "errors");
    add_meta_schema(&b, source, schema);
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
}

void airui_reply_ok(struct ubus_context *ctx,
                    struct ubus_request_data *req,
                    airui_data_builder_t data_builder,
                    void *user)
{
    airui_reply_ok_schema(ctx, req, data_builder, user, NULL, NULL);
}

void airui_reply_error_schema(struct ubus_context *ctx,
                              struct ubus_request_data *req,
                              const char *code,
                              const char *field,
                              const char *message,
                              const char *source,
                              const char *schema)
{
    struct blob_buf b = {};
    void *data;
    void *warnings;
    void *errors;
    void *error;

    blob_buf_init(&b, 0);
    blobmsg_add_u8(&b, "ok", false);
    data = blobmsg_open_table(&b, "data");
    blobmsg_close_table(&b, data);
    warnings = blobmsg_open_array(&b, "warnings");
    blobmsg_close_array(&b, warnings);
    errors = blobmsg_open_array(&b, "errors");
    error = blobmsg_open_table(&b, NULL);
    blobmsg_add_string(&b, "code", code ? code : "error");
    if (field) {
        blobmsg_add_string(&b, "field", field);
    }
    blobmsg_add_string(&b, "message", message ? message : "Request failed");
    blobmsg_close_table(&b, error);
    blobmsg_close_array(&b, errors);
    add_meta_schema(&b, source, schema);
    ubus_send_reply(ctx, req, b.head);
    blob_buf_free(&b);
}

void airui_reply_error(struct ubus_context *ctx,
                       struct ubus_request_data *req,
                       const char *code,
                       const char *field,
                       const char *message)
{
    airui_reply_error_schema(ctx, req, code, field, message, NULL, NULL);
}

void airui_reply_unsupported(struct ubus_context *ctx,
                             struct ubus_request_data *req,
                             const char *method)
{
    char message[128];

    snprintf(message, sizeof(message), "%s is not implemented yet",
             method ? method : "method");
    airui_reply_error(ctx, req, "unsupported", NULL, message);
}
