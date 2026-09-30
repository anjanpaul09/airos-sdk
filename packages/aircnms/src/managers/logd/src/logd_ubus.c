#include "logd.h"
#include "logd_ubus.h"
#include "logd_rotate.h"

#include <libubus.h>
#include <libubox/blobmsg.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

static struct ubus_context *s_ubus = NULL;
static struct ev_loop *s_loop = NULL;
static ev_io s_ubus_watcher;

enum {
    READ_LINES,
    READ_TAG,
    __READ_MAX
};

static const struct blobmsg_policy read_policy[] = {
    [READ_LINES] = { .name = "lines", .type = BLOBMSG_TYPE_INT32 },
    [READ_TAG]   = { .name = "tag",   .type = BLOBMSG_TYPE_STRING },
};

static int status_handler(struct ubus_context *ctx, struct ubus_object *obj,
                          struct ubus_request_data *req, const char *method,
                          struct blob_attr *msg)
{
    (void)obj; (void)method; (void)msg;
    static struct blob_buf b;
    blob_buf_init(&b, 0);

    char full_path[256];
    snprintf(full_path, sizeof(full_path), "%s/%s",
             g_logd.config.log_dir, g_logd.config.log_file);

    blobmsg_add_u8(&b, "enabled", g_logd.config.enabled);
    blobmsg_add_string(&b, "active_file", full_path);
    blobmsg_add_u64(&b, "current_file_size_bytes", (uint64_t)g_logd.current_file_size);
    blobmsg_add_u64(&b, "max_size_bytes", (uint64_t)g_logd.config.max_size_bytes);
    blobmsg_add_u32(&b, "max_backups", (uint32_t)g_logd.config.max_backups);
    blobmsg_add_u8(&b, "compress", g_logd.config.compress);
    blobmsg_add_u32(&b, "total_rotations", g_logd.stats.total_rotations);
    blobmsg_add_u64(&b, "messages_received", g_logd.stats.messages_received);
    blobmsg_add_u64(&b, "messages_written", g_logd.stats.messages_written);
    blobmsg_add_u64(&b, "messages_dropped_rate_limit", g_logd.stats.messages_dropped_rate_limit);
    blobmsg_add_u64(&b, "messages_dropped_filter", g_logd.stats.messages_dropped_filter);
    blobmsg_add_u8(&b, "compress_in_progress", g_logd.compress_in_progress);
    blobmsg_add_u64(&b, "uptime_seconds", (uint64_t)(time(NULL) - g_logd.stats.start_time));

    ubus_send_reply(ctx, req, b.head);
    return 0;
}

static int read_handler(struct ubus_context *ctx, struct ubus_object *obj,
                        struct ubus_request_data *req, const char *method,
                        struct blob_attr *msg)
{
    (void)obj; (void)method;
    struct blob_attr *tb[__READ_MAX];
    static struct blob_buf b;
    int max_lines = 50;
    const char *filter_tag = NULL;
    char path[256];

    blobmsg_parse(read_policy, __READ_MAX, tb, blob_data(msg), blob_len(msg));
    if (tb[READ_LINES]) {
        max_lines = blobmsg_get_u32(tb[READ_LINES]);
        if (max_lines <= 0) max_lines = 50;
        if (max_lines > 500) max_lines = 500; /* Hard clamp */
    }
    if (tb[READ_TAG]) {
        filter_tag = blobmsg_get_string(tb[READ_TAG]);
    }

    snprintf(path, sizeof(path), "%s/%s",
             g_logd.config.log_dir, g_logd.config.log_file);

    blob_buf_init(&b, 0);
    void *arr = blobmsg_open_array(&b, "lines");

    FILE *fp = fopen(path, "r");
    if (fp) {
        fseek(fp, 0, SEEK_END);
        long sz = ftell(fp);
        long seek_back = (sz > 65536) ? 65536 : sz;
        fseek(fp, sz - seek_back, SEEK_SET);

        char line_buf[1024];
        char *collected[500];
        int count = 0;

        /* If we sought into middle of a line, skip first partial line */
        if (sz > seek_back) {
            if (!fgets(line_buf, sizeof(line_buf), fp)) line_buf[0] = '\0';
        }

        while (fgets(line_buf, sizeof(line_buf), fp)) {
            size_t llen = strlen(line_buf);
            if (llen > 0 && line_buf[llen - 1] == '\n') {
                line_buf[llen - 1] = '\0';
            }

            if (filter_tag && *filter_tag) {
                if (!strstr(line_buf, filter_tag)) continue;
            }

            if (count >= max_lines) {
                free(collected[0]);
                memmove(&collected[0], &collected[1], sizeof(char *) * (max_lines - 1));
                count = max_lines - 1;
            }
            collected[count++] = strdup(line_buf);
        }
        fclose(fp);

        for (int i = 0; i < count; i++) {
            blobmsg_add_string(&b, NULL, collected[i]);
            free(collected[i]);
        }
    }

    blobmsg_close_array(&b, arr);
    ubus_send_reply(ctx, req, b.head);
    return 0;
}

static int rotate_handler(struct ubus_context *ctx, struct ubus_object *obj,
                          struct ubus_request_data *req, const char *method,
                          struct blob_attr *msg)
{
    (void)obj; (void)method; (void)msg;
    static struct blob_buf b;
    blob_buf_init(&b, 0);

    bool ok = logd_rotate_do();
    blobmsg_add_string(&b, "result", ok ? "ok" : "failed");
    ubus_send_reply(ctx, req, b.head);
    return 0;
}

static int clear_handler(struct ubus_context *ctx, struct ubus_object *obj,
                         struct ubus_request_data *req, const char *method,
                         struct blob_attr *msg)
{
    (void)obj; (void)method; (void)msg;
    static struct blob_buf b;
    blob_buf_init(&b, 0);

    bool ok = logd_rotate_clear();
    blobmsg_add_string(&b, "result", ok ? "ok" : "failed");
    ubus_send_reply(ctx, req, b.head);
    return 0;
}

static const struct ubus_method logd_methods[] = {
    UBUS_METHOD_NOARG("status", status_handler),
    UBUS_METHOD("read", read_handler, read_policy),
    UBUS_METHOD_NOARG("rotate", rotate_handler),
    UBUS_METHOD_NOARG("clear", clear_handler),
};

static struct ubus_object_type logd_object_type =
    UBUS_OBJECT_TYPE("air.log", logd_methods);

static struct ubus_object logd_object = {
    .name = "air.log",
    .type = &logd_object_type,
    .methods = logd_methods,
    .n_methods = ARRAY_SIZE(logd_methods),
};

static void ubus_io_cb(EV_P_ ev_io *watcher, int revents)
{
    (void)loop; (void)watcher; (void)revents;
    if (s_ubus) ubus_handle_event(s_ubus);
}

bool logd_ubus_init(struct ev_loop *loop)
{
    s_loop = loop;
    s_ubus = ubus_connect(NULL);
    if (!s_ubus) return false;

    if (ubus_add_object(s_ubus, &logd_object) != 0) {
        logd_ubus_cleanup();
        return false;
    }

    g_logd.ubus_ctx = s_ubus;

    ev_io_init(&s_ubus_watcher, ubus_io_cb, s_ubus->sock.fd, EV_READ);
    ev_io_start(s_loop, &s_ubus_watcher);

    return true;
}

void logd_ubus_cleanup(void)
{
    if (s_loop && s_ubus) {
        ev_io_stop(s_loop, &s_ubus_watcher);
    }
    if (s_ubus) {
        ubus_free(s_ubus);
        s_ubus = NULL;
    }
    g_logd.ubus_ctx = NULL;
}
