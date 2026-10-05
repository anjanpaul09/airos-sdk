#include "logd.h"
#include "logd_stream.h"
#include "logd_filter.h"
#include "logd_rotate.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <libubox/blobmsg.h>
#include <sys/socket.h>
#include <syslog.h>

enum {
    LOG_MSG,
    LOG_ID,
    LOG_PRIO,
    LOG_SOURCE,
    LOG_TIME,
    __LOG_MAX
};

static const struct blobmsg_policy log_policy[] = {
    [LOG_MSG]    = { .name = "msg",      .type = BLOBMSG_TYPE_STRING },
    [LOG_ID]     = { .name = "id",       .type = BLOBMSG_TYPE_INT32 },
    [LOG_PRIO]   = { .name = "priority", .type = BLOBMSG_TYPE_INT32 },
    [LOG_SOURCE] = { .name = "source",   .type = BLOBMSG_TYPE_INT32 },
    [LOG_TIME]   = { .name = "time",     .type = BLOBMSG_TYPE_INT64 },
};

static struct ubus_request s_req;
static int s_stream_fd = -1;
static ev_io s_stream_watcher;
static uint8_t s_buf[16384];
static size_t s_buf_len = 0;
static bool s_connected = false;

static void parse_msg_tag(const char *raw, char *tag, size_t tag_sz, const char **body)
{
    const char *p = raw;
    while (*p && isspace((unsigned char)*p)) p++;

    /* If first token looks like facility.priority (e.g. user.info, daemon.notice), skip it */
    const char *dot = strchr(p, '.');
    const char *space = strchr(p, ' ');
    if (dot && space && dot < space) {
        p = space + 1;
        while (*p && isspace((unsigned char)*p)) p++;
    }

    const char *tag_start = p;
    while (*p && *p != ':' && *p != '[' && !isspace((unsigned char)*p)) p++;

    size_t len = p - tag_start;
    if (len >= tag_sz) len = tag_sz - 1;
    strncpy(tag, tag_start, len);
    tag[len] = '\0';

    /* Convert to lowercase for comparison */
    for (size_t i = 0; i < len; i++) {
        tag[i] = (char)tolower((unsigned char)tag[i]);
    }

    /* Advance body pointer past ':' and spaces */
    while (*p && *p != ':') p++;
    if (*p == ':') p++;
    while (*p && isspace((unsigned char)*p)) p++;

    *body = p;
}

static void normalize_tag(char *tag, size_t tag_sz)
{
    static const struct {
        const char *from;
        const char *to;
    } tag_map[] = {
        { "onbd",        "air-onbd" },
        { "cgwd",        "air-cgwd" },
        { "netconf",     "air-netconfd" },
        { "netconfd",    "air-netconfd" },
        { "stamonitord", "air-stamond" },
        { "stamond",     "air-stamond" },
        { "netstats",    "air-netstatsd" },
        { "netstatsd",   "air-netstatsd" },
        { "cmdexec",     "air-cmdexecd" },
        { "cmdexecd",    "air-cmdexecd" },
        { "eventd",      "air-eventd" },
        { "airuid",      "airuid" },
        { "acld",        "air-acld" },
    };

    for (size_t i = 0; i < sizeof(tag_map) / sizeof(tag_map[0]); i++) {
        if (!strcmp(tag, tag_map[i].from)) {
            snprintf(tag, tag_sz, "%s", tag_map[i].to);
            return;
        }
    }
}

static void handle_log_entry(struct blob_attr *attr)
{
    struct blob_attr *tb[__LOG_MAX];
    char tag[LOGD_TAG_LEN] = {0};
    const char *body = NULL;
    char line[1024];
    char warn[256];

    blobmsg_parse(log_policy, __LOG_MAX, tb, blob_data(attr), blob_len(attr));
    if (!tb[LOG_MSG] || !tb[LOG_PRIO]) return;

    g_logd.stats.messages_received++;

    const char *msg = blobmsg_get_string(tb[LOG_MSG]);
    int prio = blobmsg_get_u32(tb[LOG_PRIO]);
    int64_t ts = tb[LOG_TIME] ? (blobmsg_get_u64(tb[LOG_TIME]) / 1000) : 0;

    parse_msg_tag(msg, tag, sizeof(tag), &body);

    normalize_tag(tag, sizeof(tag));

    if (!logd_filter_match(tag, prio)) return;

    warn[0] = '\0';
    if (!logd_filter_rate_check(tag, warn, sizeof(warn))) {
        if (warn[0] != '\0') {
            size_t wlen = logd_filter_format(line, sizeof(line), ts, false, LOG_USER | LOG_WARNING, warn);
            if (wlen > 0) logd_rotate_write(line, wlen);
        }
        return;
    }

    if (warn[0] != '\0') {
        size_t wlen = logd_filter_format(line, sizeof(line), ts, false, LOG_USER | LOG_NOTICE, warn);
        if (wlen > 0) logd_rotate_write(line, wlen);
    }

    /* Keep normalized tags for filtering, but preserve the original name/PID in output. */
    bool kernel = tb[LOG_SOURCE] && blobmsg_get_u32(tb[LOG_SOURCE]) == 0;
    size_t fmt_len = logd_filter_format(line, sizeof(line), ts, kernel, prio, msg);
    if (fmt_len > 0) {
        logd_rotate_write(line, fmt_len);
    }
}

static void stream_io_cb(EV_P_ ev_io *w, int revents)
{
    (void)loop; (void)revents;

    while (1) {
        if (s_buf_len >= sizeof(s_buf)) {
            /* Buffer overflow prevention: reset buffer if corrupted */
            s_buf_len = 0;
        }

        ssize_t n = read(w->fd, s_buf + s_buf_len, sizeof(s_buf) - s_buf_len);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            /* Read error -> disconnect */
            logd_stream_cleanup();
            ev_timer_start(g_logd.loop, &g_logd.reconnect_timer);
            return;
        }
        if (n == 0) {
            /* EOF -> ubox logd closed stream */
            logd_stream_cleanup();
            ev_timer_start(g_logd.loop, &g_logd.reconnect_timer);
            return;
        }

        s_buf_len += n;

        while (s_buf_len >= sizeof(struct blob_attr)) {
            struct blob_attr *a = (struct blob_attr *)s_buf;
            size_t cur_len = blob_len(a) + sizeof(*a);
            if (s_buf_len < cur_len) break;

            handle_log_entry(a);

            if (s_buf_len > cur_len) {
                memmove(s_buf, s_buf + cur_len, s_buf_len - cur_len);
            }
            s_buf_len -= cur_len;
        }
    }
}

static void stream_fd_cb(struct ubus_request *req, int fd)
{
    (void)req;
    if (s_stream_fd >= 0) {
        close(s_stream_fd);
        ev_io_stop(g_logd.loop, &s_stream_watcher);
    }

    s_stream_fd = fd;
    fcntl(fd, F_SETFL, O_NONBLOCK);
    s_buf_len = 0;
    s_connected = true;

    ev_io_init(&s_stream_watcher, stream_io_cb, s_stream_fd, EV_READ);
    ev_io_start(g_logd.loop, &s_stream_watcher);
}

static void reconnect_cb(EV_P_ ev_timer *w, int revents)
{
    (void)loop; (void)w; (void)revents;
    if (s_connected) return;
    logd_stream_start();
}

bool logd_stream_init(void)
{
    s_stream_fd = -1;
    s_buf_len = 0;
    s_connected = false;
    ev_timer_init(&g_logd.reconnect_timer, reconnect_cb, 2.0, 2.0);
    return true;
}

void logd_stream_start(void)
{
    uint32_t id;
    static struct blob_buf b;

    if (s_connected || !g_logd.ubus_ctx) return;

    if (ubus_lookup_id(g_logd.ubus_ctx, "log", &id) != 0) {
        ev_timer_start(g_logd.loop, &g_logd.reconnect_timer);
        return;
    }

    blob_buf_init(&b, 0);
    blobmsg_add_u8(&b, "stream", 1);
    blobmsg_add_u8(&b, "oneshot", 0);
    blobmsg_add_u32(&b, "lines", 0);

    memset(&s_req, 0, sizeof(s_req));

    int rc = ubus_invoke_async(g_logd.ubus_ctx, id, "read", b.head, &s_req);
    if (rc == 0) {
        s_req.fd_cb = stream_fd_cb;
        ubus_complete_request_async(g_logd.ubus_ctx, &s_req);
        ev_timer_stop(g_logd.loop, &g_logd.reconnect_timer);
    } else {
        ev_timer_start(g_logd.loop, &g_logd.reconnect_timer);
    }
}

void logd_stream_cleanup(void)
{
    if (s_stream_fd >= 0) {
        ev_io_stop(g_logd.loop, &s_stream_watcher);
        close(s_stream_fd);
        s_stream_fd = -1;
    }
    s_buf_len = 0;
    s_connected = false;
}
