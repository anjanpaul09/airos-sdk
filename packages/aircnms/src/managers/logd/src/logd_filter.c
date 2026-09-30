#include "logd.h"
#include "logd_filter.h"

#include <ctype.h>
#include <time.h>

#define MAX_RATE_BUCKETS 64

typedef struct rate_bucket {
    char tag[LOGD_TAG_LEN];
    double tokens;
    double last_time;
    uint32_t dropped_count;
    double last_warning_time;
    bool in_use;
} rate_bucket_t;

static rate_bucket_t s_buckets[MAX_RATE_BUCKETS];

static const char *s_severity_names[] = {
    "EMERG", "ALERT", "CRIT", "ERR", "WARN", "NOTICE", "INFO", "DEBUG"
};

void logd_filter_init(void)
{
    memset(s_buckets, 0, sizeof(s_buckets));
}

static int severity_to_level(const char *name)
{
    if (!name) return 6; /* INFO */
    if (!strcasecmp(name, "emerg")) return 0;
    if (!strcasecmp(name, "alert")) return 1;
    if (!strcasecmp(name, "crit")) return 2;
    if (!strcasecmp(name, "err") || !strcasecmp(name, "error")) return 3;
    if (!strcasecmp(name, "warn") || !strcasecmp(name, "warning")) return 4;
    if (!strcasecmp(name, "notice")) return 5;
    if (!strcasecmp(name, "info")) return 6;
    if (!strcasecmp(name, "debug")) return 7;
    return 6;
}

bool logd_filter_match(const char *tag, int priority)
{
    int sev = priority & 7;
    int max_allowed_sev = severity_to_level(g_logd.config.min_severity);

    if (sev > max_allowed_sev) {
        g_logd.stats.messages_dropped_filter++;
        return false;
    }

    if (!tag || !*tag) return true;

    if (g_logd.config.tag_count == 0) return true;

    for (int i = 0; i < g_logd.config.tag_count; i++) {
        const char *t = g_logd.config.tags[i];
        size_t len = strlen(t);
        if (!strncmp(tag, t, len)) {
            /* Prefix matched: either exact match or followed by - or _ or [ */
            char next = tag[len];
            if (next == '\0' || next == '-' || next == '_' || next == '[' || next == ':') {
                return true;
            }
        }
        /* Also match if tag starts with "air-" and configured tag t is without "air-" */
        if (!strncmp(tag, "air-", 4)) {
            const char *tag_no_prefix = tag + 4;
            if (!strncmp(tag_no_prefix, t, len)) {
                char next = tag_no_prefix[len];
                if (next == '\0' || next == '-' || next == '_' || next == '[' || next == ':') {
                    return true;
                }
            }
        }
    }

    g_logd.stats.messages_dropped_filter++;
    return false;
}

bool logd_filter_rate_check(const char *tag, char *warning_buf, size_t warning_sz)
{
    if (!g_logd.config.rate_limit_enable) return true;
    if (!tag || !*tag) return true;

    double now = ev_time();
    rate_bucket_t *b = NULL;
    int free_idx = -1;

    for (int i = 0; i < MAX_RATE_BUCKETS; i++) {
        if (s_buckets[i].in_use && !strcmp(s_buckets[i].tag, tag)) {
            b = &s_buckets[i];
            break;
        }
        if (!s_buckets[i].in_use && free_idx < 0) {
            free_idx = i;
        }
    }

    if (!b) {
        if (free_idx < 0) free_idx = 0; /* Fallback overwrite slot 0 */
        b = &s_buckets[free_idx];
        memset(b, 0, sizeof(*b));
        snprintf(b->tag, sizeof(b->tag), "%s", tag);
        b->tokens = g_logd.config.rate_limit_burst;
        b->last_time = now;
        b->in_use = true;
    }

    /* Replenish tokens */
    double elapsed = now - b->last_time;
    b->last_time = now;
    b->tokens += elapsed * g_logd.config.rate_limit_rate;
    if (b->tokens > g_logd.config.rate_limit_burst) {
        b->tokens = g_logd.config.rate_limit_burst;
    }

    if (b->tokens >= 1.0) {
        b->tokens -= 1.0;
        /* If we previously dropped messages, emit a summary warning */
        if (b->dropped_count > 0 && (now - b->last_warning_time) > 5.0) {
            if (warning_buf && warning_sz > 0) {
                snprintf(warning_buf, warning_sz,
                         "[air-logd] Tag '%s' resumed normal rate (suppressed %u burst messages)",
                         tag, b->dropped_count);
            }
            b->dropped_count = 0;
            b->last_warning_time = now;
        }
        return true;
    }

    b->dropped_count++;
    g_logd.stats.messages_dropped_rate_limit++;

    if ((now - b->last_warning_time) > 10.0) {
        if (warning_buf && warning_sz > 0) {
            snprintf(warning_buf, warning_sz,
                     "[air-logd] Message flood detected for tag '%s', suppressing further burst logs",
                     tag);
        }
        b->last_warning_time = now;
    }

    return false;
}

size_t logd_filter_format(char *out, size_t out_sz, int64_t timestamp_sec,
                          const char *tag, int priority, const char *msg)
{
    if (!out || out_sz == 0) return 0;

    time_t t = (time_t)timestamp_sec;
    struct tm tm_buf;
    if (t <= 0) t = time(NULL);
    localtime_r(&t, &tm_buf);

    char time_str[32];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_buf);

    int sev = priority & 7;
    const char *sev_str = (sev >= 0 && sev <= 7) ? s_severity_names[sev] : "INFO";

    int written = snprintf(out, out_sz, "%s [%s] [%s] %s\n",
                           time_str,
                           tag ? tag : "system",
                           sev_str,
                           msg ? msg : "");
    if (written < 0) return 0;
    if ((size_t)written >= out_sz) {
        out[out_sz - 1] = '\n';
        return out_sz;
    }
    return (size_t)written;
}
