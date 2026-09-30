#ifndef LOGD_H_INCLUDED
#define LOGD_H_INCLUDED

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ev.h>
#include <libubus.h>
#include <libubox/blobmsg_json.h>

#define LOGD_VERSION              "1.0.0"
#define LOGD_DEFAULT_DIR          "/tmp/log/airos"
#define LOGD_DEFAULT_FILE         "airos.log"
#define LOGD_DEFAULT_MAX_SIZE     (256 * 1024)   /* 256 KB */
#define LOGD_DEFAULT_MAX_BACKUPS  3
#define LOGD_MAX_TAGS             64
#define LOGD_TAG_LEN              32
#define LOGD_DEFAULT_BURST        100
#define LOGD_DEFAULT_RATE         50             /* tokens per sec */

typedef struct logd_config {
    bool enabled;
    char log_dir[128];
    char log_file[64];
    size_t max_size_bytes;
    int max_backups;
    bool compress;
    char min_severity[16];
    bool rate_limit_enable;
    int rate_limit_burst;
    int rate_limit_rate;
    char tags[LOGD_MAX_TAGS][LOGD_TAG_LEN];
    int tag_count;
} logd_config_t;

typedef struct logd_stats {
    uint64_t messages_received;
    uint64_t messages_written;
    uint64_t messages_dropped_rate_limit;
    uint64_t messages_dropped_filter;
    uint32_t total_rotations;
    time_t start_time;
} logd_stats_t;

typedef struct logd_ctx {
    struct ev_loop *loop;
    struct ubus_context *ubus_ctx;
    logd_config_t config;
    logd_stats_t stats;
    FILE *log_fp;
    size_t current_file_size;
    bool compress_in_progress;
    ev_child child_watcher;
    ev_timer reconnect_timer;
} logd_ctx_t;

extern logd_ctx_t g_logd;

#endif /* LOGD_H_INCLUDED */
