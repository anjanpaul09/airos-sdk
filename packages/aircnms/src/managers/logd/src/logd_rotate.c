#include "logd.h"
#include "logd_rotate.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/wait.h>

static void child_cb(EV_P_ ev_child *w, int revents)
{
    (void)loop; (void)revents;
    ev_child_stop(EV_A_ w);
    g_logd.compress_in_progress = false;
}

static void check_tmpfs_space(void)
{
    struct statvfs sv;
    if (statvfs(g_logd.config.log_dir, &sv) == 0) {
        uint64_t free_bytes = (uint64_t)sv.f_bavail * sv.f_bsize;
        if (free_bytes < 3 * 1024 * 1024) { /* Under 3 MB free */
            /* Purge oldest backup files to free memory */
            char path[256];
            for (int i = g_logd.config.max_backups; i >= 1; i--) {
                snprintf(path, sizeof(path), "%s/%s.%d.gz",
                         g_logd.config.log_dir, g_logd.config.log_file, i);
                unlink(path);
                snprintf(path, sizeof(path), "%s/%s.%d",
                         g_logd.config.log_dir, g_logd.config.log_file, i);
                unlink(path);
            }
        }
    }
}

bool logd_rotate_init(void)
{
    char active_path[256];
    struct stat st;

    mkdir(g_logd.config.log_dir, 0755);

    snprintf(active_path, sizeof(active_path), "%s/%s",
             g_logd.config.log_dir, g_logd.config.log_file);

    g_logd.log_fp = fopen(active_path, "a");
    if (!g_logd.log_fp) return false;

    if (stat(active_path, &st) == 0) {
        g_logd.current_file_size = (size_t)st.st_size;
    } else {
        g_logd.current_file_size = 0;
    }

    g_logd.compress_in_progress = false;
    return true;
}

void logd_rotate_close(void)
{
    if (g_logd.log_fp) {
        fflush(g_logd.log_fp);
        fclose(g_logd.log_fp);
        g_logd.log_fp = NULL;
    }
}

bool logd_rotate_do(void)
{
    char src[256], dst[256], active[256];

    if (g_logd.log_fp) {
        fflush(g_logd.log_fp);
        fclose(g_logd.log_fp);
        g_logd.log_fp = NULL;
    }

    check_tmpfs_space();

    /* Remove oldest backup if exists */
    snprintf(dst, sizeof(dst), "%s/%s.%d.gz",
             g_logd.config.log_dir, g_logd.config.log_file, g_logd.config.max_backups);
    unlink(dst);
    snprintf(dst, sizeof(dst), "%s/%s.%d",
             g_logd.config.log_dir, g_logd.config.log_file, g_logd.config.max_backups);
    unlink(dst);

    /* Shift intermediate archives down */
    for (int i = g_logd.config.max_backups - 1; i >= 1; i--) {
        snprintf(src, sizeof(src), "%s/%s.%d.gz",
                 g_logd.config.log_dir, g_logd.config.log_file, i);
        snprintf(dst, sizeof(dst), "%s/%s.%d.gz",
                 g_logd.config.log_dir, g_logd.config.log_file, i + 1);
        rename(src, dst);

        /* In case uncompressed .i exists */
        snprintf(src, sizeof(src), "%s/%s.%d",
                 g_logd.config.log_dir, g_logd.config.log_file, i);
        snprintf(dst, sizeof(dst), "%s/%s.%d",
                 g_logd.config.log_dir, g_logd.config.log_file, i + 1);
        rename(src, dst);
    }

    /* Move active log to .1 */
    snprintf(active, sizeof(active), "%s/%s",
             g_logd.config.log_dir, g_logd.config.log_file);
    snprintf(dst, sizeof(dst), "%s/%s.1",
             g_logd.config.log_dir, g_logd.config.log_file);
    rename(active, dst);

    /* Immediately open fresh active log so incoming lines are never dropped */
    g_logd.log_fp = fopen(active, "w");
    g_logd.current_file_size = 0;
    g_logd.stats.total_rotations++;

    /* Launch background compression if enabled and worker is idle */
    if (g_logd.config.compress && !g_logd.compress_in_progress && g_logd.loop) {
        pid_t pid = fork();
        if (pid == 0) {
            /* Child process: run with lowest priority */
            nice(19);
            execlp("gzip", "gzip", "-f", "-9", dst, (char *)NULL);
            _exit(1);
        } else if (pid > 0) {
            g_logd.compress_in_progress = true;
            ev_child_init(&g_logd.child_watcher, child_cb, pid, 0);
            ev_child_start(g_logd.loop, &g_logd.child_watcher);
        }
    }

    return (g_logd.log_fp != NULL);
}

bool logd_rotate_write(const char *data, size_t len)
{
    if (!data || len == 0) return true;

    if (!g_logd.log_fp) {
        if (!logd_rotate_init()) return false;
    }

    if (g_logd.current_file_size + len >= g_logd.config.max_size_bytes) {
        logd_rotate_do();
    }

    if (!g_logd.log_fp) return false;

    size_t written = fwrite(data, 1, len, g_logd.log_fp);
    if (written > 0) {
        g_logd.current_file_size += written;
        g_logd.stats.messages_written++;
        fflush(g_logd.log_fp);
        return true;
    }

    return false;
}

bool logd_rotate_clear(void)
{
    logd_rotate_close();

    char path[256];
    snprintf(path, sizeof(path), "%s/%s",
             g_logd.config.log_dir, g_logd.config.log_file);
    unlink(path);

    for (int i = 1; i <= g_logd.config.max_backups; i++) {
        snprintf(path, sizeof(path), "%s/%s.%d.gz",
                 g_logd.config.log_dir, g_logd.config.log_file, i);
        unlink(path);
        snprintf(path, sizeof(path), "%s/%s.%d",
                 g_logd.config.log_dir, g_logd.config.log_file, i);
        unlink(path);
    }

    return logd_rotate_init();
}
